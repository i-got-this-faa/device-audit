//go:build windows

package telemetry

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processMemoryCounters struct {
	cb                         uint32
	PageFaultCount             uint32
	PeakWorkingSetSize         uintptr
	WorkingSetSize             uintptr
	QuotaPeakPagedPoolUsage    uintptr
	QuotaPagedPoolUsage        uintptr
	QuotaPeakNonPagedPoolUsage uintptr
	QuotaNonPagedPoolUsage     uintptr
	PagefileUsage              uintptr
	PeakPagefileUsage          uintptr
}

func sampleProcessOS() (osSample, error) {
	handle := windows.CurrentProcess()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return osSample{}, fmt.Errorf("telemetry: process times: %w", err)
	}
	cpu := filetimeTicksToDuration(uint32(kernel.HighDateTime), uint32(kernel.LowDateTime)) +
		filetimeTicksToDuration(uint32(user.HighDateTime), uint32(user.LowDateTime))
	rss, peak, err := WindowsProcessWorkingSet(handle)
	if err != nil {
		return osSample{}, err
	}
	return osSample{CPU: cpu, RSS: rss, PeakRSS: peak}, nil
}

// WindowsProcessWorkingSet returns current and peak resident bytes from the OS.
func WindowsProcessWorkingSet(handle windows.Handle) (current, peak uint64, err error) {
	psapi := windows.NewLazySystemDLL("psapi.dll")
	proc := psapi.NewProc("GetProcessMemoryInfo")
	var counters processMemoryCounters
	counters.cb = uint32(unsafe.Sizeof(counters))
	r, _, callErr := proc.Call(uintptr(handle), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb))
	if r == 0 {
		if callErr != nil {
			return 0, 0, fmt.Errorf("telemetry: process memory: %w", callErr)
		}
		return 0, 0, fmt.Errorf("telemetry: process memory read failed")
	}
	return uint64(counters.WorkingSetSize), uint64(counters.PeakWorkingSetSize), nil
}
