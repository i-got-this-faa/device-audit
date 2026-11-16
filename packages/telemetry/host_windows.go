//go:build windows

package telemetry

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readHostDetails() (family, version, model string, total uint64) {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	family = "windows"
	version = fmt.Sprintf("%d.%d.%d", major, minor, build)
	model = windowsCPUModel()
	total = windowsTotalPhysical()
	return family, version, model, total
}

func windowsCPUModel() string {
	subkey, err := windows.UTF16PtrFromString(`HARDWARE\DESCRIPTION\System\CentralProcessor\0`)
	if err != nil {
		return ""
	}
	var handle windows.Handle
	if err := windows.RegOpenKeyEx(windows.Handle(windows.HKEY_LOCAL_MACHINE), subkey, 0, windows.KEY_READ, &handle); err != nil {
		return ""
	}
	defer windows.RegCloseKey(handle)
	value, err := windows.UTF16PtrFromString("ProcessorNameString")
	if err != nil {
		return ""
	}
	var buf [256]uint16
	size := uint32(len(buf) * 2)
	if err := windows.RegQueryValueEx(handle, value, nil, nil, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

func windowsTotalPhysical() uint64 {
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel.NewProc("GlobalMemoryStatusEx")
	var status memoryStatusEx
	status.Length = uint32(unsafe.Sizeof(status))
	r, _, _ := proc.Call(uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		return 0
	}
	return status.TotalPhys
}
