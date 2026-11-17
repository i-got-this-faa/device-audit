//go:build windows

package telemetry

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// gpuEngineWindow is the gap between the two PDH collections that a rate
// counter needs. It matches the probe's 250 ms network delta.
const gpuEngineWindow = 250 * time.Millisecond

var (
	kernel32Sensors              = windows.NewLazySystemDLL("kernel32.dll")
	procGetSystemPowerStatus     = kernel32Sensors.NewProc("GetSystemPowerStatus")
	pdhDLL                       = windows.NewLazySystemDLL("pdh.dll")
	procPdhOpenQueryW            = pdhDLL.NewProc("PdhOpenQueryW")
	procPdhAddEnglishCounterW    = pdhDLL.NewProc("PdhAddEnglishCounterW")
	procPdhCollectQueryData      = pdhDLL.NewProc("PdhCollectQueryData")
	procPdhGetFormattedCounterAr = pdhDLL.NewProc("PdhGetFormattedCounterArrayW")
	procPdhCloseQuery            = pdhDLL.NewProc("PdhCloseQuery")
)

// PlatformSensorSources returns the Windows battery, thermal, GPU engine and
// installed NVIDIA tool sources.
func PlatformSensorSources() []SensorSource {
	sources := SensorSourceSpecs()
	for i := range sources {
		switch sources[i].Name {
		case SensorBattery:
			sources[i].Read = readBatteryWindows
		case SensorThermal:
			sources[i].Read = readThermalWindows
		case SensorGPUEngine:
			sources[i].Read = readGPUEngineWindows
		case SensorGPUVendor:
			sources[i].Read = readNvidiaWindows
		}
	}
	return sources
}

func readBatteryWindows(context.Context) ([]SensorReading, error) {
	if err := procGetSystemPowerStatus.Find(); err != nil {
		return nil, sensorErr(ErrSensorUnavailable, "power_api_absent")
	}
	var status PowerStatus
	r, _, callErr := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_ACCESS_DENIED) {
			return nil, sensorErr(ErrPermissionDenied, "power_api_access_denied")
		}
		return nil, sensorErr(errors.New("telemetry: GetSystemPowerStatus failed"), "power_api_failed")
	}
	return BatteryReadings(status)
}

func readThermalWindows(ctx context.Context) ([]SensorReading, error) {
	items, err := readPDHCounter(ctx, `\Thermal Zone Information(*)\Temperature`, 0)
	if err != nil {
		return nil, err
	}
	return ThermalReadings(items)
}

func readGPUEngineWindows(ctx context.Context) ([]SensorReading, error) {
	items, err := readPDHCounter(ctx, `\GPU Engine(*)\Utilization Percentage`, gpuEngineWindow)
	if err != nil {
		return nil, err
	}
	return GPUEngineReadings(items)
}

// readNvidiaWindows runs only the vendor tool already installed at the fixed
// System32 path, with fixed arguments and no shell. It never searches PATH or
// installs anything. Absence is not_applicable: no NVIDIA driver tool is present.
func readNvidiaWindows(ctx context.Context) ([]SensorReading, error) {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, sensorErr(errors.New("telemetry: system directory unavailable"), "system_directory_unavailable")
	}
	smi := filepath.Join(system, "nvidia-smi.exe")
	info, err := os.Stat(smi)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, sensorErr(ErrSensorNotApplicable, "vendor_tool_absent")
	case errors.Is(err, fs.ErrPermission):
		return nil, sensorErr(ErrPermissionDenied, "vendor_tool_access_denied")
	case err != nil:
		return nil, sensorErr(err, "vendor_tool_stat_failed")
	case !info.Mode().IsRegular():
		return nil, sensorErr(ErrSensorUnavailable, "vendor_tool_not_file")
	}
	cmd := exec.CommandContext(ctx, smi, NvidiaSMIQuery, NvidiaSMIFormat)
	cmd.WaitDelay = time.Second
	var stdout limitedBuffer
	stdout.limit = maxVendorOutput + 1
	cmd.Stdout = &stdout
	cmd.Stderr = nil
	err = cmd.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	var exitErr *exec.ExitError
	switch {
	case errors.As(err, &exitErr):
		return nil, NvidiaExitError(exitErr.ExitCode())
	case errors.Is(err, fs.ErrPermission), errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return nil, sensorErr(ErrPermissionDenied, "vendor_tool_access_denied")
	case err != nil:
		return nil, sensorErr(err, "vendor_tool_start_failed")
	}
	return NvidiaReadings(stdout.Bytes())
}

// limitedBuffer keeps at most limit bytes and discards the rest, so a
// misbehaving tool cannot grow collector memory without bound.
type limitedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// pdhFmtCounterValueItemDouble mirrors PDH_FMT_COUNTERVALUE_ITEM_W with a
// double value. The explicit pad keeps the union at offset 8 on every arch.
type pdhFmtCounterValueItemDouble struct {
	Name    *uint16
	CStatus uint32
	_       uint32
	Value   float64
}

const (
	pdhFmtDouble   = 0x00000200
	pdhFmtNoCap100 = 0x00008000
	// GPU engine instances scale with processes times engines, so the cap is
	// generous. The byte cap bounds the instance-name strings as well.
	pdhMaxItems = 65536
	pdhMaxBytes = 16 << 20
)

// readPDHCounter opens a local query, adds one English counter path and
// returns its formatted instances. A non-zero window collects twice, as rate
// counters require.
func readPDHCounter(ctx context.Context, path string, window time.Duration) ([]CounterItem, error) {
	// The Go struct matches the C layout only where pointers are 8 bytes.
	var probe pdhFmtCounterValueItemDouble
	if unsafe.Offsetof(probe.Value) != 16 {
		return nil, sensorErr(ErrSensorUnavailable, "pdh_layout_unsupported")
	}
	if err := pdhDLL.Load(); err != nil {
		return nil, sensorErr(ErrSensorUnavailable, "pdh_absent")
	}
	var query windows.Handle
	if status, _, _ := procPdhOpenQueryW.Call(0, 0, uintptr(unsafe.Pointer(&query))); status != 0 {
		return nil, PDHFailure(uint32(status))
	}
	defer procPdhCloseQuery.Call(uintptr(query))
	counterPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, sensorErr(err, "pdh_path_invalid")
	}
	var counter windows.Handle
	if status, _, _ := procPdhAddEnglishCounterW.Call(uintptr(query), uintptr(unsafe.Pointer(counterPath)), 0, uintptr(unsafe.Pointer(&counter))); status != 0 {
		return nil, PDHFailure(uint32(status))
	}
	if status, _, _ := procPdhCollectQueryData.Call(uintptr(query)); status != 0 {
		return nil, PDHFailure(uint32(status))
	}
	if window > 0 {
		if err := sleepContext(ctx, window); err != nil {
			return nil, err
		}
		if status, _, _ := procPdhCollectQueryData.Call(uintptr(query)); status != 0 {
			return nil, PDHFailure(uint32(status))
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var size, count uint32
	status, _, _ := procPdhGetFormattedCounterAr.Call(uintptr(counter), pdhFmtDouble|pdhFmtNoCap100,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), 0)
	switch uint32(status) {
	case 0:
		return nil, nil
	case PDHMoreData:
	default:
		if (PDHError{Status: uint32(status)}).Is(ErrSensorUnavailable) && uint32(status) != PDHCStatusNoObject {
			return nil, nil
		}
		return nil, PDHFailure(uint32(status))
	}
	if count == 0 || size == 0 {
		return nil, nil
	}
	itemSize := uint32(unsafe.Sizeof(pdhFmtCounterValueItemDouble{}))
	if count > pdhMaxItems || size > pdhMaxBytes {
		return nil, sensorErr(errors.New("telemetry: PDH instance count too large"), "pdh_too_many_instances")
	}
	// The buffer holds the item array followed by the instance-name strings.
	// Allocate whole items so the array is correctly aligned.
	buf := make([]pdhFmtCounterValueItemDouble, (size+itemSize-1)/itemSize)
	status, _, _ = procPdhGetFormattedCounterAr.Call(uintptr(counter), pdhFmtDouble|pdhFmtNoCap100,
		uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&buf[0])))
	if status != 0 {
		return nil, PDHFailure(uint32(status))
	}
	if int(count) > len(buf) {
		return nil, sensorErr(errors.New("telemetry: PDH returned more items than buffer"), "pdh_call_failed")
	}
	items := make([]CounterItem, 0, count)
	for _, raw := range buf[:count] {
		items = append(items, CounterItem{Name: windows.UTF16PtrToString(raw.Name), Status: raw.CStatus, Value: raw.Value})
	}
	return items, nil
}
