//go:build windows

package telemetry

import (
	"context"
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	procGetSystemTimes       = kernel32Sensors.NewProc("GetSystemTimes")
	procGlobalMemoryStatusEx = kernel32Sensors.NewProc("GlobalMemoryStatusEx")
)

// MIB_IF_ROW2 InterfaceAndOperStatusFlags bits.
const (
	ifFlagHardwareInterface = 0x01
	ifFlagFilterInterface   = 0x02
)

func readCPUWindows(ctx context.Context) ([]SensorReading, error) {
	first, err := systemTimes()
	if err != nil {
		return nil, err
	}
	if err := sleepContext(ctx, resourceRateWindow); err != nil {
		return nil, err
	}
	second, err := systemTimes()
	if err != nil {
		return nil, err
	}
	return CPUReadings(first, second)
}

func systemTimes() (SystemTimes, error) {
	var idle, kernel, user windows.Filetime
	r, _, callErr := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idle)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_ACCESS_DENIED) {
			return SystemTimes{}, sensorErr(ErrPermissionDenied, "system_times_access_denied")
		}
		return SystemTimes{}, sensorErr(errors.New("telemetry: GetSystemTimes failed"), "system_times_failed")
	}
	ticks := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	return SystemTimes{Idle: ticks(idle), Kernel: ticks(kernel), User: ticks(user)}, nil
}

func readMemoryWindows(context.Context) ([]SensorReading, error) {
	status := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	r, _, callErr := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&status)))
	if r == 0 {
		if errors.Is(callErr, windows.ERROR_ACCESS_DENIED) {
			return nil, sensorErr(ErrPermissionDenied, "memory_status_access_denied")
		}
		return nil, sensorErr(errors.New("telemetry: GlobalMemoryStatusEx failed"), "memory_status_failed")
	}
	return MemoryReadings(status.TotalPhys, status.AvailPhys)
}

func readDiskWindows(ctx context.Context) ([]SensorReading, error) {
	buf := make([]uint16, 512)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buf)), &buf[0])
	if err != nil || n == 0 || int(n) > len(buf) {
		return nil, sensorErr(errors.New("telemetry: GetLogicalDriveStrings failed"), "volume_list_failed")
	}
	var volumes []VolumeSpace
	for start := 0; start < int(n); {
		end := start
		for end < int(n) && buf[end] != 0 {
			end++
		}
		if end == start {
			break
		}
		root := buf[start : end+1]
		start = end + 1
		if windows.GetDriveType(&root[0]) != windows.DRIVE_FIXED {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		vol := VolumeSpace{Root: windows.UTF16ToString(root)}
		var available uint64
		if err := windows.GetDiskFreeSpaceEx(&root[0], &available, &vol.Total, &vol.Free); err != nil {
			vol.Err = volumeError(err)
		}
		volumes = append(volumes, vol)
	}
	return DiskReadings(volumes)
}

func volumeError(err error) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return sensorErr(ErrPermissionDenied, "volume_access_denied")
	case errors.Is(err, windows.ERROR_NOT_READY):
		return sensorErr(ErrSensorUnavailable, "volume_not_ready")
	default:
		return sensorErr(err, "volume_query_failed")
	}
}

func readNetworkWindows(ctx context.Context) ([]SensorReading, error) {
	first, err := interfaceCounters()
	if err != nil {
		return nil, err
	}
	start := time.Now()
	if err := sleepContext(ctx, resourceRateWindow); err != nil {
		return nil, err
	}
	second, err := interfaceCounters()
	elapsed := time.Since(start)
	if err != nil {
		return nil, err
	}
	return NetworkReadings(first, second, elapsed)
}

// interfaceCounters reads hardware, non-filter interfaces. Software loopback,
// tunnels and filter layers are not device network interfaces.
func interfaceCounters() ([]InterfaceCounters, error) {
	var table *windows.MibIfTable2
	if err := windows.GetIfTable2Ex(windows.MibIfTableNormal, &table); err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, sensorErr(ErrPermissionDenied, "interface_table_access_denied")
		}
		return nil, sensorErr(errors.New("telemetry: GetIfTable2Ex failed"), "interface_table_failed")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	rows := unsafe.Slice(&table.Table[0], table.NumEntries)
	var out []InterfaceCounters
	for i := range rows {
		row := &rows[i]
		if row.InterfaceAndOperStatusFlags&ifFlagHardwareInterface == 0 ||
			row.InterfaceAndOperStatusFlags&ifFlagFilterInterface != 0 ||
			row.Type == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		out = append(out, InterfaceCounters{
			Key:     row.InterfaceLuid,
			Up:      row.OperStatus == windows.IfOperStatusUp,
			RxBytes: row.InOctets,
			TxBytes: row.OutOctets,
		})
	}
	return out, nil
}
