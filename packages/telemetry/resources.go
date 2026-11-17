package telemetry

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"time"
)

// TEL05 #91: CPU, memory, fixed-volume and network collectors.
//
// They run as sources of the same SensorCollector as battery, thermal and GPU,
// so each has its own deadline, panic isolation, v2 missing reasons, observation
// time and provenance. Rates come from two counter reads inside one source read.
// A counter that moves backwards or an interface that disappears between the
// reads is a null reading, never a negative rate or a zero.

// Resource source names. They match the #85 planning catalog sources.
const (
	SensorCPU     = "cpu"
	SensorMemory  = "memory"
	SensorDisk    = "disk"
	SensorNetwork = "network"
)

// Resource metric names and the rate unit.
const (
	MetricCPUUtilization      = "cpu_utilization"
	MetricMemoryUsed          = "memory_used"
	MetricVolumeUsed          = "volume_used"
	MetricNetworkReceivedRate = "network_received_rate"
	MetricNetworkSentRate     = "network_sent_rate"
	UnitBytesPerSecond        = "bytes_per_second"
)

// Provider labels name the Win32 call the Go collector makes.
const (
	ProviderSystemTimes    = "Win32:kernel32:GetSystemTimes (250 ms delta, busy = kernel + user - idle)"
	ProviderMemoryStatus   = "Win32:kernel32:GlobalMemoryStatusEx (TotalPhys - AvailPhys) / TotalPhys"
	ProviderFixedVolumes   = "Win32:kernel32:GetDiskSpaceInformationW (DRIVE_FIXED, volume-wide actual units)"
	ProviderInterfaceRx    = "Win32:iphlpapi:GetIfTable2Ex.InOctets (250 ms delta, hardware interfaces)"
	ProviderInterfaceTx    = "Win32:iphlpapi:GetIfTable2Ex.OutOctets (250 ms delta, hardware interfaces)"
	resourceRateWindow     = 250 * time.Millisecond
	maxVolumes             = 26
	maxNetworkInterfaces   = MaxReadingsPerSource / 2
	instanceCPUTotal       = "total"
	instancePhysicalMemory = "physical"
)

func resourceSourceSpecs() []SensorSource {
	return []SensorSource{
		{Name: SensorCPU, Required: []Capability{CapPerfOSProcessor},
			Metrics: []MetricSpec{{MetricCPUUtilization, UnitPercent, ProviderSystemTimes}}},
		{Name: SensorMemory, Required: []Capability{CapOSMemory},
			Metrics: []MetricSpec{{MetricMemoryUsed, UnitPercent, ProviderMemoryStatus}}},
		{Name: SensorDisk, Required: []Capability{CapFixedVolumeSpace},
			Metrics: []MetricSpec{{MetricVolumeUsed, UnitPercent, ProviderFixedVolumes}}},
		{Name: SensorNetwork, Required: []Capability{CapLocalInterfaceCounters},
			Metrics: []MetricSpec{
				{MetricNetworkReceivedRate, UnitBytesPerSecond, ProviderInterfaceRx},
				{MetricNetworkSentRate, UnitBytesPerSecond, ProviderInterfaceTx},
			}},
	}
}

// SystemTimes is one GetSystemTimes read as 100 ns tick counts. Kernel time
// includes idle time.
type SystemTimes struct {
	Idle, Kernel, User uint64
}

// CPUReadings derives machine CPU utilization from two reads. A counter that
// moved backwards is a reset, and an empty interval has no rate. Both are null.
func CPUReadings(first, second SystemTimes) ([]SensorReading, error) {
	if second.Idle < first.Idle || second.Kernel < first.Kernel || second.User < first.User {
		return nil, sensorErr(errors.New("telemetry: cpu counter moved backwards"), "counter_reset")
	}
	idle := second.Idle - first.Idle
	total := (second.Kernel - first.Kernel) + (second.User - first.User)
	switch {
	case total == 0:
		return nil, sensorErr(errors.New("telemetry: cpu counters did not advance"), "no_elapsed_ticks")
	case idle > total:
		return nil, sensorErr(errors.New("telemetry: idle exceeds kernel plus user time"), "out_of_range")
	}
	v := float64(total-idle) / float64(total) * 100
	return []SensorReading{{Metric: MetricCPUUtilization, Instance: instanceCPUTotal, Value: &v}}, nil
}

// MemoryReadings returns physical memory in use. Zero total memory is not a
// reading.
func MemoryReadings(totalPhys, availPhys uint64) ([]SensorReading, error) {
	switch {
	case totalPhys == 0:
		return nil, sensorErr(ErrSensorUnavailable, "memory_total_zero")
	case availPhys > totalPhys:
		return nil, sensorErr(errors.New("telemetry: available memory exceeds total"), "out_of_range")
	}
	v := float64(totalPhys-availPhys) / float64(totalPhys) * 100
	return []SensorReading{{Metric: MetricMemoryUsed, Instance: instancePhysicalMemory, Value: &v}}, nil
}

// DiskSpaceInformation mirrors DISK_SPACE_INFORMATION. Actual* fields are
// volume-wide; Caller* fields are reduced by the caller's disk quota.
type DiskSpaceInformation struct {
	ActualTotalAllocationUnits           uint64
	ActualAvailableAllocationUnits       uint64
	ActualPoolUnavailableAllocationUnits uint64
	CallerTotalAllocationUnits           uint64
	CallerAvailableAllocationUnits       uint64
	CallerPoolUnavailableAllocationUnits uint64
	UsedAllocationUnits                  uint64
	TotalReservedAllocationUnits         uint64
	VolumeStorageReserveAllocationUnits  uint64
	AvailableCommittedAllocationUnits    uint64
	PoolAvailableAllocationUnits         uint64
	SectorsPerAllocationUnit             uint32
	BytesPerSector                       uint32
}

// VolumeBytes returns volume-wide size and free bytes. Quota-relative caller
// fields are never mixed in, so a quota cannot change the used percentage.
func VolumeBytes(info DiskSpaceInformation) (total, free uint64, err error) {
	unit := uint64(info.SectorsPerAllocationUnit) * uint64(info.BytesPerSector) // two uint32s cannot overflow
	if unit == 0 {
		return 0, 0, sensorErr(errors.New("telemetry: invalid allocation unit size"), "volume_geometry_invalid")
	}
	hi, total := bits.Mul64(info.ActualTotalAllocationUnits, unit)
	hi2, free := bits.Mul64(info.ActualAvailableAllocationUnits, unit)
	if hi != 0 || hi2 != 0 {
		return 0, 0, sensorErr(errors.New("telemetry: volume size overflows"), "volume_geometry_invalid")
	}
	return total, free, nil
}

// VolumeSpace is one fixed volume. Root stays inside the collector; readings
// carry only an index label. Err is the per-volume query error.
type VolumeSpace struct {
	Root        string
	Total, Free uint64
	Err         error
}

// DiskReadings returns used space per fixed volume. A denied or not-ready
// volume is a null reading for that volume only; the others stay known.
func DiskReadings(volumes []VolumeSpace) ([]SensorReading, error) {
	if len(volumes) == 0 {
		return nil, sensorErr(ErrSensorUnavailable, "no_fixed_volumes")
	}
	sorted := append([]VolumeSpace(nil), volumes...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Root < sorted[j].Root })
	if len(sorted) > maxVolumes {
		sorted = sorted[:maxVolumes]
	}
	out := make([]SensorReading, 0, len(sorted))
	for i, vol := range sorted {
		r := SensorReading{Metric: MetricVolumeUsed, Instance: fmt.Sprintf("volume-%d", i)}
		switch {
		case vol.Err != nil:
			r.MissingReason, r.Detail = ClassifySensorError(vol.Err)
		case vol.Total == 0:
			r.MissingReason, r.Detail = ReasonSensorUnavailable, "volume_size_zero"
		case vol.Free > vol.Total:
			r.MissingReason, r.Detail = ReasonCollectionError, "out_of_range"
		default:
			v := float64(vol.Total-vol.Free) / float64(vol.Total) * 100
			r.Value = &v
		}
		out = append(out, r)
	}
	return out, nil
}

// InterfaceCounters is one interface in one GetIfTable2Ex read. Key is the
// interface LUID and never leaves the collector.
type InterfaceCounters struct {
	Key     uint64
	Up      bool
	RxBytes uint64
	TxBytes uint64
}

// NetworkReadings derives receive and send rates for each interface in the
// first read. An interface that is not up, disappears or goes down between
// reads, or whose counter moved backwards, gets null readings.
func NetworkReadings(first, second []InterfaceCounters, elapsed time.Duration) ([]SensorReading, error) {
	if len(first) == 0 {
		return nil, sensorErr(ErrSensorUnavailable, "no_hardware_interfaces")
	}
	if elapsed <= 0 {
		return nil, sensorErr(errors.New("telemetry: rate window did not advance"), "no_elapsed_time")
	}
	later := make(map[uint64]InterfaceCounters, len(second))
	for _, c := range second {
		later[c.Key] = c
	}
	sorted := append([]InterfaceCounters(nil), first...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Key < sorted[j].Key })
	if len(sorted) > maxNetworkInterfaces {
		sorted = sorted[:maxNetworkInterfaces]
	}
	seconds := elapsed.Seconds()
	out := make([]SensorReading, 0, 2*len(sorted))
	for i, before := range sorted {
		instance := fmt.Sprintf("interface-%d", i)
		rx := SensorReading{Metric: MetricNetworkReceivedRate, Instance: instance}
		tx := SensorReading{Metric: MetricNetworkSentRate, Instance: instance}
		after, present := later[before.Key]
		reason, detail := "", ""
		switch {
		case !before.Up:
			reason, detail = ReasonSensorUnavailable, "interface_down"
		case !present:
			reason, detail = ReasonSensorUnavailable, "interface_removed"
		case !after.Up:
			reason, detail = ReasonSensorUnavailable, "interface_down"
		}
		if reason != "" {
			rx.MissingReason, rx.Detail = reason, detail
			tx.MissingReason, tx.Detail = reason, detail
			out = append(out, rx, tx)
			continue
		}
		out = append(out,
			rateReading(rx, before.RxBytes, after.RxBytes, seconds),
			rateReading(tx, before.TxBytes, after.TxBytes, seconds))
	}
	return out, nil
}

func rateReading(r SensorReading, before, after uint64, seconds float64) SensorReading {
	if after < before {
		r.MissingReason, r.Detail = ReasonCollectionError, "counter_reset"
		return r
	}
	v := float64(after-before) / seconds
	r.Value = &v
	return r
}
