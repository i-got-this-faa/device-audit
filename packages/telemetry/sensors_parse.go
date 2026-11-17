package telemetry

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Provider labels. They name the actual OS interface the Go collector calls,
// which differs from the PowerShell probe's CIM classes.
const (
	ProviderBatteryPowerStatus = "Win32:kernel32:GetSystemPowerStatus.BatteryLifePercent"
	ProviderThermalZonePDH     = `PDH:\Thermal Zone Information(*)\Temperature (kelvin)`
	ProviderGPUEnginePDH       = `PDH:\GPU Engine(*)\Utilization Percentage (max engine per adapter)`
	ProviderNvidiaUtilization  = "NVIDIA:nvidia-smi:utilization.gpu"
	ProviderNvidiaTemperature  = "NVIDIA:nvidia-smi:temperature.gpu"
	// NvidiaSMIQuery is the fixed argument list. Nothing else is passed.
	NvidiaSMIQuery  = "--query-gpu=utilization.gpu,temperature.gpu"
	NvidiaSMIFormat = "--format=csv,noheader,nounits"
	maxNvidiaGPUs   = 16
	maxVendorOutput = 64 << 10
)

// SensorSourceSpecs returns the CPU, memory, disk, network, battery, thermal
// and GPU sources without their read functions. Platform files attach the
// readers.
func SensorSourceSpecs() []SensorSource {
	return append(resourceSourceSpecs(), []SensorSource{
		{Name: SensorBattery, Required: []Capability{CapBatteryCharge},
			Metrics: []MetricSpec{{MetricBatteryCharge, UnitPercent, ProviderBatteryPowerStatus}}},
		{Name: SensorThermal, Required: []Capability{CapACPIThermal},
			Metrics: []MetricSpec{{MetricACPIZoneTemperature, UnitCelsius, ProviderThermalZonePDH}}},
		{Name: SensorGPUEngine, Required: []Capability{CapGPUEngine},
			Metrics: []MetricSpec{{MetricGPUAdapterUtilization, UnitPercent, ProviderGPUEnginePDH}}},
		{Name: SensorGPUVendor, Required: []Capability{CapExistingNvidiaSMI},
			Metrics: []MetricSpec{
				{MetricNvidiaUtilization, UnitPercent, ProviderNvidiaUtilization},
				{MetricNvidiaTemperature, UnitCelsius, ProviderNvidiaTemperature},
			}},
	}...)
}

// PowerStatus mirrors SYSTEM_POWER_STATUS.
type PowerStatus struct {
	ACLineStatus        uint8
	BatteryFlag         uint8
	BatteryLifePercent  uint8
	SystemStatusFlag    uint8
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

const (
	batteryFlagNoBattery  = 128
	batteryFlagUnknown    = 255
	batteryPercentUnknown = 255
)

// BatteryReadings decodes SYSTEM_POWER_STATUS. No system battery is
// not_applicable. An unknown status or charge is sensor_unavailable.
func BatteryReadings(status PowerStatus) ([]SensorReading, error) {
	switch {
	case status.BatteryFlag == batteryFlagUnknown:
		return nil, sensorErr(ErrSensorUnavailable, "battery_status_unknown")
	case status.BatteryFlag&batteryFlagNoBattery != 0:
		return nil, sensorErr(ErrSensorNotApplicable, "no_system_battery")
	case status.BatteryLifePercent == batteryPercentUnknown:
		return nil, sensorErr(ErrSensorUnavailable, "charge_unknown")
	case status.BatteryLifePercent > 100:
		return nil, sensorErr(errors.New("telemetry: battery percent out of range"), "out_of_range")
	}
	v := float64(status.BatteryLifePercent)
	return []SensorReading{{Metric: MetricBatteryCharge, Instance: "system", Value: &v}}, nil
}

// CounterItem is one formatted PDH counter instance. Name stays inside the
// collector; it is never exported.
type CounterItem struct {
	Name   string
	Status uint32
	Value  float64
}

const (
	pdhCStatusValidData = 0x00000000
	pdhCStatusNewData   = 0x00000001
)

func validCounter(item CounterItem) bool {
	return item.Status == pdhCStatusValidData || item.Status == pdhCStatusNewData
}

// ThermalReadings converts thermal-zone Kelvin values to Celsius. No zones is
// sensor_unavailable: the provider exposes nothing to read. A non-positive
// Kelvin value is a null reading, not zero Celsius.
func ThermalReadings(items []CounterItem) ([]SensorReading, error) {
	if len(items) == 0 {
		return nil, sensorErr(ErrSensorUnavailable, "no_thermal_zones")
	}
	sorted := sortedItems(items)
	out := make([]SensorReading, 0, len(sorted))
	for i, item := range sorted {
		r := SensorReading{Metric: MetricACPIZoneTemperature, Instance: fmt.Sprintf("zone-%d", i)}
		switch {
		case !validCounter(item):
			r.MissingReason, r.Detail = ReasonCollectionError, "counter_status_invalid"
		case item.Value <= 0:
			r.MissingReason, r.Detail = ReasonSensorUnavailable, "non_positive_kelvin"
		default:
			v := item.Value - 273.15
			r.Value = &v
		}
		out = append(out, r)
	}
	return out, nil
}

// GPUEngineReadings aggregates per-process GPU engine instances the way the
// Windows task manager does: sum processes per engine, then take the busiest
// engine of each adapter. Adapter labels are indexes; LUIDs and PIDs are
// dropped. No instances is sensor_unavailable, not not_applicable: a hosted
// denied account saw zero instances on a VM that had a display adapter.
func GPUEngineReadings(items []CounterItem) ([]SensorReading, error) {
	if len(items) == 0 {
		return nil, sensorErr(ErrSensorUnavailable, "no_engine_instances")
	}
	engines := map[string]float64{}
	adapters := map[string]bool{}
	valid := 0
	for _, item := range items {
		adapter, engine, ok := parseGPUEngineInstance(item.Name)
		if !ok || !validCounter(item) || item.Value < 0 {
			continue
		}
		valid++
		adapters[adapter] = true
		engines[adapter+"|"+engine] += item.Value
	}
	if valid == 0 {
		return nil, sensorErr(errors.New("telemetry: no valid GPU engine counters"), "counter_status_invalid")
	}
	names := make([]string, 0, len(adapters))
	for name := range adapters {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]SensorReading, 0, len(names))
	for i, adapter := range names {
		busiest := 0.0
		for key, value := range engines {
			if strings.HasPrefix(key, adapter+"|") && value > busiest {
				busiest = value
			}
		}
		if busiest > 100 {
			busiest = 100
		}
		v := busiest
		out = append(out, SensorReading{Metric: MetricGPUAdapterUtilization, Instance: fmt.Sprintf("adapter-%d", i), Value: &v})
	}
	return out, nil
}

// parseGPUEngineInstance reads "pid_N_luid_0xH_0xL_phys_P_eng_E_engtype_T".
func parseGPUEngineInstance(name string) (adapter, engine string, ok bool) {
	fields := strings.Split(name, "_")
	var luidHigh, luidLow, phys, eng string
	for i := 0; i < len(fields); i++ {
		switch fields[i] {
		case "luid":
			if i+2 < len(fields) {
				luidHigh, luidLow = fields[i+1], fields[i+2]
				i += 2
			}
		case "phys":
			if i+1 < len(fields) {
				phys = fields[i+1]
				i++
			}
		case "eng":
			if i+1 < len(fields) {
				eng = fields[i+1]
				i++
			}
		}
	}
	if luidHigh == "" || luidLow == "" || phys == "" || eng == "" {
		return "", "", false
	}
	return luidHigh + luidLow + "/" + phys, eng, true
}

func sortedItems(items []CounterItem) []CounterItem {
	sorted := append([]CounterItem(nil), items...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	return sorted
}

// NvidiaReadings parses nvidia-smi CSV output. "[N/A]" and "[Not Supported]"
// fields are sensor_unavailable readings for that GPU and field only.
func NvidiaReadings(output []byte) ([]SensorReading, error) {
	if len(output) > maxVendorOutput {
		return nil, sensorErr(errors.New("telemetry: vendor output too large"), "vendor_output_too_large")
	}
	var out []SensorReading
	scanner := bufio.NewScanner(bytes.NewReader(output))
	gpu := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if gpu >= maxNvidiaGPUs {
			break
		}
		fields := strings.Split(line, ",")
		if len(fields) != 2 {
			return nil, sensorErr(errors.New("telemetry: malformed vendor output"), "malformed_vendor_output")
		}
		instance := fmt.Sprintf("nvidia-%d", gpu)
		out = append(out,
			vendorField(MetricNvidiaUtilization, instance, fields[0]),
			vendorField(MetricNvidiaTemperature, instance, fields[1]))
		gpu++
	}
	if err := scanner.Err(); err != nil {
		return nil, sensorErr(err, "malformed_vendor_output")
	}
	if len(out) == 0 {
		return nil, sensorErr(ErrSensorUnavailable, "no_vendor_gpus")
	}
	return out, nil
}

func vendorField(metric, instance, raw string) SensorReading {
	r := SensorReading{Metric: metric, Instance: instance}
	field := strings.TrimSpace(raw)
	switch field {
	case "[N/A]", "[Not Supported]", "N/A":
		r.MissingReason, r.Detail = ReasonSensorUnavailable, "vendor_field_unsupported"
		return r
	case "[Insufficient Permissions]":
		r.MissingReason, r.Detail = ReasonPermissionDenied, "vendor_insufficient_permissions"
		return r
	}
	v, err := strconv.ParseFloat(field, 64)
	if err != nil {
		r.MissingReason, r.Detail = ReasonCollectionError, "malformed_vendor_output"
		return r
	}
	r.Value = &v
	return r
}

// NvidiaExitError classifies a non-zero nvidia-smi exit code using the
// tool's documented return values.
func NvidiaExitError(code int) error {
	switch code {
	case 4:
		return sensorErr(ErrPermissionDenied, "vendor_insufficient_permissions")
	case 9:
		return sensorErr(ErrSensorUnavailable, "vendor_driver_not_loaded")
	case 12:
		return sensorErr(ErrSensorUnavailable, "vendor_library_not_found")
	case 3, 13:
		return sensorErr(ErrSensorUnavailable, "vendor_query_not_supported")
	default:
		return sensorErr(fmt.Errorf("telemetry: nvidia-smi exit %d", code), "vendor_query_failed")
	}
}

// PDH status values used for classification.
const (
	PDHMoreData          uint32 = 0x800007D2
	PDHNoData            uint32 = 0x800007D5
	PDHCStatusNoInstance uint32 = 0x800007D1
	PDHCStatusNoObject   uint32 = 0xC0000BB8
	PDHCStatusNoCounter  uint32 = 0xC0000BB9
	PDHCStatusBadPath    uint32 = 0xC0000BC0
	PDHAccessDenied      uint32 = 0xC0000BDB
	PDHInvalidData       uint32 = 0xC0000BC6
	win32AccessDenied    uint32 = 5
)

// PDHError is a PDH status code with classification.
type PDHError struct{ Status uint32 }

func (e PDHError) Error() string { return fmt.Sprintf("telemetry: PDH status 0x%08X", e.Status) }

// Is maps PDH statuses onto the sensor sentinel errors.
func (e PDHError) Is(target error) bool {
	switch target {
	case ErrPermissionDenied:
		return e.Status == PDHAccessDenied || e.Status == win32AccessDenied
	case ErrSensorUnavailable:
		switch e.Status {
		case PDHCStatusNoObject, PDHCStatusNoCounter, PDHCStatusBadPath, PDHCStatusNoInstance, PDHNoData:
			return true
		}
	}
	return false
}

// pdhDetail is the fixed detail word for a PDH status.
func pdhDetail(status uint32) string {
	switch status {
	case PDHAccessDenied, win32AccessDenied:
		return "pdh_access_denied"
	case PDHCStatusNoObject:
		return "pdh_object_absent"
	case PDHCStatusNoCounter, PDHCStatusBadPath:
		return "pdh_counter_absent"
	case PDHCStatusNoInstance, PDHNoData:
		return "pdh_no_instances"
	default:
		return "pdh_call_failed"
	}
}

// PDHFailure wraps a non-zero PDH status as a classified sensor error.
func PDHFailure(status uint32) error {
	return sensorErr(PDHError{Status: status}, pdhDetail(status))
}

// sleepContext waits d or until ctx ends.
func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
