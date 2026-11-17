package telemetry

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// TEL06 #92: nullable battery, thermal and GPU collectors. TEL05 #91 adds CPU,
// memory, disk and network sources to the same collector (resources.go).
//
// A sensor source returns readings with provider, unit and source-local
// instance labels. A failed source becomes null readings with one of the v2
// missing reasons and a fixed detail word. It never becomes a zero, and it never
// stops another source from being read.

const (
	// SensorReportSchema identifies sensor availability output. It is not
	// telemetry v1 or v2 and carries no device identifier.
	SensorReportSchema = "device-audit.sensor-availability.v1"
	// ProvenanceEndpointSensor marks a value an OS provider returned on this host.
	ProvenanceEndpointSensor = "endpoint_sensor"
	// DefaultSensorDeadline bounds one source read.
	DefaultSensorDeadline = 5 * time.Second
	// MaxSensorDeadline matches the probe ceiling.
	MaxSensorDeadline = 30 * time.Second
	// MaxReadingsPerSource bounds provider output.
	MaxReadingsPerSource = 32
)

// Sensor source names. GPU is split so a failed vendor tool cannot null the
// OS engine counter, and the reverse.
const (
	SensorBattery   = "battery"
	SensorThermal   = "thermal"
	SensorGPUEngine = "gpu_engine"
	SensorGPUVendor = "gpu_vendor"
)

// Reading metric names and units.
const (
	MetricBatteryCharge         = "battery_charge"
	MetricACPIZoneTemperature   = "acpi_zone_temperature"
	MetricGPUAdapterUtilization = "gpu_adapter_utilization"
	MetricNvidiaUtilization     = "nvidia_gpu_utilization"
	MetricNvidiaTemperature     = "nvidia_gpu_temperature"
	UnitPercent                 = "percent"
	UnitCelsius                 = "celsius"
)

// Missing reasons. These are exactly the telemetry v2 reasons.
const (
	ReasonSensorUnavailable = "sensor_unavailable"
	ReasonNotApplicable     = "not_applicable"
	ReasonPermissionDenied  = "permission_denied"
	ReasonCollectionError   = "collection_error"
)

// ErrSensorUnavailable means the provider or its sensor is absent or reports
// no usable value. ErrSensorNotApplicable means the hardware class is absent,
// for example a desktop without a system battery.
var (
	ErrSensorUnavailable   = errors.New("telemetry: sensor unavailable")
	ErrSensorNotApplicable = errors.New("telemetry: sensor not applicable")
)

// SensorError carries a fixed detail word alongside a classified cause. The
// detail never contains provider error text, paths or instance names.
type SensorError struct {
	Cause  error
	Detail string
}

func (e *SensorError) Error() string { return fmt.Sprintf("%v (%s)", e.Cause, e.Detail) }
func (e *SensorError) Unwrap() error { return e.Cause }

func sensorErr(cause error, detail string) error { return &SensorError{Cause: cause, Detail: detail} }

// MetricSpec is one expected reading of a source.
type MetricSpec struct {
	Metric   string `json:"metric"`
	Unit     string `json:"unit"`
	Provider string `json:"provider"`
}

// SensorReading is one reading. Value nil requires MissingReason. Instance
// labels are source-local indexes such as "zone-0", never hardware names.
type SensorReading struct {
	Source        string   `json:"source"`
	Metric        string   `json:"metric"`
	Unit          string   `json:"unit"`
	Provider      string   `json:"provider"`
	Instance      string   `json:"instance"`
	Value         *float64 `json:"value"`
	MissingReason string   `json:"missing_reason,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

// SensorSource is one independently bounded provider.
type SensorSource struct {
	Name     string
	Required []Capability
	Metrics  []MetricSpec
	Read     func(context.Context) ([]SensorReading, error)
}

// SourceResult is the outcome of one source read.
type SourceResult struct {
	Source     string          `json:"source"`
	Provenance string          `json:"provenance"`
	ObservedAt time.Time       `json:"observed_at"`
	QueryMS    float64         `json:"query_ms"`
	Outcome    string          `json:"outcome"`
	Readings   []SensorReading `json:"readings"`
}

// SensorSample is one sweep over every configured source.
type SensorSample struct {
	CollectedAt time.Time      `json:"collected_at"`
	Sources     []SourceResult `json:"sources"`
}

// SensorCollector reads the CPU, memory, disk, network, battery, thermal and
// GPU sources. Each source has its own deadline. A panic, error or timeout in
// one source is recorded on that source only.
type SensorCollector struct {
	Sources  []SensorSource
	Deadline time.Duration
	Now      func() time.Time
}

// NewSensorCollector returns every platform source.
func NewSensorCollector() SensorCollector {
	return SensorCollector{Sources: PlatformSensorSources(), Deadline: DefaultSensorDeadline}
}

// Collect reads every source once. It returns an error only for invalid
// configuration or a cancelled parent context, never for a sensor failure.
func (c SensorCollector) Collect(ctx context.Context) (SensorSample, error) {
	if err := c.validate(); err != nil {
		return SensorSample{}, err
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	deadline := c.Deadline
	if deadline == 0 {
		deadline = DefaultSensorDeadline
	}
	sample := SensorSample{CollectedAt: now().UTC()}
	for _, src := range c.Sources {
		if err := ctx.Err(); err != nil {
			return SensorSample{}, err
		}
		result := readSource(ctx, src, deadline, now, nil)
		if errors.Is(ctx.Err(), context.Canceled) {
			return SensorSample{}, ctx.Err()
		}
		sample.Sources = append(sample.Sources, result)
	}
	return sample, nil
}

func (c SensorCollector) validate() error {
	if len(c.Sources) == 0 {
		return errors.New("telemetry: at least one sensor source is required")
	}
	if c.Deadline < 0 || c.Deadline > MaxSensorDeadline {
		return fmt.Errorf("telemetry: sensor deadline must be from 0 to %s", MaxSensorDeadline)
	}
	seen := map[string]bool{}
	for _, src := range c.Sources {
		if src.Name == "" || seen[src.Name] || src.Read == nil || len(src.Metrics) == 0 {
			return fmt.Errorf("telemetry: sensor source %q is incomplete or duplicated", src.Name)
		}
		seen[src.Name] = true
		for _, cap := range src.Required {
			if !knownCapability(cap) || unrestrictedCapability(cap) {
				return fmt.Errorf("telemetry: sensor source %s has invalid capability %s", src.Name, cap)
			}
		}
		for _, m := range src.Metrics {
			if m.Metric == "" || m.Unit == "" || m.Provider == "" {
				return fmt.Errorf("telemetry: sensor source %s has an incomplete metric", src.Name)
			}
		}
	}
	return nil
}

type readOutcome struct {
	readings []SensorReading
	err      error
}

// readSource reads one source under its own deadline. onExit, when set, runs
// when the provider goroutine itself returns, which can be after readSource
// has given up on it at the deadline.
func readSource(parent context.Context, src SensorSource, deadline time.Duration, now func() time.Time, onExit func()) SourceResult {
	ctx, cancel := context.WithTimeout(parent, deadline)
	defer cancel()
	start := now()
	done := make(chan readOutcome, 1)
	go func() {
		if onExit != nil {
			defer onExit()
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				done <- readOutcome{err: sensorErr(errors.New("telemetry: sensor provider panicked"), "provider_panic")}
			}
		}()
		readings, err := src.Read(ctx)
		done <- readOutcome{readings: readings, err: err}
	}()
	var out readOutcome
	select {
	case out = <-done:
	case <-ctx.Done():
		// A provider blocked in a system call may finish later. Its result is
		// discarded; the buffered channel lets that goroutine exit.
		out = readOutcome{err: ctx.Err()}
	}
	elapsed := now().Sub(start)
	result := SourceResult{
		Source:     src.Name,
		Provenance: ProvenanceEndpointSensor,
		ObservedAt: now().UTC(),
		QueryMS:    ms(elapsed),
	}
	if out.err != nil {
		reason, detail := ClassifySensorError(out.err)
		result.Readings = nullReadings(src, reason, detail)
	} else {
		result.Readings = sanitizeReadings(src, out.readings)
	}
	result.Outcome = sourceOutcome(result.Readings)
	return result
}

// ClassifySensorError maps a provider error to a v2 missing reason and a fixed
// detail word. Unknown errors are collection errors, not denials.
func ClassifySensorError(err error) (reason, detail string) {
	var sensorError *SensorError
	if errors.As(err, &sensorError) {
		detail = sensorError.Detail
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ReasonCollectionError, "timeout"
	case errors.Is(err, context.Canceled):
		return ReasonCollectionError, "cancelled"
	case errors.Is(err, ErrPermissionDenied), errors.Is(err, os.ErrPermission):
		return ReasonPermissionDenied, orDetail(detail, "access_denied")
	case errors.Is(err, ErrSensorNotApplicable):
		return ReasonNotApplicable, orDetail(detail, "hardware_absent")
	case errors.Is(err, ErrSensorUnavailable):
		return ReasonSensorUnavailable, orDetail(detail, "provider_absent")
	default:
		return ReasonCollectionError, orDetail(detail, "provider_error")
	}
}

func orDetail(detail, fallback string) string {
	if detail != "" {
		return detail
	}
	return fallback
}

func nullReadings(src SensorSource, reason, detail string) []SensorReading {
	out := make([]SensorReading, 0, len(src.Metrics))
	for _, m := range src.Metrics {
		out = append(out, SensorReading{
			Source: src.Name, Metric: m.Metric, Unit: m.Unit, Provider: m.Provider,
			Instance: "source", MissingReason: reason, Detail: detail,
		})
	}
	return out
}

// sanitizeReadings enforces the reading invariants. A provider that returns a
// value with a reason, a reason it may not use, an unknown metric, or an
// out-of-range number gets that reading turned into a collection error.
func sanitizeReadings(src SensorSource, readings []SensorReading) []SensorReading {
	if len(readings) == 0 {
		return nullReadings(src, ReasonCollectionError, "empty_provider_result")
	}
	if len(readings) > MaxReadingsPerSource {
		readings = readings[:MaxReadingsPerSource]
	}
	specs := map[string]MetricSpec{}
	for _, m := range src.Metrics {
		specs[m.Metric] = m
	}
	out := make([]SensorReading, 0, len(readings))
	for _, r := range readings {
		spec, ok := specs[r.Metric]
		if !ok {
			continue
		}
		r.Source, r.Unit, r.Provider = src.Name, spec.Unit, spec.Provider
		if r.Instance == "" {
			r.Instance = "source"
		}
		switch {
		case r.Value != nil && r.MissingReason != "":
			r.Value, r.MissingReason, r.Detail = nil, ReasonCollectionError, "value_with_reason"
		case r.Value == nil && !validMissingReason(r.MissingReason):
			r.MissingReason, r.Detail = ReasonCollectionError, "missing_reason_invalid"
		case r.Value != nil && !inRange(spec.Unit, *r.Value):
			r.Value, r.MissingReason, r.Detail = nil, ReasonCollectionError, "out_of_range"
		case r.Value != nil:
			r.Detail = ""
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nullReadings(src, ReasonCollectionError, "unknown_metric")
	}
	return out
}

func validMissingReason(reason string) bool {
	switch reason {
	case ReasonSensorUnavailable, ReasonNotApplicable, ReasonPermissionDenied, ReasonCollectionError:
		return true
	}
	return false
}

// inRange rejects NaN/Inf, percents outside 0-100, negative rates and
// temperatures below absolute zero or above 200 Celsius, which no supported
// sensor reports.
func inRange(unit string, v float64) bool {
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return false
	}
	switch unit {
	case UnitPercent:
		return v >= 0 && v <= 100
	case UnitBytesPerSecond:
		return v >= 0
	case UnitCelsius:
		return v > -273.15 && v <= 200
	}
	return true
}

func sourceOutcome(readings []SensorReading) string {
	known := 0
	for _, r := range readings {
		if r.Value != nil {
			known++
		}
	}
	switch {
	case known == len(readings):
		return "success"
	case known > 0:
		return "partial"
	default:
		return "null"
	}
}

// MetricsV2 maps a sample into the v2 fields it can fill.
//
// cpu_utilization and memory_percent are the machine totals. disk_used_percent
// is the fullest fixed volume. battery_percent is the system battery charge.
// temperature_c is the highest ACPI thermal-zone reading; the NVIDIA GPU
// temperature is a different sensor and never fills a missing ACPI value.
// gpu_utilization is the highest adapter or vendor utilization reading.
// Network rates have no v2 field and stay in the collector output. Each is a
// provisional aggregation, not a qualified health input. A field is omitted
// when its source was not configured. When nothing is known, the null keeps
// the most specific reason.
func (s SensorSample) MetricsV2() contracts.MetricsV2 {
	var m contracts.MetricsV2
	m.CPUUtilization = s.aggregate(UnitPercent, map[string]bool{MetricCPUUtilization: true})
	m.MemoryPercent = s.aggregate(UnitPercent, map[string]bool{MetricMemoryUsed: true})
	m.DiskUsedPercent = s.aggregate(UnitPercent, map[string]bool{MetricVolumeUsed: true})
	m.BatteryPercent = s.aggregate(UnitPercent, map[string]bool{MetricBatteryCharge: true})
	m.TemperatureC = s.aggregate(UnitCelsius, map[string]bool{MetricACPIZoneTemperature: true})
	m.GPUUtilization = s.aggregate(UnitPercent, map[string]bool{MetricGPUAdapterUtilization: true, MetricNvidiaUtilization: true})
	return m
}

func (s SensorSample) aggregate(unit string, metrics map[string]bool) *contracts.MetricV2 {
	var best *float64
	reason := ""
	found := false
	for _, src := range s.Sources {
		for _, r := range src.Readings {
			if !metrics[r.Metric] {
				continue
			}
			found = true
			if r.Value != nil {
				if best == nil || *r.Value > *best {
					v := *r.Value
					best = &v
				}
				continue
			}
			if reasonRank(r.MissingReason) > reasonRank(reason) {
				reason = r.MissingReason
			}
		}
	}
	if !found {
		return nil
	}
	if best != nil {
		return &contracts.MetricV2{Value: best, Unit: unit}
	}
	return &contracts.MetricV2{Unit: unit, MissingReason: reason}
}

// reasonRank orders reasons when several null readings feed one v2 field.
// A denial or provider failure is more actionable than an absent sensor, and
// an absent sensor more than absent hardware.
func reasonRank(reason string) int {
	switch reason {
	case ReasonPermissionDenied:
		return 4
	case ReasonCollectionError:
		return 3
	case ReasonSensorUnavailable:
		return 2
	case ReasonNotApplicable:
		return 1
	}
	return 0
}
