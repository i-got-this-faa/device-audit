package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// SensorQualificationNone is the only qualification the availability report
// makes. The process cannot attest its token or that the host is a selected
// physical target.
const SensorQualificationNone = "not_service_token_or_physical_target_attested"

// MaxSensorSamples bounds an availability run.
const MaxSensorSamples = 30

// SensorReport records which battery, thermal and GPU readings a host
// returned. It contains no hostname, serial, device ID, LUID, PID or zone name.
type SensorReport struct {
	Schema        string                `json:"schema"`
	Provenance    string                `json:"provenance"`
	Qualification string                `json:"qualification"`
	Host          HostInfo              `json:"host"`
	IntervalMS    int64                 `json:"interval_ms"`
	DeadlineMS    int64                 `json:"deadline_ms"`
	Samples       []SensorSample        `json:"samples"`
	MetricsV2     []contracts.MetricsV2 `json:"metrics_v2"`
	Availability  []MetricAvailability  `json:"availability"`
}

// MetricAvailability counts the outcomes of one source metric across samples.
type MetricAvailability struct {
	Source     string         `json:"source"`
	Metric     string         `json:"metric"`
	Unit       string         `json:"unit"`
	Provider   string         `json:"provider"`
	Known      int            `json:"known"`
	Null       int            `json:"null"`
	Reasons    map[string]int `json:"reasons,omitempty"`
	Details    map[string]int `json:"details,omitempty"`
	MinValue   *float64       `json:"min_value"`
	MaxValue   *float64       `json:"max_value"`
	MaxQueryMS float64        `json:"max_query_ms"`
}

// SensorRun samples the collector repeatedly at a fixed start-to-start
// interval without catch-up sweeps.
type SensorRun struct {
	Collector SensorCollector
	Samples   int
	Interval  time.Duration
	Sleep     func(context.Context, time.Duration) error
}

// Measure runs the samples and builds the report.
func (r SensorRun) Measure(ctx context.Context) (SensorReport, error) {
	if r.Samples < 1 || r.Samples > MaxSensorSamples {
		return SensorReport{}, fmt.Errorf("telemetry: samples must be from 1 to %d", MaxSensorSamples)
	}
	if r.Interval < 0 || r.Interval > MaxInterval {
		return SensorReport{}, fmt.Errorf("telemetry: interval must be from 0 to %s", MaxInterval)
	}
	sleep := r.Sleep
	if sleep == nil {
		sleep = sleepContext
	}
	deadline := r.Collector.Deadline
	if deadline == 0 {
		deadline = DefaultSensorDeadline
	}
	report := SensorReport{
		Schema:        SensorReportSchema,
		Provenance:    ProvenanceEndpointSensor,
		Qualification: SensorQualificationNone,
		Host:          CurrentHost(),
		IntervalMS:    r.Interval.Milliseconds(),
		DeadlineMS:    deadline.Milliseconds(),
	}
	for i := 0; i < r.Samples; i++ {
		start := time.Now()
		sample, err := r.Collector.Collect(ctx)
		if err != nil {
			return SensorReport{}, err
		}
		report.Samples = append(report.Samples, sample)
		report.MetricsV2 = append(report.MetricsV2, sample.MetricsV2())
		if i < r.Samples-1 {
			if wait := r.Interval - time.Since(start); wait > 0 {
				if err := sleep(ctx, wait); err != nil {
					return SensorReport{}, err
				}
			}
		}
	}
	report.Availability = summarizeSensors(report.Samples)
	return report, nil
}

func summarizeSensors(samples []SensorSample) []MetricAvailability {
	index := map[string]*MetricAvailability{}
	var order []string
	for _, sample := range samples {
		for _, src := range sample.Sources {
			for _, r := range src.Readings {
				key := src.Source + "|" + r.Metric
				a, ok := index[key]
				if !ok {
					a = &MetricAvailability{Source: src.Source, Metric: r.Metric, Unit: r.Unit, Provider: r.Provider}
					index[key] = a
					order = append(order, key)
				}
				if src.QueryMS > a.MaxQueryMS {
					a.MaxQueryMS = src.QueryMS
				}
				if r.Value != nil {
					a.Known++
					v := *r.Value
					if a.MinValue == nil || v < *a.MinValue {
						a.MinValue = &v
					}
					if a.MaxValue == nil || v > *a.MaxValue {
						w := v
						a.MaxValue = &w
					}
					continue
				}
				a.Null++
				if a.Reasons == nil {
					a.Reasons, a.Details = map[string]int{}, map[string]int{}
				}
				a.Reasons[r.MissingReason]++
				if r.Detail != "" {
					a.Details[r.Detail]++
				}
			}
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return order[i] < order[j] })
	out := make([]MetricAvailability, 0, len(order))
	for _, key := range order {
		out = append(out, *index[key])
	}
	return out
}

// MarshalSensorReport encodes an availability report, indented.
func MarshalSensorReport(report SensorReport) ([]byte, error) {
	if report.Schema != SensorReportSchema || report.Provenance != ProvenanceEndpointSensor || report.Qualification != SensorQualificationNone {
		return nil, errors.New("telemetry: refusing to encode a report that is not the sensor availability schema")
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
