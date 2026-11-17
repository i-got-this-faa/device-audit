package telemetry

import (
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// requireNull fails unless r is a null reading with the reason and detail.
func requireNull(t *testing.T, r SensorReading, reason, detail string) {
	t.Helper()
	if r.Value != nil || r.MissingReason != reason || r.Detail != detail {
		t.Fatalf("reading = %+v, want null %s/%s", r, reason, detail)
	}
}

func requireValue(t *testing.T, r SensorReading, want float64) {
	t.Helper()
	if r.Value == nil || math.Abs(*r.Value-want) > 1e-9 || r.MissingReason != "" {
		t.Fatalf("reading = %+v, want %v", r, want)
	}
}

func TestCPUReadings(t *testing.T) {
	got, err := CPUReadings(SystemTimes{Idle: 100, Kernel: 300, User: 100}, SystemTimes{Idle: 175, Kernel: 400, User: 100})
	if err != nil {
		t.Fatal(err)
	}
	requireValue(t, got[0], 25)
	if got[0].Instance != instanceCPUTotal {
		t.Fatalf("instance = %q", got[0].Instance)
	}

	for name, tc := range map[string]struct {
		first, second SystemTimes
		reason        string
		detail        string
	}{
		"idle reset":   {SystemTimes{Idle: 50, Kernel: 100}, SystemTimes{Idle: 10, Kernel: 200}, ReasonCollectionError, "counter_reset"},
		"kernel reset": {SystemTimes{Kernel: 100}, SystemTimes{Kernel: 90}, ReasonCollectionError, "counter_reset"},
		"user reset":   {SystemTimes{User: 100}, SystemTimes{User: 1}, ReasonCollectionError, "counter_reset"},
		"no ticks":     {SystemTimes{Kernel: 5}, SystemTimes{Kernel: 5}, ReasonCollectionError, "no_elapsed_ticks"},
		"idle > total": {SystemTimes{}, SystemTimes{Idle: 20, Kernel: 10}, ReasonCollectionError, "out_of_range"},
	} {
		_, err := CPUReadings(tc.first, tc.second)
		reason, detail := ClassifySensorError(err)
		if err == nil || reason != tc.reason || detail != tc.detail {
			t.Fatalf("%s: err=%v reason=%s detail=%s", name, err, reason, detail)
		}
	}
}

func TestMemoryReadings(t *testing.T) {
	got, err := MemoryReadings(16<<30, 4<<30)
	if err != nil {
		t.Fatal(err)
	}
	requireValue(t, got[0], 75)
	if _, err := MemoryReadings(0, 0); err == nil {
		t.Fatal("zero total accepted")
	} else if reason, detail := ClassifySensorError(err); reason != ReasonSensorUnavailable || detail != "memory_total_zero" {
		t.Fatalf("zero total = %s/%s", reason, detail)
	}
	if _, err := MemoryReadings(10, 11); err == nil {
		t.Fatal("available above total accepted")
	}
}

// A denied or not-ready volume is null for that volume; the others stay known
// and the denial is not a zero.
func TestDiskReadingsDeniedVolumeStaysNull(t *testing.T) {
	got, err := DiskReadings([]VolumeSpace{
		{Root: `D:\`, Err: sensorErr(ErrPermissionDenied, "volume_access_denied")},
		{Root: `C:\`, Total: 1000, Free: 250},
		{Root: `E:\`, Err: sensorErr(ErrSensorUnavailable, "volume_not_ready")},
		{Root: `F:\`, Total: 0},
		{Root: `G:\`, Total: 10, Free: 11},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("readings = %+v", got)
	}
	requireValue(t, got[0], 75)
	requireNull(t, got[1], ReasonPermissionDenied, "volume_access_denied")
	requireNull(t, got[2], ReasonSensorUnavailable, "volume_not_ready")
	requireNull(t, got[3], ReasonSensorUnavailable, "volume_size_zero")
	requireNull(t, got[4], ReasonCollectionError, "out_of_range")
	for i, r := range got {
		if r.Instance != []string{"volume-0", "volume-1", "volume-2", "volume-3", "volume-4"}[i] {
			t.Fatalf("instance %d = %q", i, r.Instance)
		}
	}
	if _, err := DiskReadings(nil); err == nil {
		t.Fatal("no volumes accepted")
	}
}

// Counter resets and unavailable interfaces become nulls, never negative or
// fabricated zero rates. A quiet but up interface is a known zero.
func TestNetworkReadingsCounterResetAndUnavailableInterfaces(t *testing.T) {
	first := []InterfaceCounters{
		{Key: 1, Up: true, RxBytes: 1000, TxBytes: 500},  // normal
		{Key: 2, Up: true, RxBytes: 9000, TxBytes: 9000}, // rx counter reset
		{Key: 3, Up: false, RxBytes: 0, TxBytes: 0},      // down for the whole window
		{Key: 4, Up: true, RxBytes: 10, TxBytes: 10},     // removed before second read
		{Key: 5, Up: true, RxBytes: 10, TxBytes: 10},     // went down between reads
		{Key: 6, Up: true, RxBytes: 77, TxBytes: 88},     // idle but up
	}
	second := []InterfaceCounters{
		{Key: 1, Up: true, RxBytes: 1250, TxBytes: 600},
		{Key: 2, Up: true, RxBytes: 100, TxBytes: 9500},
		{Key: 3, Up: false},
		{Key: 5, Up: false, RxBytes: 10, TxBytes: 10},
		{Key: 6, Up: true, RxBytes: 77, TxBytes: 88},
		{Key: 7, Up: true, RxBytes: 1, TxBytes: 1}, // appeared; no baseline
	}
	got, err := NetworkReadings(first, second, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 12 {
		t.Fatalf("readings = %d %+v", len(got), got)
	}
	requireValue(t, got[0], 1000)
	requireValue(t, got[1], 400)
	requireNull(t, got[2], ReasonCollectionError, "counter_reset")
	requireValue(t, got[3], 2000)
	requireNull(t, got[4], ReasonSensorUnavailable, "interface_down")
	requireNull(t, got[5], ReasonSensorUnavailable, "interface_down")
	requireNull(t, got[6], ReasonSensorUnavailable, "interface_removed")
	requireNull(t, got[7], ReasonSensorUnavailable, "interface_removed")
	requireNull(t, got[8], ReasonSensorUnavailable, "interface_down")
	requireValue(t, got[10], 0)
	requireValue(t, got[11], 0)
	for _, r := range got {
		if r.Value != nil && *r.Value < 0 {
			t.Fatalf("negative rate %+v", r)
		}
	}

	if _, err := NetworkReadings(nil, nil, time.Second); err == nil {
		t.Fatal("no interfaces accepted")
	} else if reason, detail := ClassifySensorError(err); reason != ReasonSensorUnavailable || detail != "no_hardware_interfaces" {
		t.Fatalf("no interfaces = %s/%s", reason, detail)
	}
	if _, err := NetworkReadings(first, second, 0); err == nil {
		t.Fatal("zero window accepted")
	}
}

// Through the collector: a source that reports a negative rate is rejected,
// and the resource nulls leave the other sources and v2 fields intact.
func TestResourceSourcesThroughCollector(t *testing.T) {
	collector := SensorCollector{
		Deadline: time.Second,
		Sources: []SensorSource{
			sourceWith(SensorCPU, func(context.Context) ([]SensorReading, error) {
				return CPUReadings(SystemTimes{Kernel: 100}, SystemTimes{Kernel: 50})
			}),
			sourceWith(SensorMemory, func(context.Context) ([]SensorReading, error) {
				return MemoryReadings(8, 2)
			}),
			sourceWith(SensorDisk, func(context.Context) ([]SensorReading, error) {
				return DiskReadings([]VolumeSpace{
					{Root: `C:\`, Total: 100, Free: 40},
					{Root: `D:\`, Err: sensorErr(ErrPermissionDenied, "volume_access_denied")},
				})
			}),
			sourceWith(SensorNetwork, func(context.Context) ([]SensorReading, error) {
				return []SensorReading{{Metric: MetricNetworkReceivedRate, Value: f64(-5)}}, nil
			}),
		},
	}
	sample, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cpu := resultFor(t, sample, SensorCPU)
	requireNull(t, cpu.Readings[0], ReasonCollectionError, "counter_reset")
	if cpu.Outcome != "null" || cpu.Provenance != ProvenanceEndpointSensor || cpu.ObservedAt.IsZero() {
		t.Fatalf("cpu = %+v", cpu)
	}
	disk := resultFor(t, sample, SensorDisk)
	if disk.Outcome != "partial" || disk.Readings[0].Provider != ProviderFixedVolumes || disk.Readings[0].Unit != UnitPercent {
		t.Fatalf("disk = %+v", disk)
	}
	network := resultFor(t, sample, SensorNetwork)
	requireNull(t, network.Readings[0], ReasonCollectionError, "out_of_range")
	if network.Readings[0].Unit != UnitBytesPerSecond {
		t.Fatalf("network = %+v", network)
	}

	m := sample.MetricsV2()
	if m.CPUUtilization.Value != nil || m.CPUUtilization.MissingReason != ReasonCollectionError {
		t.Fatalf("cpu v2 = %+v", m.CPUUtilization)
	}
	if *m.MemoryPercent.Value != 75 || *m.DiskUsedPercent.Value != 60 || m.NetworkLatencyMS != nil {
		t.Fatalf("v2 = %+v %+v %+v", m.MemoryPercent, m.DiskUsedPercent, m.NetworkLatencyMS)
	}
}

func TestEndpointTelemetryV2(t *testing.T) {
	sample := SensorSample{CollectedAt: time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC), Sources: []SourceResult{
		{Source: SensorCPU, Readings: []SensorReading{{Metric: MetricCPUUtilization, Unit: UnitPercent, Value: f64(12.5)}}},
		{Source: SensorDisk, Readings: []SensorReading{{Metric: MetricVolumeUsed, Unit: UnitPercent, MissingReason: ReasonPermissionDenied}}},
	}}
	payload, err := EndpointTelemetryV2(sample, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var decoded contracts.TelemetryV2
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Validate(); err != nil {
		t.Fatal(err)
	}
	if decoded.Source != "endpoint" || decoded.Metrics.CPUUtilization.Unit != "percent" || decoded.Metrics.DiskUsedPercent.MissingReason != ReasonPermissionDenied {
		t.Fatalf("decoded = %s", encoded)
	}

	allNull := SensorSample{CollectedAt: sample.CollectedAt, Sources: sample.Sources[1:]}
	if _, err := EndpointTelemetryV2(allNull, "device-1"); err == nil {
		t.Fatal("payload without a known metric accepted")
	}
	if _, err := EndpointTelemetryV2(sample, "bad id with spaces"); err == nil {
		t.Fatal("invalid device ID accepted")
	}
	if _, err := EndpointTelemetryV2(SensorSample{}, "device-1"); err == nil {
		t.Fatal("zero collection time accepted")
	}
}
