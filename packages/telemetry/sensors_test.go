package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func f64(v float64) *float64 { return &v }

func sourceWith(name string, read func(context.Context) ([]SensorReading, error)) SensorSource {
	for _, src := range SensorSourceSpecs() {
		if src.Name == name {
			src.Read = read
			return src
		}
	}
	panic("unknown source " + name)
}

func resultFor(t *testing.T, sample SensorSample, name string) SourceResult {
	t.Helper()
	for _, r := range sample.Sources {
		if r.Source == name {
			return r
		}
	}
	t.Fatalf("source %s missing from sample", name)
	return SourceResult{}
}

// The acceptance case: missing battery, absent thermal provider and denied GPU
// sensor each return null with a distinct reason, and none stops the vendor
// source from being read.
func TestSensorCollectorDistinctNullReasonsDoNotFailOtherSources(t *testing.T) {
	collector := SensorCollector{
		Deadline: time.Second,
		Sources: []SensorSource{
			sourceWith(SensorBattery, func(context.Context) ([]SensorReading, error) {
				return BatteryReadings(PowerStatus{BatteryFlag: batteryFlagNoBattery, BatteryLifePercent: batteryPercentUnknown})
			}),
			sourceWith(SensorThermal, func(context.Context) ([]SensorReading, error) {
				return nil, PDHFailure(PDHCStatusNoObject)
			}),
			sourceWith(SensorGPUEngine, func(context.Context) ([]SensorReading, error) {
				return nil, PDHFailure(PDHAccessDenied)
			}),
			sourceWith(SensorGPUVendor, func(context.Context) ([]SensorReading, error) {
				return NvidiaReadings([]byte("7, 48\n"))
			}),
		},
	}
	sample, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		SensorBattery:   {ReasonNotApplicable, "no_system_battery"},
		SensorThermal:   {ReasonSensorUnavailable, "pdh_object_absent"},
		SensorGPUEngine: {ReasonPermissionDenied, "pdh_access_denied"},
	}
	for name, reason := range want {
		got := resultFor(t, sample, name)
		if got.Outcome != "null" || len(got.Readings) != 1 {
			t.Fatalf("%s: %+v", name, got)
		}
		r := got.Readings[0]
		if r.Value != nil || r.MissingReason != reason[0] || r.Detail != reason[1] || r.Provider == "" || r.Unit == "" {
			t.Fatalf("%s reading = %+v, want %v", name, r, reason)
		}
	}
	vendor := resultFor(t, sample, SensorGPUVendor)
	if vendor.Outcome != "success" || *vendor.Readings[0].Value != 7 || *vendor.Readings[1].Value != 48 {
		t.Fatalf("vendor source did not survive earlier failures: %+v", vendor)
	}

	metrics := sample.MetricsV2()
	if metrics.BatteryPercent.Value != nil || metrics.BatteryPercent.MissingReason != ReasonNotApplicable {
		t.Fatalf("battery = %+v", metrics.BatteryPercent)
	}
	// The NVIDIA temperature never fills the missing ACPI thermal value.
	if metrics.TemperatureC.Value != nil || metrics.TemperatureC.MissingReason != ReasonSensorUnavailable {
		t.Fatalf("temperature = %+v", metrics.TemperatureC)
	}
	if metrics.GPUUtilization.Value == nil || *metrics.GPUUtilization.Value != 7 {
		t.Fatalf("gpu = %+v", metrics.GPUUtilization)
	}
}

func TestSensorCollectorTimeoutPanicAndErrorStayOnTheirSource(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	collector := SensorCollector{
		Deadline: 20 * time.Millisecond,
		Sources: []SensorSource{
			sourceWith(SensorBattery, func(context.Context) ([]SensorReading, error) {
				<-block // a provider stuck in a system call that ignores ctx
				return nil, nil
			}),
			sourceWith(SensorThermal, func(context.Context) ([]SensorReading, error) {
				panic("provider bug")
			}),
			sourceWith(SensorGPUEngine, func(context.Context) ([]SensorReading, error) {
				return nil, errors.New("opaque failure with C:\\private\\path")
			}),
			sourceWith(SensorGPUVendor, func(context.Context) ([]SensorReading, error) {
				return nil, NvidiaExitError(4)
			}),
		},
	}
	sample, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		SensorBattery:   {ReasonCollectionError, "timeout"},
		SensorThermal:   {ReasonCollectionError, "provider_panic"},
		SensorGPUEngine: {ReasonCollectionError, "provider_error"},
		SensorGPUVendor: {ReasonPermissionDenied, "vendor_insufficient_permissions"},
	}
	for name, want := range cases {
		got := resultFor(t, sample, name)
		for _, r := range got.Readings {
			if r.Value != nil || r.MissingReason != want[0] || r.Detail != want[1] {
				t.Fatalf("%s reading = %+v, want %v", name, r, want)
			}
			if strings.Contains(r.Detail, "private") {
				t.Fatal("provider error text leaked into detail")
			}
		}
	}
	if n := len(resultFor(t, sample, SensorGPUVendor).Readings); n != 2 {
		t.Fatalf("vendor null readings = %d, want one per metric", n)
	}
}

func TestSensorCollectorParentCancelIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	collector := SensorCollector{Sources: []SensorSource{
		sourceWith(SensorBattery, func(ctx context.Context) ([]SensorReading, error) {
			cancel()
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}}
	if _, err := collector.Collect(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

func TestSensorCollectorRejectsBadConfiguration(t *testing.T) {
	read := func(context.Context) ([]SensorReading, error) { return nil, nil }
	bad := []SensorCollector{
		{},
		{Sources: []SensorSource{sourceWith(SensorBattery, nil)}},
		{Sources: []SensorSource{sourceWith(SensorBattery, read), sourceWith(SensorBattery, read)}},
		{Sources: []SensorSource{{Name: "x", Read: read, Metrics: []MetricSpec{{Metric: "m", Unit: "u", Provider: "p"}}, Required: []Capability{CapAdministrator}}}},
		{Sources: []SensorSource{{Name: "x", Read: read, Metrics: []MetricSpec{{Metric: "m"}}}}},
		{Sources: []SensorSource{sourceWith(SensorBattery, read)}, Deadline: time.Hour},
	}
	for i, c := range bad {
		if _, err := c.Collect(context.Background()); err == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}

func TestSanitizeReadingsEnforcesInvariants(t *testing.T) {
	src := sourceWith(SensorGPUVendor, nil)
	got := sanitizeReadings(src, []SensorReading{
		{Metric: MetricNvidiaUtilization, Value: f64(5), MissingReason: ReasonSensorUnavailable},
		{Metric: MetricNvidiaUtilization, Value: f64(101)},
		{Metric: MetricNvidiaTemperature, Value: f64(math.NaN())},
		{Metric: MetricNvidiaTemperature},
		{Metric: MetricNvidiaTemperature, MissingReason: "timeout"},
		{Metric: "unknown_metric", Value: f64(1)},
		{Metric: MetricNvidiaTemperature, Value: f64(0), Unit: "kelvin", Provider: "spoofed"},
	})
	wantDetail := []string{"value_with_reason", "out_of_range", "out_of_range", "missing_reason_invalid", "missing_reason_invalid", ""}
	if len(got) != len(wantDetail) {
		t.Fatalf("got %d readings: %+v", len(got), got)
	}
	for i, r := range got {
		if r.Detail != wantDetail[i] {
			t.Fatalf("reading %d = %+v, want detail %q", i, r, wantDetail[i])
		}
	}
	last := got[len(got)-1]
	// A genuine provider zero is kept; unit and provider come from the spec.
	if last.Value == nil || *last.Value != 0 || last.Unit != UnitCelsius || last.Provider != ProviderNvidiaTemperature {
		t.Fatalf("last = %+v", last)
	}
	if empty := sanitizeReadings(src, nil); len(empty) != 2 || empty[0].Detail != "empty_provider_result" {
		t.Fatalf("empty = %+v", empty)
	}
}

func TestBatteryReadings(t *testing.T) {
	cases := []struct {
		status PowerStatus
		value  float64
		reason string
		detail string
	}{
		{PowerStatus{BatteryFlag: 1, BatteryLifePercent: 87}, 87, "", ""},
		{PowerStatus{BatteryFlag: 8, BatteryLifePercent: 0}, 0, "", ""},
		{PowerStatus{BatteryFlag: 128, BatteryLifePercent: 255}, 0, ReasonNotApplicable, "no_system_battery"},
		{PowerStatus{BatteryFlag: 255, BatteryLifePercent: 255}, 0, ReasonSensorUnavailable, "battery_status_unknown"},
		{PowerStatus{BatteryFlag: 2, BatteryLifePercent: 255}, 0, ReasonSensorUnavailable, "charge_unknown"},
		{PowerStatus{BatteryFlag: 2, BatteryLifePercent: 101}, 0, ReasonCollectionError, "out_of_range"},
	}
	for i, c := range cases {
		readings, err := BatteryReadings(c.status)
		if c.reason == "" {
			if err != nil || len(readings) != 1 || *readings[0].Value != c.value {
				t.Fatalf("case %d: %+v %v", i, readings, err)
			}
			continue
		}
		reason, detail := ClassifySensorError(err)
		if reason != c.reason || detail != c.detail {
			t.Fatalf("case %d: %s/%s, want %s/%s", i, reason, detail, c.reason, c.detail)
		}
	}
}

func TestThermalReadings(t *testing.T) {
	if _, err := ThermalReadings(nil); !errors.Is(err, ErrSensorUnavailable) {
		t.Fatalf("no zones err = %v", err)
	}
	readings, err := ThermalReadings([]CounterItem{
		{Name: `\_TZ.THRM`, Value: 318},
		{Name: `\_TZ.CPUZ`, Value: 0},
		{Name: `\_TZ.GPUZ`, Status: PDHInvalidData, Value: 300},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Sorted by name, labelled by index; the ACPI path is not exported.
	if readings[0].Instance != "zone-0" || readings[0].MissingReason != ReasonSensorUnavailable || readings[0].Detail != "non_positive_kelvin" {
		t.Fatalf("zone-0 = %+v", readings[0])
	}
	if readings[1].MissingReason != ReasonCollectionError {
		t.Fatalf("zone-1 = %+v", readings[1])
	}
	if v := readings[2].Value; v == nil || math.Abs(*v-44.85) > 1e-9 {
		t.Fatalf("zone-2 = %+v", readings[2])
	}
	encoded, _ := json.Marshal(readings)
	if strings.Contains(string(encoded), "_TZ") {
		t.Fatal("thermal zone name leaked")
	}
}

func TestGPUEngineReadings(t *testing.T) {
	if _, err := GPUEngineReadings(nil); !errors.Is(err, ErrSensorUnavailable) {
		t.Fatalf("no instances err = %v", err)
	}
	items := []CounterItem{
		// adapter A, engine 0 (3D): two processes sum to 70.
		{Name: "pid_100_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D", Value: 40},
		{Name: "pid_200_luid_0x00000000_0x0000AAAA_phys_0_eng_0_engtype_3D", Value: 30},
		// adapter A, engine 1 (Copy): 10.
		{Name: "pid_100_luid_0x00000000_0x0000AAAA_phys_0_eng_1_engtype_Copy", Value: 10},
		// adapter B: per-process sum above 100 is clamped.
		{Name: "pid_300_luid_0x00000000_0x0000BBBB_phys_0_eng_0_engtype_3D", Value: 80},
		{Name: "pid_301_luid_0x00000000_0x0000BBBB_phys_0_eng_0_engtype_3D", Value: 40},
		// ignored: malformed name and invalid status.
		{Name: "garbage", Value: 99},
		{Name: "pid_1_luid_0x00000000_0x0000CCCC_phys_0_eng_0_engtype_3D", Status: PDHInvalidData, Value: 99},
	}
	readings, err := GPUEngineReadings(items)
	if err != nil {
		t.Fatal(err)
	}
	if len(readings) != 2 || *readings[0].Value != 70 || *readings[1].Value != 100 {
		t.Fatalf("readings = %+v", readings)
	}
	encoded, _ := json.Marshal(readings)
	for _, leaked := range []string{"pid_", "luid", "AAAA", "BBBB"} {
		if strings.Contains(string(encoded), leaked) {
			t.Fatalf("%s leaked: %s", leaked, encoded)
		}
	}
	if _, err := GPUEngineReadings(items[5:]); err == nil {
		t.Fatal("all-invalid counters accepted")
	} else if reason, _ := ClassifySensorError(err); reason != ReasonCollectionError {
		t.Fatalf("all-invalid reason = %s", reason)
	}
}

func TestNvidiaReadings(t *testing.T) {
	readings, err := NvidiaReadings([]byte("0, 43\r\n[N/A], [Not Supported]\n12, [Insufficient Permissions]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(readings) != 6 {
		t.Fatalf("readings = %+v", readings)
	}
	// A provider-returned zero utilization stays a known zero.
	if readings[0].Value == nil || *readings[0].Value != 0 || *readings[1].Value != 43 {
		t.Fatalf("gpu 0 = %+v %+v", readings[0], readings[1])
	}
	if readings[2].MissingReason != ReasonSensorUnavailable || readings[3].MissingReason != ReasonSensorUnavailable {
		t.Fatalf("gpu 1 = %+v %+v", readings[2], readings[3])
	}
	if readings[4].Value == nil || readings[5].MissingReason != ReasonPermissionDenied {
		t.Fatalf("gpu 2 = %+v %+v", readings[4], readings[5])
	}
	for _, bad := range []string{"1,2,3\n", "only-one\n"} {
		if _, err := NvidiaReadings([]byte(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	if _, err := NvidiaReadings(nil); !errors.Is(err, ErrSensorUnavailable) {
		t.Fatalf("empty err = %v", err)
	}
	if _, err := NvidiaReadings(make([]byte, maxVendorOutput+1)); err == nil {
		t.Fatal("oversized output accepted")
	}
	if r, _ := NvidiaReadings([]byte("x, 40\n")); r[0].MissingReason != ReasonCollectionError {
		t.Fatalf("malformed field = %+v", r[0])
	}
}

func TestNvidiaExitAndPDHClassification(t *testing.T) {
	cases := []struct {
		err    error
		reason string
		detail string
	}{
		{NvidiaExitError(4), ReasonPermissionDenied, "vendor_insufficient_permissions"},
		{NvidiaExitError(9), ReasonSensorUnavailable, "vendor_driver_not_loaded"},
		{NvidiaExitError(12), ReasonSensorUnavailable, "vendor_library_not_found"},
		{NvidiaExitError(13), ReasonSensorUnavailable, "vendor_query_not_supported"},
		{NvidiaExitError(255), ReasonCollectionError, "vendor_query_failed"},
		{PDHFailure(PDHAccessDenied), ReasonPermissionDenied, "pdh_access_denied"},
		{PDHFailure(PDHCStatusNoObject), ReasonSensorUnavailable, "pdh_object_absent"},
		{PDHFailure(PDHCStatusNoCounter), ReasonSensorUnavailable, "pdh_counter_absent"},
		{PDHFailure(PDHNoData), ReasonSensorUnavailable, "pdh_no_instances"},
		{PDHFailure(0xC0000BBC), ReasonCollectionError, "pdh_call_failed"},
		{os.ErrPermission, ReasonPermissionDenied, "access_denied"},
		{context.DeadlineExceeded, ReasonCollectionError, "timeout"},
	}
	for i, c := range cases {
		reason, detail := ClassifySensorError(c.err)
		if reason != c.reason || detail != c.detail {
			t.Fatalf("case %d: %s/%s, want %s/%s", i, reason, detail, c.reason, c.detail)
		}
	}
}

// The mapped fields validate as telemetry v2 when another metric is known, and
// an all-null sensor sample still keeps units and reasons.
func TestSensorMetricsV2Validate(t *testing.T) {
	sample := SensorSample{Sources: []SourceResult{
		{Source: SensorBattery, Readings: []SensorReading{{Metric: MetricBatteryCharge, Value: f64(64)}}},
		{Source: SensorThermal, Readings: []SensorReading{
			{Metric: MetricACPIZoneTemperature, Value: f64(41.5)},
			{Metric: MetricACPIZoneTemperature, Value: f64(55.25)},
		}},
		{Source: SensorGPUEngine, Readings: []SensorReading{{Metric: MetricGPUAdapterUtilization, MissingReason: ReasonSensorUnavailable}}},
		{Source: SensorGPUVendor, Readings: []SensorReading{
			{Metric: MetricNvidiaUtilization, MissingReason: ReasonPermissionDenied},
			{Metric: MetricNvidiaTemperature, Value: f64(90)},
		}},
	}}
	m := sample.MetricsV2()
	if *m.BatteryPercent.Value != 64 || *m.TemperatureC.Value != 55.25 {
		t.Fatalf("metrics = %+v %+v", m.BatteryPercent, m.TemperatureC)
	}
	if m.GPUUtilization.Value != nil || m.GPUUtilization.MissingReason != ReasonPermissionDenied {
		t.Fatalf("gpu = %+v", m.GPUUtilization)
	}
	telemetry := contracts.TelemetryV2{
		SchemaVersion: contracts.TelemetryV2Version, DeviceID: "fixture-device", CollectedAt: time.Unix(1, 0).UTC(),
		Source: "fixture", Metrics: m, Inventory: contracts.InventoryV2{Components: []contracts.ComponentV2{}},
		LogReferences: []contracts.LogReferenceV2{},
	}
	if err := telemetry.Validate(); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(telemetry)
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
	if (SensorSample{}).MetricsV2().BatteryPercent != nil {
		t.Fatal("unconfigured source produced a metric")
	}
}

// Every reason the collector can emit is a telemetry v2 reason.
func TestSensorReasonsAreV2Reasons(t *testing.T) {
	for _, reason := range []string{ReasonSensorUnavailable, ReasonNotApplicable, ReasonPermissionDenied, ReasonCollectionError} {
		m := contracts.MetricV2{Unit: "percent", MissingReason: reason}
		tel := contracts.TelemetryV2{
			SchemaVersion: contracts.TelemetryV2Version, DeviceID: "fixture-device", CollectedAt: time.Unix(1, 0).UTC(),
			Source: "fixture", Metrics: contracts.MetricsV2{BatteryPercent: &m, CPUUtilization: &contracts.MetricV2{Value: f64(1), Unit: "percent"}},
			Inventory: contracts.InventoryV2{Components: []contracts.ComponentV2{}}, LogReferences: []contracts.LogReferenceV2{},
		}
		if err := tel.Validate(); err != nil {
			t.Fatalf("%s: %v", reason, err)
		}
	}
}

func TestSensorSourceSpecsUseCatalogCapabilities(t *testing.T) {
	for _, src := range SensorSourceSpecs() {
		if len(src.Required) != 1 {
			t.Fatalf("%s requires %v", src.Name, src.Required)
		}
		allowed := false
		for _, spec := range Catalog() {
			for _, cap := range spec.Required {
				if cap == src.Required[0] {
					allowed = true
				}
			}
		}
		if !allowed || unrestrictedCapability(src.Required[0]) {
			t.Fatalf("%s uses %s outside the planning catalog", src.Name, src.Required[0])
		}
		if err := PlanningToken().Allows(SourceSpec{Source: src.Name, Metric: "m", Unit: "u", Provider: "p", Required: src.Required}); err != nil {
			t.Fatalf("%s: %v", src.Name, err)
		}
	}
}

func TestPlatformSensorCollectorReturnsSample(t *testing.T) {
	sample, err := NewSensorCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(sample.Sources) != len(SensorSourceSpecs()) {
		t.Fatalf("sources = %d", len(sample.Sources))
	}
	for _, src := range sample.Sources {
		if src.Provenance != ProvenanceEndpointSensor || src.ObservedAt.IsZero() || len(src.Readings) == 0 {
			t.Fatalf("source = %+v", src)
		}
		for _, r := range src.Readings {
			if r.Provider == "" || r.Unit == "" || r.Metric == "" || r.Instance == "" {
				t.Fatalf("reading missing metadata: %+v", r)
			}
			if (r.Value == nil) == (r.MissingReason == "") {
				t.Fatalf("reading must have exactly one of value or reason: %+v", r)
			}
			if r.MissingReason != "" && !validMissingReason(r.MissingReason) {
				t.Fatalf("invalid reason: %+v", r)
			}
		}
	}
}
