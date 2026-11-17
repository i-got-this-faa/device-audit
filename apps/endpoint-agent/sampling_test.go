package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

func TestLoadSamplingConfig(t *testing.T) {
	cfg, err := loadSamplingConfig("")
	if err != nil || len(cfg.Sources) == 0 {
		t.Fatalf("default = %+v %v", cfg, err)
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(good, []byte(`{"schema_version":"device-audit.sampling-config.v1","emit_interval":"30s","budget":{"max_cpu_percent_one_core":1,"max_rss_bytes":33554432},"sources":[{"source":"memory","interval":"10s","deadline":"2s"}]}`), 0o600)
	os.WriteFile(bad, []byte(`{"schema_version":"device-audit.sampling-config.v1","emit_interval":"30s","budget":{"max_cpu_percent_one_core":1,"max_rss_bytes":33554432},"sources":[{"source":"shell","interval":"10s","deadline":"2s"}]}`), 0o600)
	if cfg, err := loadSamplingConfig(good); err != nil || cfg.Sources[0].Source != telemetry.SensorMemory {
		t.Fatalf("good = %+v %v", cfg, err)
	}
	for _, path := range []string{bad, filepath.Join(dir, "missing.json")} {
		if _, err := loadSamplingConfig(path); err == nil {
			t.Fatalf("%s accepted", path)
		}
	}
}

func TestSamplingReportIsNotOverwritten(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	report := telemetry.SamplingReport{Schema: telemetry.SamplingReportSchema, Qualification: telemetry.SensorQualificationNone}
	if err := writeSamplingReport(path, report); err != nil {
		t.Fatal(err)
	}
	if err := writeSamplingReport(path, report); err == nil {
		t.Fatal("existing report overwritten")
	}
	if err := writeSamplingReport(filepath.Join(t.TempDir(), "x.json"), telemetry.SamplingReport{}); err == nil {
		t.Fatal("non-sampling report encoded")
	}
}

func TestRunSamplingRejectsDuration(t *testing.T) {
	s := telemetry.NewScheduler(telemetry.DefaultSamplingConfig())
	for _, d := range []time.Duration{0, 500 * time.Millisecond, 25 * time.Hour} {
		if _, err := runSampling(context.Background(), s, "device-1", d, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("duration %s accepted", d)
		}
	}
}

// On Windows: a short real schedule emits valid endpoint v2 payloads and a
// report whose sources were each read.
func TestRunSamplingRealWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("V1 selects only Windows endpoint providers")
	}
	cfg := telemetry.SamplingConfig{
		SchemaVersion: telemetry.SamplingConfigSchema,
		EmitInterval:  telemetry.Duration(5 * time.Second),
		Budget:        telemetry.SamplingBudget{MaxCPUPercentOneCore: 100, MaxRSSBytes: 1 << 30},
		Sources: []telemetry.SourceSchedule{
			{Source: telemetry.SensorCPU, Interval: telemetry.Duration(5 * time.Second), Deadline: telemetry.Duration(2 * time.Second)},
			{Source: telemetry.SensorMemory, Interval: telemetry.Duration(5 * time.Second), Deadline: telemetry.Duration(2 * time.Second)},
		},
	}
	var out, errOut bytes.Buffer
	report, err := runSampling(context.Background(), telemetry.NewScheduler(cfg), "device-1", 6*time.Second, &out, &errOut)
	if err != nil {
		t.Fatal(err)
	}
	lines := 0
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		var payload contracts.TelemetryV2
		if err := json.Unmarshal(scanner.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if err := payload.Validate(); err != nil || payload.Source != "endpoint" || payload.Metrics.CPUUtilization.Value == nil || payload.Metrics.MemoryPercent.Value == nil {
			t.Fatalf("payload = %s err=%v", scanner.Bytes(), err)
		}
		lines++
	}
	if lines != 1 || report.Emits != 1 || errOut.Len() != 0 {
		t.Fatalf("lines=%d emits=%d stderr=%q", lines, report.Emits, errOut.String())
	}
	for _, st := range report.Sources {
		if st.Reads < 2 || st.KnownReads < 2 || st.BusySkips != 0 {
			t.Fatalf("source stats = %+v", st)
		}
	}
	if report.Budget.RSSPeakBytes == 0 || report.Budget.WallMS < 5000 {
		t.Fatalf("budget = %+v", report.Budget)
	}
}
