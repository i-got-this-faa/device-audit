package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCommandWritesHarnessReportWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "budget.json")
	var stdout bytes.Buffer
	err := run([]string{
		"-output", output,
		"-interval", "20ms",
		"-samples", "2",
		"-repeats", "1",
		"-baseline", "10ms",
		"-deadline", "1s",
		"-iterations", "1000",
		"-token", "planned",
		"-allow-non-candidate",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-output", output, "-interval", "15s", "-samples", "1", "-baseline", "0"}, &stdout); err == nil {
		t.Fatal("existing output was overwritten")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report["schema"] != "device-audit.collector-budget.harness.v1" || report["candidate_cadence"] != false {
		t.Fatalf("report identity = %#v", report)
	}
	if report["service_access_qualified"] != false {
		t.Fatal("service access was qualified")
	}
	recommendation := report["recommendation"].(map[string]any)
	if recommendation["production_budget_approved"] != false || recommendation["status"] != "not_approved" {
		t.Fatalf("recommendation = %#v", recommendation)
	}
	windows := report["windows"].([]any)
	probe := windows[1].(map[string]any)
	samples := probe["rss_samples_bytes"].([]any)
	var peak float64
	var sum float64
	for _, sample := range samples {
		value := sample.(float64)
		sum += value
		if value > peak {
			peak = value
		}
	}
	if probe["rss_peak_bytes"].(float64) != peak || (len(samples) > 1 && peak == sum) {
		t.Fatalf("rss peak=%v max=%v sum=%v", probe["rss_peak_bytes"], peak, sum)
	}
	sweeps := probe["sweeps"].([]any)
	sources := sweeps[0].(map[string]any)["sources"].([]any)
	if len(sources) != 8 {
		t.Fatalf("sources = %d", len(sources))
	}
	for _, source := range sources {
		item := source.(map[string]any)
		if item["outcome"] != "success" || item["metric"] != "synthetic_work" || item["provenance"] != "harness_synthetic" {
			t.Fatalf("source = %#v", item)
		}
	}
	access := report["access"].([]any)
	for _, row := range access {
		item := row.(map[string]any)
		if item["denied_profile"] != "permission_denied" || item["extra_grant_selected"] != false {
			t.Fatalf("access = %#v", item)
		}
	}
}

func TestDeniedTokenSkipsSources(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "denied.json")
	err := run([]string{
		"-output", output,
		"-interval", "15s",
		"-samples", "1",
		"-repeats", "1",
		"-baseline", "0",
		"-token", "denied",
	}, ioDiscard())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Windows []struct {
			Kind   string
			Sweeps []struct {
				Sources []struct {
					Outcome string
					Invoked bool
					Value   *float64
				}
			}
		}
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	sources := report.Windows[1].Sweeps[0].Sources
	if len(sources) != 8 {
		t.Fatalf("sources = %d", len(sources))
	}
	for _, source := range sources {
		if source.Outcome != "permission_denied" || source.Invoked || source.Value != nil {
			t.Fatalf("source = %#v", source)
		}
	}
}

func TestCandidateIntervalIsRequired(t *testing.T) {
	dir := t.TempDir()
	err := run([]string{"-output", filepath.Join(dir, "short.json"), "-interval", "20ms", "-samples", "1"}, ioDiscard())
	if err == nil {
		t.Fatal("non-candidate interval was accepted")
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func ioDiscard() discard { return discard{} }
