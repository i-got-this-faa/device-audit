package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

func TestCommandWritesReportWithoutOverwriting(t *testing.T) {
	output := filepath.Join(t.TempDir(), "sensors.json")
	var stdout bytes.Buffer
	if err := run([]string{"-output", output, "-samples", "2", "-interval", "10ms", "-deadline", "2s"}, &stdout); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-output", output, "-samples", "1"}, &stdout); err == nil {
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
	if report["schema"] != "device-audit.sensor-availability.v1" || report["qualification"] != "not_service_token_or_physical_target_attested" {
		t.Fatalf("report identity = %v %v", report["schema"], report["qualification"])
	}
	if n := len(report["samples"].([]any)); n != 2 {
		t.Fatalf("samples = %d", n)
	}
	want := 0
	for _, src := range telemetry.SensorSourceSpecs() {
		want += len(src.Metrics)
	}
	availability := report["availability"].([]any)
	if len(availability) != want {
		t.Fatalf("availability = %d metrics, want %d", len(availability), want)
	}
	for _, field := range []string{"device_id", "hostname", "serial", "pid_", "luid"} {
		if strings.Contains(string(data), field) {
			t.Fatalf("report contains %q", field)
		}
	}
}

func TestCommandRejectsBadArguments(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{},
		{"-output", filepath.Join(dir, "missing", "x.json")},
		{"-output", filepath.Join(dir, "a.json"), "-samples", "0"},
		{"-output", filepath.Join(dir, "b.json"), "-samples", "31"},
		{"-output", filepath.Join(dir, "c.json"), "-deadline", "0s"},
		{"-output", filepath.Join(dir, "d.json"), "-deadline", "31s", "-samples", "1"},
		{"-output", filepath.Join(dir, "e.json"), "extra"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("%v accepted", args)
		}
	}
}
