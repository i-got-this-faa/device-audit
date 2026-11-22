package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// validTelemetryLines returns every valid shared telemetry v2 vector, one compact payload per line.
func validTelemetryLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("../../packages/contracts/fixtures/telemetry/v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Valid     bool            `json:"valid"`
			Telemetry json.RawMessage `json:"telemetry"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, v := range file.Vectors {
		if !v.Valid {
			continue
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, v.Telemetry); err != nil {
			t.Fatal(err)
		}
		lines = append(lines, compact.String())
	}
	if len(lines) == 0 {
		t.Fatal("no valid telemetry")
	}
	return lines
}

func TestFeaturesModeReportsAnIncompleteVectorForTelemetry(t *testing.T) {
	var out bytes.Buffer
	if err := runFeatures("2026-11-17T16:00:00Z", strings.NewReader(strings.Join(validTelemetryLines(t), "\n")+"\n"), &out); err != nil {
		t.Fatal(err)
	}
	var vector contracts.FeatureVectorV1
	if err := json.Unmarshal(out.Bytes(), &vector); err != nil {
		t.Fatal(err)
	}
	if err := vector.Validate(); err != nil {
		t.Fatal(err)
	}
	if vector.Status != contracts.FeatureStatusIncomplete || vector.WindowEnd != "2026-11-17" {
		t.Fatalf("unexpected vector: %+v", vector)
	}
	for _, f := range vector.Features {
		if f.Value != nil || f.MissingReason != contracts.FeatureMissingNoObservation {
			t.Fatalf("%s should be no_observation: %+v", f.Name, f)
		}
	}
}

func TestFeaturesModeRefusesBadInput(t *testing.T) {
	good := validTelemetryLines(t)[0]
	for name, tc := range map[string]struct{ asOf, input string }{
		"empty as-of":          {"", good},
		"as-of without a zone": {"2026-11-17T16:00:00", good},
		"not json":             {"2026-11-17T16:00:00Z", "{"},
		"unknown field":        {"2026-11-17T16:00:00Z", strings.Replace(good, `"device_id"`, `"smart_5_raw":1,"device_id"`, 1)},
		"invalid telemetry":    {"2026-11-17T16:00:00Z", strings.Replace(good, `"schema_version":"device-audit.telemetry.v2"`, `"schema_version":"device-audit.telemetry.v1"`, 1)},
		"oversized line":       {"2026-11-17T16:00:00Z", strings.Repeat("x", contracts.MaxEvidencePayloadBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if err := runFeatures(tc.asOf, strings.NewReader(tc.input+"\n"), &out); err == nil {
				t.Fatalf("accepted input, wrote %q", out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("wrote a vector for rejected input: %q", out.String())
			}
		})
	}
}
