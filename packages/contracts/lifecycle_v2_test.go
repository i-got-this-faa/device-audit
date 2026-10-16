package contracts

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type lifecycleVector struct {
	Name      string          `json:"name"`
	Valid     bool            `json:"valid"`
	Lifecycle json.RawMessage `json:"lifecycle"`
}

func lifecycleVectors(t *testing.T) []lifecycleVector {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("fixtures", "lifecycle", "v2-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		Vectors []lifecycleVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Vectors) == 0 {
		t.Fatal("no lifecycle vectors")
	}
	return collection.Vectors
}

func TestLifecycleV2JSONVectors(t *testing.T) {
	for _, vector := range lifecycleVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			var report LifecycleV2
			err := json.Unmarshal(vector.Lifecycle, &report)
			if err == nil {
				err = report.Validate()
			}
			if (err == nil) != vector.Valid {
				t.Fatalf("valid = %t, want %t (error: %v)", err == nil, vector.Valid, err)
			}
			if vector.Valid {
				encoded, err := json.Marshal(report)
				if err != nil {
					t.Fatal(err)
				}
				var decoded LifecycleV2
				if err := json.Unmarshal(encoded, &decoded); err != nil {
					t.Fatal(err)
				}
				if err := decoded.Validate(); err != nil {
					t.Fatalf("round trip lost contract state: %v", err)
				}
				var want, got interface{}
				if err := json.Unmarshal(vector.Lifecycle, &want); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(encoded, &got); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(want, got) {
					t.Fatalf("round trip changed explicit values/nullability: %s", encoded)
				}
			}
		})
	}
}

// JSON Schema cannot portably compare fields or calculate derived quantities.
func TestLifecycleV2SemanticValidation(t *testing.T) {
	complete := lifecycleVectors(t)[0].Lifecycle
	mutations := []struct {
		name   string
		mutate func(*LifecycleV2)
	}{
		{"reversed baseline", func(v *LifecycleV2) { v.Provenance.BaselineWindowEnd = v.Provenance.BaselineWindowStart }},
		{"overlapping windows", func(v *LifecycleV2) { v.Provenance.WindowStart = v.Provenance.BaselineWindowStart }},
		{"reversed current window", func(v *LifecycleV2) { v.Provenance.WindowEnd = v.Provenance.WindowStart }},
		{"future evidence", func(v *LifecycleV2) { v.GeneratedAt = v.Provenance.WindowEnd.Add(-time.Second) }},
		{"zero window", func(v *LifecycleV2) { v.Provenance.WindowStart = time.Time{} }},
		{"oversized batch", func(v *LifecycleV2) { v.Recommendations[0].AffectedDeviceCount = v.Provenance.CohortSize + 1 }},
		{"duplicate batch", func(v *LifecycleV2) { v.Recommendations = append(v.Recommendations, v.Recommendations[0]) }},
		{"reversed uncertainty", func(v *LifecycleV2) { *v.Recommendations[0].Longevity.LowerBoundMonths = 40 }},
		{"fabricated score", func(v *LifecycleV2) { *v.Recommendations[0].Sustainability.ScorePercent = 90 }},
		{"fabricated carbon", func(v *LifecycleV2) { *v.Recommendations[0].Sustainability.CarbonAvoidedKGCO2e = 90 }},
		{"fabricated waste", func(v *LifecycleV2) { *v.Recommendations[0].Sustainability.EWasteAvoidedKG = 90 }},
		{"fabricated trend", func(v *LifecycleV2) { *v.ComponentTrends[0].ChangePercentagePoints = 90 }},
		{"nonfinite input", func(v *LifecycleV2) { *v.Recommendations[0].Inputs.AgeMonths = math.Inf(1) }},
		{"nonfinite output", func(v *LifecycleV2) { *v.Recommendations[0].Longevity.RemainingMonths = math.NaN() }},
		{"unknown methodology", func(v *LifecycleV2) { v.Recommendations[0].Sustainability.MethodologyVersion = "unknown" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			var report LifecycleV2
			if err := json.Unmarshal(complete, &report); err != nil {
				t.Fatal(err)
			}
			mutation.mutate(&report)
			if err := report.Validate(); err == nil {
				t.Fatal("invalid report accepted")
			}
		})
	}
}

func TestLifecycleV2DecodeReplacesReusedValue(t *testing.T) {
	vectors := lifecycleVectors(t)
	var report LifecycleV2
	if err := json.Unmarshal(vectors[0].Lifecycle, &report); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(vectors[1].Lifecycle, &report); err != nil {
		t.Fatal(err)
	}
	if report.Recommendations[0].Inputs.AgeMonths != nil || report.Recommendations[0].Sustainability.ScorePercent != nil || report.Provenance.EvidenceDigest != nil {
		t.Fatal("reused report retained stale evidence or complete outputs")
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
}
