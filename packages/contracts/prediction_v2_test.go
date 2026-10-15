package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type predictionVector struct {
	Name       string          `json:"name"`
	Valid      bool            `json:"valid"`
	Prediction json.RawMessage `json:"prediction"`
}

func TestPredictionV2JSONVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("fixtures", "prediction", "v2-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		Vectors []predictionVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Vectors) == 0 {
		t.Fatal("no prediction vectors")
	}
	for _, vector := range collection.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(vector.Prediction))
			decoder.DisallowUnknownFields()
			var prediction PredictionV2
			err := decoder.Decode(&prediction)
			if err == nil {
				err = prediction.Validate()
			}
			if (err == nil) != vector.Valid {
				t.Fatalf("valid = %t, want %t (error: %v)", err == nil, vector.Valid, err)
			}
		})
	}
}

func TestPredictionV2StalenessExpiryBoundary(t *testing.T) {
	prediction := PredictionV2{ExpiresAt: time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC)}
	if prediction.IsStale(prediction.ExpiresAt.Add(-time.Nanosecond)) {
		t.Fatal("prediction stale before expiry")
	}
	if !prediction.IsStale(prediction.ExpiresAt) {
		t.Fatal("prediction not stale at expiry")
	}
	if !prediction.IsStale(prediction.ExpiresAt.Add(time.Nanosecond)) {
		t.Fatal("prediction not stale after expiry")
	}
}

func TestPredictionV2RejectsZeroOrReversedTimes(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("fixtures", "prediction", "v2-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		Vectors []predictionVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	var prediction PredictionV2
	for _, vector := range collection.Vectors {
		if vector.Name == "known risk is numeric zero" {
			if err := json.Unmarshal(vector.Prediction, &prediction); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if err := prediction.Validate(); err != nil {
		t.Fatal(err)
	}
	prediction.ExpiresAt = prediction.GeneratedAt
	if err := prediction.Validate(); err == nil {
		t.Fatal("equal timestamps accepted")
	}
	prediction.ExpiresAt = prediction.GeneratedAt.Add(-time.Second)
	if err := prediction.Validate(); err == nil {
		t.Fatal("reversed timestamps accepted")
	}
	prediction.ExpiresAt = time.Time{}
	if err := prediction.Validate(); err == nil {
		t.Fatal("zero expiry accepted")
	}
}

func TestPredictionV2DecodeReplacesReusedValue(t *testing.T) {
	unknown := `{"schema_version":"device-audit.prediction.v2","device_id":"asset:opaque-01","model_reference":null,"evidence":{"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","telemetry_schema_version":"device-audit.telemetry.v2"},"generated_at":"2026-10-13T06:00:00Z","expires_at":"2026-10-14T06:00:00Z","health":{"status":"unknown","probability":null,"probability_unit":"probability","horizon_hours":null,"unknown_reason":"insufficient_evidence"},"forecasts":[]}`
	known := `{"schema_version":"device-audit.prediction.v2","device_id":"asset:opaque-01","model_reference":{"version":"model-1","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"evidence":{"digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","telemetry_schema_version":"device-audit.telemetry.v2"},"generated_at":"2026-10-13T06:00:00Z","expires_at":"2026-10-14T06:00:00Z","health":{"status":"healthy","probability":0,"probability_unit":"probability","horizon_hours":24},"forecasts":[]}`
	var prediction PredictionV2
	if err := json.Unmarshal([]byte(unknown), &prediction); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(known), &prediction); err != nil {
		t.Fatal(err)
	}
	if prediction.Health.UnknownReason != "" || prediction.Health.Probability == nil || *prediction.Health.Probability != 0 || prediction.Model == nil {
		t.Fatalf("reused value retained stale or lost current fields: %+v", prediction)
	}
	if err := prediction.Validate(); err != nil {
		t.Fatalf("decoded known prediction invalid: %v", err)
	}
}

func TestPredictionV2ProgrammaticConstructionAndUnknownSerialization(t *testing.T) {
	probability := 0.0
	horizon := uint32(24)
	prediction := PredictionV2{
		SchemaVersion: PredictionV2Version,
		DeviceID:      "asset:opaque-01",
		Model:         &ModelReferenceV2{Version: "model-1", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		Evidence:      &EvidenceV2{Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", TelemetrySchemaVersion: TelemetryV2Version},
		GeneratedAt:   time.Date(2026, 10, 13, 6, 0, 0, 0, time.UTC),
		ExpiresAt:     time.Date(2026, 10, 14, 6, 0, 0, 0, time.UTC),
		Health:        HealthV2{Status: "healthy", Probability: &probability, ProbabilityUnit: "probability", HorizonHours: &horizon},
		Forecasts:     []FaultForecastV2{},
	}
	if err := prediction.Validate(); err != nil {
		t.Fatalf("programmatically constructed prediction invalid: %v", err)
	}

	unknown := PredictionV2{
		SchemaVersion: PredictionV2Version,
		DeviceID:      "asset:opaque-01",
		Evidence:      prediction.Evidence,
		GeneratedAt:   prediction.GeneratedAt,
		ExpiresAt:     prediction.ExpiresAt,
		Health:        HealthV2{Status: "unknown", ProbabilityUnit: "probability", UnknownReason: "insufficient_evidence"},
		Forecasts:     []FaultForecastV2{},
	}
	encoded, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &shape); err != nil {
		t.Fatal(err)
	}
	var health map[string]json.RawMessage
	if err := json.Unmarshal(shape["health"], &health); err != nil {
		t.Fatal(err)
	}
	if string(shape["model_reference"]) != "null" || string(health["probability"]) != "null" || string(health["horizon_hours"]) != "null" || string(health["unknown_reason"]) != `"insufficient_evidence"` {
		t.Fatalf("unexpected unknown serialization shape: %s", encoded)
	}
}
