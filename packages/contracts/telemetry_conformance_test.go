package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type telemetryVector struct {
	Name      string          `json:"name"`
	Valid     bool            `json:"valid"`
	Telemetry json.RawMessage `json:"telemetry"`
}

func TestTelemetryJSONVectors(t *testing.T) {
	path := filepath.Join("fixtures", "telemetry", "vectors.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		Vectors []telemetryVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Vectors) == 0 {
		t.Fatal("no telemetry vectors")
	}
	for _, vector := range collection.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(vector.Telemetry))
			decoder.DisallowUnknownFields()
			var telemetry Telemetry
			err := decoder.Decode(&telemetry)
			if err == nil {
				err = telemetry.Validate()
			}
			if gotValid := err == nil; gotValid != vector.Valid {
				t.Fatalf("valid = %t, want %t (error: %v)", gotValid, vector.Valid, err)
			}
		})
	}
}

func TestTelemetryRejectsZeroTimeInstant(t *testing.T) {
	for _, collectedAt := range []string{
		"0001-01-01T00:00:00Z",
		"0001-01-01T01:00:00+01:00",
	} {
		t.Run(collectedAt, func(t *testing.T) {
			data := []byte(`{"schema_version":"device-audit.v1","device_id":"node-zero-time","collected_at":"` + collectedAt + `","source":"fixture","metrics":{"cpu_percent":1}}`)
			var telemetry Telemetry
			if err := json.Unmarshal(data, &telemetry); err != nil {
				t.Fatal(err)
			}
			if err := telemetry.Validate(); err == nil {
				t.Fatal("Validate() accepted the zero time instant")
			}
		})
	}
}
