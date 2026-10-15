package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestTelemetryV2JSONVectors(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("fixtures", "telemetry", "v2-vectors.json"))
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
		t.Fatal("no v2 telemetry vectors")
	}
	for _, vector := range collection.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader(vector.Telemetry))
			decoder.DisallowUnknownFields()
			var telemetry TelemetryV2
			err := decoder.Decode(&telemetry)
			if err == nil {
				err = telemetry.Validate()
			}
			if got := err == nil; got != vector.Valid {
				t.Fatalf("valid = %t, want %t (error: %v)", got, vector.Valid, err)
			}
		})
	}
}

func TestTelemetryV2RejectsReversedLogWindow(t *testing.T) {
	start, _ := time.Parse(time.RFC3339, "2026-10-13T06:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-10-13T05:00:00Z")
	value := 1.0
	telemetry := TelemetryV2{
		SchemaVersion: TelemetryV2Version, DeviceID: "node-1", CollectedAt: start, Source: "fixture",
		Metrics:   MetricsV2{MemoryPercent: &MetricV2{Value: &value, Unit: "percent"}},
		Inventory: InventoryV2{Components: []ComponentV2{}}, LogReferences: []LogReferenceV2{{
			ReferenceID: "log-1", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			ByteSize: 1, WindowStart: start, WindowEnd: end,
		}},
	}
	telemetry.LogReferences[0].WindowEnd = start
	if err := telemetry.Validate(); err != nil {
		t.Fatalf("valid log window rejected: %v", err)
	}
	telemetry.LogReferences[0].WindowEnd = end
	if err := telemetry.Validate(); err == nil {
		t.Fatal("Validate() accepted a reversed log time window")
	}
}

func TestMetricV2UnmarshalClearsReusedValue(t *testing.T) {
	value := 50.0
	metric := MetricV2{Value: &value, Unit: "percent"}
	if err := json.Unmarshal([]byte(`{"value":null,"unit":"percent","missing_reason":"sensor_unavailable"}`), &metric); err != nil {
		t.Fatal(err)
	}
	if metric.Value != nil {
		t.Fatalf("reused metric value = %v, want nil", *metric.Value)
	}
}
