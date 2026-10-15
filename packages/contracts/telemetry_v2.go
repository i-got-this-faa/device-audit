package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"
	"unicode/utf8"
)

const TelemetryV2Version = "device-audit.telemetry.v2"

var opaqueIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

// MetricV2 keeps units on the wire so consumers cannot infer them from names.
type MetricV2 struct {
	Value         *float64 `json:"value"`
	Unit          string   `json:"unit"`
	MissingReason string   `json:"missing_reason,omitempty"`
}

func (m *MetricV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "value", "unit", "missing_reason"); err != nil {
		return err
	}
	var wire struct {
		Value         json.RawMessage `json:"value"`
		Unit          string          `json:"unit"`
		MissingReason string          `json:"missing_reason"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if wire.Value == nil {
		return fmt.Errorf("metric value is required")
	}
	if reason, ok := fields["missing_reason"]; ok {
		if string(reason) == "null" {
			return fmt.Errorf("missing_reason cannot be null")
		}
		if string(wire.Value) != "null" {
			return fmt.Errorf("known metric cannot include missing_reason")
		}
	}
	m.Unit, m.MissingReason = wire.Unit, wire.MissingReason
	m.Value = nil
	if string(wire.Value) != "null" {
		var value float64
		if err := json.Unmarshal(wire.Value, &value); err != nil {
			return err
		}
		m.Value = &value
	}
	return nil
}

func (m *MetricsV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "cpu_utilization", "gpu_utilization", "memory_percent", "disk_used_percent", "battery_percent", "temperature_c", "network_latency_ms"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"cpu_utilization", "gpu_utilization", "memory_percent", "disk_used_percent", "battery_percent", "temperature_c", "network_latency_ms"} {
		if value, ok := fields[name]; ok && string(value) == "null" {
			return fmt.Errorf("%s must be a metric object", name)
		}
	}
	type metricsAlias MetricsV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded metricsAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*m = MetricsV2(decoded)
	return nil
}

type MetricsV2 struct {
	CPUUtilization   *MetricV2 `json:"cpu_utilization,omitempty"`
	GPUUtilization   *MetricV2 `json:"gpu_utilization,omitempty"`
	MemoryPercent    *MetricV2 `json:"memory_percent,omitempty"`
	DiskUsedPercent  *MetricV2 `json:"disk_used_percent,omitempty"`
	BatteryPercent   *MetricV2 `json:"battery_percent,omitempty"`
	TemperatureC     *MetricV2 `json:"temperature_c,omitempty"`
	NetworkLatencyMS *MetricV2 `json:"network_latency_ms,omitempty"`
}

type ComponentV2 struct {
	ID    string `json:"id"`
	Type  string `json:"type"`
	Model string `json:"model,omitempty"`
}

func (c *ComponentV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "id", "type", "model"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if model, ok := fields["model"]; ok && string(model) == "null" {
		return fmt.Errorf("component model cannot be null")
	}
	type componentAlias ComponentV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded componentAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*c = ComponentV2(decoded)
	return nil
}

type InventoryV2 struct {
	GroupID          string        `json:"group_id,omitempty"`
	NetworkSegmentID string        `json:"network_segment_id,omitempty"`
	Components       []ComponentV2 `json:"components"`
}

func (i *InventoryV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "group_id", "network_segment_id", "components"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"group_id", "network_segment_id"} {
		if value, ok := fields[name]; ok {
			var id string
			if string(value) == "null" || json.Unmarshal(value, &id) != nil || id == "" {
				return fmt.Errorf("%s must be a non-empty ID when present", name)
			}
		}
	}
	type inventoryAlias InventoryV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded inventoryAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*i = InventoryV2(decoded)
	return nil
}

type LogReferenceV2 struct {
	ReferenceID string    `json:"reference_id"`
	SHA256      string    `json:"sha256"`
	ByteSize    int64     `json:"byte_size"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

func (r *LogReferenceV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "reference_id", "sha256", "byte_size", "window_start", "window_end"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"reference_id", "sha256", "byte_size", "window_start", "window_end"} {
		value, ok := fields[name]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("log reference %s is required and cannot be null", name)
		}
	}
	type logReferenceAlias LogReferenceV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded logReferenceAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*r = LogReferenceV2(decoded)
	return nil
}

type TelemetryV2 struct {
	SchemaVersion string           `json:"schema_version"`
	DeviceID      string           `json:"device_id"`
	CollectedAt   time.Time        `json:"collected_at"`
	Source        string           `json:"source"`
	Metrics       MetricsV2        `json:"metrics"`
	Inventory     InventoryV2      `json:"inventory"`
	LogReferences []LogReferenceV2 `json:"log_references"`
}

func (t *TelemetryV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "schema_version", "device_id", "collected_at", "source", "metrics", "inventory", "log_references"); err != nil {
		return err
	}
	type telemetryAlias TelemetryV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded telemetryAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*t = TelemetryV2(decoded)
	return nil
}

func (t TelemetryV2) Validate() error {
	if t.SchemaVersion != TelemetryV2Version || !opaqueIDPattern.MatchString(t.DeviceID) || t.CollectedAt.IsZero() {
		return fmt.Errorf("valid v2 schema_version, device_id and collected_at are required")
	}
	if t.Source != "fixture" && t.Source != "endpoint" {
		return fmt.Errorf("source must be fixture or endpoint")
	}
	if t.Inventory.Components == nil || t.LogReferences == nil {
		return fmt.Errorf("components and log_references are required")
	}
	if len(t.Inventory.Components) > 64 || len(t.LogReferences) > 8 {
		return fmt.Errorf("inventory or log reference collection exceeds its bound")
	}
	for _, id := range []string{t.Inventory.GroupID, t.Inventory.NetworkSegmentID} {
		if id != "" && !opaqueIDPattern.MatchString(id) {
			return fmt.Errorf("invalid inventory metadata ID")
		}
	}
	for _, c := range t.Inventory.Components {
		if !opaqueIDPattern.MatchString(c.ID) || c.Type == "" || utf8.RuneCountInString(c.Type) > 64 || utf8.RuneCountInString(c.Model) > 128 {
			return fmt.Errorf("invalid component metadata")
		}
	}
	known := 0
	for _, item := range []struct {
		name, unit string
		metric     *MetricV2
		percent    bool
	}{
		{"cpu_utilization", "percent", t.Metrics.CPUUtilization, true}, {"gpu_utilization", "percent", t.Metrics.GPUUtilization, true},
		{"memory_percent", "percent", t.Metrics.MemoryPercent, true}, {"disk_used_percent", "percent", t.Metrics.DiskUsedPercent, true},
		{"battery_percent", "percent", t.Metrics.BatteryPercent, true}, {"temperature_c", "celsius", t.Metrics.TemperatureC, false},
		{"network_latency_ms", "milliseconds", t.Metrics.NetworkLatencyMS, false},
	} {
		if item.metric == nil {
			continue
		}
		m := item.metric
		if m.Unit != item.unit {
			return fmt.Errorf("%s unit must be %s", item.name, item.unit)
		}
		if m.Value == nil {
			if !missingReasonV2(m.MissingReason) {
				return fmt.Errorf("%s null value requires a missing_reason", item.name)
			}
			continue
		}
		known++
		if m.MissingReason != "" {
			return fmt.Errorf("%s known value cannot have missing_reason", item.name)
		}
		v := *m.Value
		if math.IsNaN(v) || math.IsInf(v, 0) || ((item.percent || item.name == "network_latency_ms") && v < 0) || (item.percent && v > 100) {
			return fmt.Errorf("%s is outside its allowed range", item.name)
		}
	}
	if known == 0 {
		return fmt.Errorf("at least one known metric is required")
	}
	for _, ref := range t.LogReferences {
		if !opaqueIDPattern.MatchString(ref.ReferenceID) || !sha256Pattern.MatchString(ref.SHA256) || ref.ByteSize < 0 || ref.ByteSize > 10485760 || ref.WindowStart.IsZero() || ref.WindowEnd.Before(ref.WindowStart) {
			return fmt.Errorf("invalid bounded log reference")
		}
	}
	return nil
}

func missingReasonV2(reason string) bool {
	switch reason {
	case "sensor_unavailable", "not_applicable", "permission_denied", "collection_error":
		return true
	}
	return false
}

func requireJSONFieldNames(data []byte, allowed ...string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for name := range fields {
		found := false
		for _, candidate := range allowed {
			if name == candidate {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown JSON field %q", name)
		}
	}
	return nil
}
