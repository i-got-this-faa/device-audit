package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

const PredictionV2Version = "device-audit.prediction.v2"

// PredictionV2 is a proposed, separately versioned prediction contract.
type PredictionV2 struct {
	SchemaVersion string            `json:"schema_version"`
	DeviceID      string            `json:"device_id"`
	Model         *ModelReferenceV2 `json:"model_reference"`
	Evidence      *EvidenceV2       `json:"evidence"`
	GeneratedAt   time.Time         `json:"generated_at"`
	ExpiresAt     time.Time         `json:"expires_at"`
	Health        HealthV2          `json:"health"`
	Forecasts     []FaultForecastV2 `json:"forecasts"`
}

type ModelReferenceV2 struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type EvidenceV2 struct {
	Digest                 string `json:"digest"`
	TelemetrySchemaVersion string `json:"telemetry_schema_version"`
}

type HealthV2 struct {
	Status          string   `json:"status"`
	Probability     *float64 `json:"probability"`
	ProbabilityUnit string   `json:"probability_unit"`
	HorizonHours    *uint32  `json:"horizon_hours"`
	UnknownReason   string   `json:"unknown_reason,omitempty"`
}

type FaultForecastV2 struct {
	Category        string  `json:"category"`
	Probability     float64 `json:"probability"`
	ProbabilityUnit string  `json:"probability_unit"`
	HorizonHours    uint32  `json:"horizon_hours"`
}

func (p *PredictionV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "schema_version", "device_id", "model_reference", "evidence", "generated_at", "expires_at", "health", "forecasts"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"schema_version", "device_id", "model_reference", "evidence", "generated_at", "expires_at", "health", "forecasts"} {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("%s is required", name)
		}
	}
	if string(fields["evidence"]) == "null" || string(fields["health"]) == "null" || string(fields["forecasts"]) == "null" {
		return fmt.Errorf("evidence, health and forecasts cannot be null")
	}
	type predictionAlias PredictionV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded predictionAlias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*p = PredictionV2(decoded)
	return nil
}

func (m *ModelReferenceV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "version", "sha256"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["version"]; !ok {
		return fmt.Errorf("model version is required")
	}
	if _, ok := fields["sha256"]; !ok {
		return fmt.Errorf("model sha256 is required")
	}
	type alias ModelReferenceV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded alias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*m = ModelReferenceV2(decoded)
	return nil
}

func (e *EvidenceV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "digest", "telemetry_schema_version"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["digest"]; !ok {
		return fmt.Errorf("evidence digest is required")
	}
	if _, ok := fields["telemetry_schema_version"]; !ok {
		return fmt.Errorf("evidence telemetry schema version is required")
	}
	type alias EvidenceV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded alias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*e = EvidenceV2(decoded)
	return nil
}

func (h *HealthV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "status", "probability", "probability_unit", "horizon_hours", "unknown_reason"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"status", "probability", "probability_unit", "horizon_hours"} {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("health %s is required", name)
		}
	}
	if reason, ok := fields["unknown_reason"]; ok {
		var value string
		if err := json.Unmarshal(reason, &value); err != nil || value == "" {
			return fmt.Errorf("unknown_reason must be a non-empty string when present")
		}
	}
	type alias HealthV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded alias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*h = HealthV2(decoded)
	return nil
}

func (f *FaultForecastV2) UnmarshalJSON(data []byte) error {
	if err := requireJSONFieldNames(data, "category", "probability", "probability_unit", "horizon_hours"); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range []string{"category", "probability", "probability_unit", "horizon_hours"} {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("forecast %s is required", name)
		}
		if string(fields[name]) == "null" {
			return fmt.Errorf("forecast %s cannot be null", name)
		}
	}
	type alias FaultForecastV2
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded alias
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	*f = FaultForecastV2(decoded)
	return nil
}

func (p PredictionV2) Validate() error {
	if p.SchemaVersion != PredictionV2Version || !opaqueIDPattern.MatchString(p.DeviceID) || p.GeneratedAt.IsZero() || p.ExpiresAt.IsZero() || !p.ExpiresAt.After(p.GeneratedAt) {
		return fmt.Errorf("valid schema_version, device_id and increasing non-zero timestamps are required")
	}
	if p.Forecasts == nil || len(p.Forecasts) > 8 {
		return fmt.Errorf("forecasts are required and limited to 8")
	}
	if p.Evidence == nil || !sha256Pattern.MatchString(p.Evidence.Digest) || p.Evidence.TelemetrySchemaVersion != TelemetryV2Version {
		return fmt.Errorf("valid compatible evidence reference is required")
	}
	if p.Model != nil && (p.Model.Version == "" || utf8.RuneCountInString(p.Model.Version) > 128 || !sha256Pattern.MatchString(p.Model.SHA256)) {
		return fmt.Errorf("invalid model reference")
	}
	if p.Health.ProbabilityUnit != "probability" {
		return fmt.Errorf("probability_unit must be probability")
	}
	switch p.Health.Status {
	case "healthy", "degraded", "critical":
		if p.Health.Probability == nil || p.Health.HorizonHours == nil || *p.Health.HorizonHours == 0 || p.Health.UnknownReason != "" || p.Model == nil {
			return fmt.Errorf("known health requires risk, positive horizon and model; unknown_reason is forbidden")
		}
		if !validProbability(*p.Health.Probability) {
			return fmt.Errorf("health probability must be within 0..1")
		}
	case "unknown":
		if p.Health.Probability != nil || p.Health.HorizonHours != nil || p.Health.UnknownReason == "" {
			return fmt.Errorf("unknown health requires null risk and horizon and an unknown_reason")
		}
		if p.Health.UnknownReason == "model_unavailable" && p.Model != nil {
			return fmt.Errorf("model_unavailable requires a null model reference")
		}
		switch p.Health.UnknownReason {
		case "insufficient_evidence", "model_unavailable", "stale_evidence":
		default:
			return fmt.Errorf("invalid unknown_reason")
		}
		if len(p.Forecasts) != 0 {
			return fmt.Errorf("unknown health cannot include fault forecasts")
		}
	default:
		return fmt.Errorf("health status must be unknown, healthy, degraded or critical")
	}
	for _, forecast := range p.Forecasts {
		if !validFaultCategory(forecast.Category) || !validProbability(forecast.Probability) || forecast.ProbabilityUnit != "probability" || forecast.HorizonHours == 0 {
			return fmt.Errorf("invalid fault forecast")
		}
	}
	return nil
}

func validProbability(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}
func validFaultCategory(category string) bool {
	switch category {
	case "cpu", "gpu", "memory", "storage", "battery", "thermal", "network":
		return true
	}
	return false
}

// IsStale reports expiry at or before now. The caller supplies the clock for deterministic evaluation.
func (p PredictionV2) IsStale(now time.Time) bool { return !now.Before(p.ExpiresAt) }
