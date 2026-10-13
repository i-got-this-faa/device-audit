// Package contracts owns the initial v1 application wire types.
package contracts

import (
	"fmt"
	"math"
	"regexp"
	"time"
)

const Version = "device-audit.v1"

var deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Metrics use pointers so an unavailable sensor is not represented as zero.
type Metrics struct {
	CPUPercent       *float64 `json:"cpu_percent,omitempty"`
	MemoryPercent    *float64 `json:"memory_percent,omitempty"`
	DiskUsedPercent  *float64 `json:"disk_used_percent,omitempty"`
	BatteryPercent   *float64 `json:"battery_percent,omitempty"`
	TemperatureC     *float64 `json:"temperature_c,omitempty"`
	NetworkLatencyMS *float64 `json:"network_latency_ms,omitempty"`
}

type Telemetry struct {
	SchemaVersion string    `json:"schema_version"`
	DeviceID      string    `json:"device_id"`
	CollectedAt   time.Time `json:"collected_at"`
	Source        string    `json:"source"` // fixture or endpoint; provenance is not attestation
	Metrics       Metrics   `json:"metrics"`
}

func (t Telemetry) Validate() error {
	if t.SchemaVersion != Version || !deviceIDPattern.MatchString(t.DeviceID) || t.CollectedAt.IsZero() {
		return fmt.Errorf("valid schema_version, device_id and collected_at are required")
	}
	if t.Source != "fixture" && t.Source != "endpoint" {
		return fmt.Errorf("source must be fixture or endpoint")
	}
	count := 0
	for name, value := range map[string]*float64{
		"cpu_percent": t.Metrics.CPUPercent, "memory_percent": t.Metrics.MemoryPercent,
		"disk_used_percent": t.Metrics.DiskUsedPercent, "battery_percent": t.Metrics.BatteryPercent,
		"temperature_c": t.Metrics.TemperatureC, "network_latency_ms": t.Metrics.NetworkLatencyMS,
	} {
		if value == nil {
			continue
		}
		count++
		if math.IsNaN(*value) || math.IsInf(*value, 0) {
			return fmt.Errorf("%s must be finite", name)
		}
		if name != "temperature_c" && (*value < 0 || (name != "network_latency_ms" && *value > 100)) {
			return fmt.Errorf("%s is outside its allowed range", name)
		}
	}
	if count == 0 {
		return fmt.Errorf("at least one metric is required")
	}
	return nil
}

type Prediction struct {
	DeviceID       string   `json:"device_id"`
	ModelVersion   string   `json:"model_version"`
	Health         string   `json:"health"` // unknown until a validated model is available
	FailureRisk    *float64 `json:"failure_risk,omitempty"`
	HorizonHours   *int     `json:"horizon_hours,omitempty"`
	EvidenceDigest string   `json:"evidence_digest"`
}

type ModelUpdate struct {
	RoundID          string    `json:"round_id"`
	DeviceID         string    `json:"device_id"`
	BaseModelVersion string    `json:"base_model_version"`
	SampleCount      int       `json:"sample_count"`
	ArtifactDigest   string    `json:"artifact_digest"`
	CreatedAt        time.Time `json:"created_at"`
}

type DiagnosticTask struct {
	TaskID         string    `json:"task_id"`
	DeviceID       string    `json:"device_id"`
	Workflow       string    `json:"workflow"`
	EvidenceDigest string    `json:"evidence_digest"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type Recommendation struct {
	Action string `json:"action"` // repair, upgrade, replace, retain, or insufficient_evidence
	Reason string `json:"reason"`
}

type AuditReport struct {
	DeviceID        string           `json:"device_id"`
	GeneratedAt     time.Time        `json:"generated_at"`
	Prediction      Prediction       `json:"prediction"`
	Recommendations []Recommendation `json:"recommendations"`
	Sustainability  *Sustainability  `json:"sustainability,omitempty"`
	EvidenceDigest  string           `json:"evidence_digest"`
}

type Sustainability struct {
	MethodologyVersion string   `json:"methodology_version"`
	CarbonKGCO2e       *float64 `json:"carbon_kg_co2e,omitempty"`
	EWasteKG           *float64 `json:"e_waste_kg,omitempty"`
	RemainingMonths    *float64 `json:"remaining_months,omitempty"`
}
