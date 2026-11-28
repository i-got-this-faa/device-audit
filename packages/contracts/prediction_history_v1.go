package contracts

import (
	"fmt"
	"time"
)

const (
	PredictionHistoryV1Version = "device-audit.prediction-history.v1"
	PredictionLatestV1Version  = "device-audit.prediction-latest.v1"
	// PredictionHistoryPageMaxV1 bounds one prediction history page; larger requests are rejected.
	PredictionHistoryPageMaxV1     = 100
	PredictionHistoryPageDefaultV1 = 50
	// PredictionHistoryWindowMaxV1 bounds the queried time window.
	PredictionHistoryWindowMaxV1 = 31 * 24 * time.Hour
)

// PredictionModelProvenanceV1 records the evaluated controller model, policy,
// and ML05 evaluation report digest behind a persisted health assessment.
type PredictionModelProvenanceV1 struct {
	Version          string `json:"version"`
	SHA256           string `json:"sha256"`
	PolicyVersion    string `json:"policy_version"`
	PolicySHA256     string `json:"policy_sha256"`
	EvaluationSHA256 string `json:"evaluation_sha256"`
}

// PredictionEvidenceRefV1 identifies the exact persisted telemetry sample on
// which a prediction/health assessment rests.
type PredictionEvidenceRefV1 struct {
	Sequence               uint64    `json:"sequence"`
	CollectedAt            time.Time `json:"collected_at"`
	ReceivedAt             time.Time `json:"received_at"`
	PayloadSHA256          string    `json:"payload_sha256"`
	RequestSHA256          string    `json:"request_sha256"`
	Source                 string    `json:"source"`
	TelemetrySchemaVersion string    `json:"telemetry_schema_version"`
}

// PredictionFeatureRefV1 identifies the CT03 feature window and completeness
// observed up to AsOf.
type PredictionFeatureRefV1 struct {
	FeatureVersion string `json:"feature_version"`
	WindowStart    string `json:"window_start"`
	WindowEnd      string `json:"window_end"`
	Status         string `json:"status"`
	FeatureCount   int    `json:"feature_count"`
	SamplesRead    int    `json:"samples_read"`
	LastSequence   uint64 `json:"last_sequence"`
}

// PredictionFaultWindowRefV1 describes one bounded ML10 fault-history window.
type PredictionFaultWindowRefV1 struct {
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	Days        int       `json:"days"`
	SampledDays int       `json:"sampled_days"`
	Sufficient  bool      `json:"sufficient"`
}

// PredictionFaultBaselineRefV1 captures the ML10 current/baseline fault
// comparison provenance without turning missing days into healthy history.
type PredictionFaultBaselineRefV1 struct {
	Current                  PredictionFaultWindowRefV1 `json:"current"`
	Baseline                 PredictionFaultWindowRefV1 `json:"baseline"`
	ObservationNote          string                     `json:"observation_note"`
	TotalTypes               int                        `json:"total_types"`
	RecurrentTypes           int                        `json:"recurrent_types"`
	IsolatedTypes            int                        `json:"isolated_types"`
	BaselineOnlyTypes        int                        `json:"baseline_only_types"`
	InsufficientHistoryTypes int                        `json:"insufficient_history_types"`
	CurrentReports           int                        `json:"current_reports"`
	BaselineReports          int                        `json:"baseline_reports"`
	DuplicateReports         int                        `json:"duplicate_reports"`
	SamplesRead              int                        `json:"samples_read"`
	LastSequence             uint64                     `json:"last_sequence"`
}

// PredictionHistoryRecordV1 is one durable prediction/health assessment with its
// model, feature, horizon, evidence, and historical-baseline references.
// Prediction and Evidence are null when no telemetry existed at or before AsOf.
type PredictionHistoryRecordV1 struct {
	ID              uint64                       `json:"id"`
	AsOf            time.Time                    `json:"as_of"`
	RecordedAt      time.Time                    `json:"recorded_at"`
	ExpiresAt       *time.Time                   `json:"expires_at"`
	Stale           bool                         `json:"stale"`
	RulesVersion    string                       `json:"rules_version"`
	RuleReason      string                       `json:"rule_reason"`
	ModelStatus     string                       `json:"model_status"`
	ModelError      string                       `json:"model_error,omitempty"`
	ModelProvenance *PredictionModelProvenanceV1 `json:"model_provenance"`
	Evidence        *PredictionEvidenceRefV1     `json:"evidence"`
	Features        PredictionFeatureRefV1       `json:"features"`
	FaultBaseline   PredictionFaultBaselineRefV1 `json:"fault_baseline"`
	Health          HealthV2                     `json:"health"`
	Prediction      *PredictionV2                `json:"prediction"`
}

// PredictionHistoryV1 is one page of a device's durable prediction/health
// assessments with from <= as_of < to, ordered by (as_of, id). NextAfter is an
// opaque cursor, or null on the last page.
type PredictionHistoryV1 struct {
	SchemaVersion string                      `json:"schema_version"`
	DeploymentID  string                      `json:"deployment_id"`
	DeviceID      string                      `json:"device_id"`
	From          time.Time                   `json:"from"`
	To            time.Time                   `json:"to"`
	Records       []PredictionHistoryRecordV1 `json:"records"`
	NextAfter     *string                     `json:"next_after"`
}

// LatestPredictionV1 returns the newest persisted prediction/health record for
// one device alongside CurrentHealth, which fails closed to unknown
// (stale_evidence) with null probability and horizon once ExpiresAt passes.
type LatestPredictionV1 struct {
	SchemaVersion string                    `json:"schema_version"`
	DeploymentID  string                    `json:"deployment_id"`
	DeviceID      string                    `json:"device_id"`
	EvaluatedAt   time.Time                 `json:"evaluated_at"`
	Stale         bool                      `json:"stale"`
	CurrentHealth HealthV2                  `json:"current_health"`
	Record        PredictionHistoryRecordV1 `json:"record"`
}

// Validate checks internal consistency between a record's health state, model
// provenance, evidence reference, and embedded PredictionV2 payload.
func (r PredictionHistoryRecordV1) Validate(deviceID string) error {
	if r.ID == 0 || r.AsOf.IsZero() || r.RecordedAt.IsZero() || !opaqueIDPattern.MatchString(r.RulesVersion) || r.RuleReason == "" {
		return fmt.Errorf("invalid prediction history record metadata")
	}
	switch r.ModelStatus {
	case "ready", "unavailable", "unknown", "healthy", "degraded", "critical":
	default:
		return fmt.Errorf("invalid prediction model status")
	}
	if r.Health.ProbabilityUnit != "probability" {
		return fmt.Errorf("invalid prediction health probability unit")
	}
	switch r.Health.Status {
	case "healthy", "degraded", "critical":
		if r.Health.Probability == nil || r.Health.HorizonHours == nil || *r.Health.HorizonHours == 0 || r.Health.UnknownReason != "" ||
			!validProbability(*r.Health.Probability) || r.ModelProvenance == nil || r.Evidence == nil || r.Prediction == nil ||
			r.Features.Status != FeatureStatusComplete {
			return fmt.Errorf("known prediction record requires risk, horizon, complete features, model, evidence and prediction")
		}
	case "unknown":
		if r.Health.Probability != nil || r.Health.HorizonHours != nil || r.Health.UnknownReason == "" {
			return fmt.Errorf("unknown prediction record must keep null probability and horizon with reason")
		}
		if r.Health.UnknownReason == "model_unavailable" && r.ModelProvenance != nil {
			return fmt.Errorf("model_unavailable record requires null model provenance")
		}
	default:
		return fmt.Errorf("invalid prediction health status")
	}
	if r.ModelProvenance != nil {
		m := r.ModelProvenance
		if !opaqueIDPattern.MatchString(m.Version) || !sha256Pattern.MatchString(m.SHA256) ||
			!opaqueIDPattern.MatchString(m.PolicyVersion) || !sha256Pattern.MatchString(m.PolicySHA256) || !sha256Pattern.MatchString(m.EvaluationSHA256) {
			return fmt.Errorf("invalid model provenance")
		}
	}
	if r.Evidence == nil {
		if r.ExpiresAt != nil || r.Prediction != nil || r.Health.Status != "unknown" ||
			(r.Health.UnknownReason != "insufficient_evidence" && r.Health.UnknownReason != "model_unavailable") {
			return fmt.Errorf("record without evidence cannot carry a prediction, expiry, or stale_evidence")
		}
		return nil
	}
	if r.Evidence.Sequence < FirstEvidenceSequenceV1 || r.Evidence.CollectedAt.IsZero() || r.Evidence.ReceivedAt.IsZero() ||
		!sha256Pattern.MatchString(r.Evidence.PayloadSHA256) || !sha256Pattern.MatchString(r.Evidence.RequestSHA256) ||
		r.Evidence.TelemetrySchemaVersion != TelemetryV2Version {
		return fmt.Errorf("invalid prediction evidence reference")
	}
	if r.Health.Status != "unknown" && r.Evidence.CollectedAt.After(r.AsOf) {
		return fmt.Errorf("known prediction cannot rely on future evidence")
	}
	if r.ExpiresAt == nil || r.Prediction == nil {
		return fmt.Errorf("record with evidence requires prediction and expiry")
	}
	if err := r.Prediction.Validate(); err != nil {
		return fmt.Errorf("invalid embedded prediction: %w", err)
	}
	p := r.Prediction
	if p.DeviceID != deviceID || !p.GeneratedAt.UTC().Equal(r.AsOf.UTC()) || !p.ExpiresAt.UTC().Equal(r.ExpiresAt.UTC()) ||
		p.Evidence.Digest != r.Evidence.PayloadSHA256 || p.Evidence.TelemetrySchemaVersion != r.Evidence.TelemetrySchemaVersion {
		return fmt.Errorf("prediction payload disagrees with record provenance")
	}
	if (p.Model == nil) != (r.ModelProvenance == nil) {
		return fmt.Errorf("prediction model reference disagrees with record model provenance")
	}
	if p.Model != nil && (p.Model.Version != r.ModelProvenance.Version || p.Model.SHA256 != r.ModelProvenance.SHA256) {
		return fmt.Errorf("prediction model disagrees with model provenance")
	}
	if p.Health.Status != r.Health.Status || p.Health.UnknownReason != r.Health.UnknownReason ||
		p.Health.ProbabilityUnit != r.Health.ProbabilityUnit ||
		(p.Health.Probability == nil) != (r.Health.Probability == nil) ||
		(p.Health.HorizonHours == nil) != (r.Health.HorizonHours == nil) {
		return fmt.Errorf("prediction health disagrees with record health")
	}
	if p.Health.Probability != nil && *p.Health.Probability != *r.Health.Probability {
		return fmt.Errorf("prediction probability disagrees with record probability")
	}
	if p.Health.HorizonHours != nil && *p.Health.HorizonHours != *r.Health.HorizonHours {
		return fmt.Errorf("prediction horizon disagrees with record horizon")
	}
	return nil
}
