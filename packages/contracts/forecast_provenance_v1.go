package contracts

import "time"

const (
	// ForecastProvenanceV1Version versions DeviceForecastV1.
	ForecastProvenanceV1Version = "device-audit.forecast-provenance.v1"
	// ForecastSourceV1Version versions ForecastSourceV1.
	ForecastSourceV1Version = "device-audit.forecast-source.v1"
)

// ForecastStatusV1 is whether a workflow may act on a device's forecasts.
type ForecastStatusV1 string

const (
	// ForecastAvailable means the forecasts are fresh and rest on a promoted,
	// evaluated model that is still the active model.
	ForecastAvailable ForecastStatusV1 = "available"
	// ForecastStale means a forecast exists but may no longer be acted on.
	ForecastStale ForecastStatusV1 = "stale"
	// ForecastUnavailable means no forecast may be used.
	ForecastUnavailable ForecastStatusV1 = "unavailable"
)

// ForecastReasonV1 is the stable code for a forecast that is not available.
type ForecastReasonV1 string

const (
	ForecastReasonNone ForecastReasonV1 = ""
	// Prediction state.
	ForecastReasonNoPrediction         ForecastReasonV1 = "no_prediction"
	ForecastReasonModelUnavailable     ForecastReasonV1 = "model_unavailable"
	ForecastReasonInsufficientEvidence ForecastReasonV1 = "insufficient_evidence"
	ForecastReasonStaleEvidence        ForecastReasonV1 = "stale_evidence"
	ForecastReasonPredictionExpired    ForecastReasonV1 = "prediction_expired"
	ForecastReasonModelSuperseded      ForecastReasonV1 = "model_superseded"
	// Model source state.
	ForecastReasonRoundNotAggregated   ForecastReasonV1 = "round_not_aggregated"
	ForecastReasonRoundFailed          ForecastReasonV1 = "round_failed"
	ForecastReasonCandidateUnevaluated ForecastReasonV1 = "candidate_unevaluated"
	ForecastReasonEvaluationNotPassing ForecastReasonV1 = "evaluation_not_passing"
	ForecastReasonCandidateRejected    ForecastReasonV1 = "candidate_rejected"
	ForecastReasonNotPromoted          ForecastReasonV1 = "not_promoted"
)

// ForecastOriginV1 is the federated round that produced a model. It is null
// for a model that did not come from a round.
type ForecastOriginV1 struct {
	RoundID          string `json:"round_id"`
	CandidateID      string `json:"candidate_id"`
	WeightingPolicy  string `json:"weighting_policy"`
	ParticipantCount int    `json:"participant_count"`
	TotalSamples     uint64 `json:"total_samples"`
	InputSHA256      string `json:"input_sha256"`
	WeightsSHA256    string `json:"weights_sha256"`
}

// ForecastModelV1 names the evaluated model behind a forecast and the records
// that made it eligible.
type ForecastModelV1 struct {
	Version                string            `json:"version"`
	ArtifactSHA256         string            `json:"artifact_sha256"`
	FeatureVersion         string            `json:"feature_version"`
	EvaluationSHA256       string            `json:"evaluation_sha256"`
	EvaluationPolicy       string            `json:"evaluation_policy_version"`
	EvaluationVerdict      string            `json:"evaluation_verdict"`
	PromotionPolicyVersion string            `json:"promotion_policy_version"`
	PromotedAt             *time.Time        `json:"promoted_at"`
	Active                 bool              `json:"active"`
	Origin                 *ForecastOriginV1 `json:"origin"`
}

// ForecastWindowV1 is the observation window the forecast was computed from.
type ForecastWindowV1 struct {
	FeatureVersion string `json:"feature_version"`
	Start          string `json:"start"`
	End            string `json:"end"`
	Status         string `json:"status"`
	SamplesRead    int    `json:"samples_read"`
}

// DeviceForecastV1 is the forecast data a workflow may consume for one
// device, with its provenance and freshness. Forecasts is empty unless Status
// is "available", so a stale or unevaluated forecast cannot be used by
// mistake. A null probability or horizon is never converted to zero.
type DeviceForecastV1 struct {
	SchemaVersion string                   `json:"schema_version"`
	DeploymentID  string                   `json:"deployment_id"`
	DeviceID      string                   `json:"device_id"`
	EvaluatedAt   time.Time                `json:"evaluated_at"`
	Status        ForecastStatusV1         `json:"status"`
	Reason        ForecastReasonV1         `json:"reason"`
	AsOf          *time.Time               `json:"as_of"`
	ExpiresAt     *time.Time               `json:"expires_at"`
	HorizonHours  *uint32                  `json:"horizon_hours"`
	Health        *HealthV2                `json:"health"`
	Forecasts     []FaultForecastV2        `json:"forecasts"`
	Model         *ForecastModelV1         `json:"model"`
	Window        *ForecastWindowV1        `json:"observation_window"`
	Evidence      *PredictionEvidenceRefV1 `json:"evidence"`
}

// ForecastSourceV1 says whether a model, or a federated round's candidate,
// may back forecasts. Status is "available" or "unavailable". A failed round,
// a rejected candidate and an unevaluated aggregate are unavailable with a
// stable reason; none of them is ever reported as an approved forecast.
type ForecastSourceV1 struct {
	SchemaVersion string           `json:"schema_version"`
	DeploymentID  string           `json:"deployment_id"`
	RoundID       string           `json:"round_id"`
	ModelVersion  string           `json:"model_version"`
	Status        ForecastStatusV1 `json:"status"`
	Reason        ForecastReasonV1 `json:"reason"`
	FailureReason string           `json:"round_failure_reason"`
	Model         *ForecastModelV1 `json:"model"`
}
