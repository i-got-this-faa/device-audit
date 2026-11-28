package contracts

import "time"

const (
	// ForecastDiagnosticsV1Version versions ForecastDiagnosticsV1.
	ForecastDiagnosticsV1Version = "device-audit.forecast-diagnostics.v1"
	// ForecastDiagnosticTraceV1Version versions ForecastDiagnosticTraceV1.
	ForecastDiagnosticTraceV1Version = "device-audit.forecast-diagnostic-trace.v1"
)

// ForecastDiagnosticOutcomeV1 is what the controller did for one forecast.
type ForecastDiagnosticOutcomeV1 string

const (
	// ForecastDiagnosticLaunched means a new signed assignment was queued.
	ForecastDiagnosticLaunched ForecastDiagnosticOutcomeV1 = "launched"
	// ForecastDiagnosticDeduplicated means this forecast already launched its job.
	ForecastDiagnosticDeduplicated ForecastDiagnosticOutcomeV1 = "deduplicated"
	// ForecastDiagnosticSkipped means no job was queued; Reason says why.
	ForecastDiagnosticSkipped ForecastDiagnosticOutcomeV1 = "skipped"
)

const (
	// ForecastDiagnosticReasonJobInFlight: an earlier forecast's job for the
	// same probe has not reached a terminal state.
	ForecastDiagnosticReasonJobInFlight = "job_in_flight"
)

// ForecastDiagnosticDecisionV1 is the controller's decision for one category.
type ForecastDiagnosticDecisionV1 struct {
	Category         string                      `json:"category"`
	Probability      float64                     `json:"probability"`
	HorizonHours     uint32                      `json:"horizon_hours"`
	ProbeID          string                      `json:"probe_id"`
	Outcome          ForecastDiagnosticOutcomeV1 `json:"outcome"`
	Reason           string                      `json:"reason,omitempty"`
	AssignmentID     string                      `json:"assignment_id,omitempty"`
	AssignmentStatus string                      `json:"assignment_status,omitempty"`
}

// ForecastDiagnosticsV1 is the result of evaluating one device's forecast for
// diagnostics. Decisions is empty unless the forecast is available, so a stale
// or unevaluated forecast never launches work. ForecastStatus and
// ForecastReason are the FED13 freshness verdict that gated the evaluation.
type ForecastDiagnosticsV1 struct {
	SchemaVersion  string                         `json:"schema_version"`
	DeploymentID   string                         `json:"deployment_id"`
	DeviceID       string                         `json:"device_id"`
	EvaluatedAt    time.Time                      `json:"evaluated_at"`
	PolicyVersion  string                         `json:"policy_version"`
	ForecastStatus ForecastStatusV1               `json:"forecast_status"`
	ForecastReason ForecastReasonV1               `json:"forecast_reason"`
	AsOf           *time.Time                     `json:"as_of"`
	Decisions      []ForecastDiagnosticDecisionV1 `json:"decisions"`
}

// ForecastDiagnosticLinkV1 traces one forecast to its job and local insight.
// Evidence holds the device-signed result's evidence references once the job
// finished; it is empty while the job is open or when it produced none.
type ForecastDiagnosticLinkV1 struct {
	AsOf             time.Time              `json:"as_of"`
	Category         string                 `json:"category"`
	Probability      float64                `json:"probability"`
	HorizonHours     uint32                 `json:"horizon_hours"`
	PolicyVersion    string                 `json:"policy_version"`
	ModelVersion     string                 `json:"model_version"`
	ArtifactSHA256   string                 `json:"artifact_sha256"`
	EvaluationSHA256 string                 `json:"evaluation_sha256"`
	EvidenceSequence *uint64                `json:"evidence_sequence"`
	ProbeID          string                 `json:"probe_id"`
	AssignmentID     string                 `json:"assignment_id"`
	AssignmentStatus string                 `json:"assignment_status"`
	ResultState      *string                `json:"result_state"`
	ResultReason     *string                `json:"result_reason"`
	Evidence         []DiagnosticEvidenceV1 `json:"evidence"`
	TriggeredBy      ModelActorV1           `json:"triggered_by"`
	TriggeredAt      time.Time              `json:"triggered_at"`
}

// ForecastDiagnosticTraceV1 lists a device's forecast-triggered jobs, newest
// forecast first.
type ForecastDiagnosticTraceV1 struct {
	SchemaVersion string                     `json:"schema_version"`
	DeploymentID  string                     `json:"deployment_id"`
	DeviceID      string                     `json:"device_id"`
	Links         []ForecastDiagnosticLinkV1 `json:"links"`
}
