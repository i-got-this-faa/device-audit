package health

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ML04 #35: versioned health-assignment rules combining evaluated model
// predictions with ML10 historical fault comparisons.
const (
	HealthRulesVersion = "health-rules.v1"

	HealthStatusHealthy  = "healthy"
	HealthStatusDegraded = "degraded"
	HealthStatusCritical = "critical"
	HealthStatusUnknown  = "unknown"

	UnknownReasonInsufficientEvidence = "insufficient_evidence"
	UnknownReasonModelUnavailable     = "model_unavailable"
	UnknownReasonStaleEvidence        = "stale_evidence"
)

var opaqueDeviceIDPattern = regexp.MustCompile(contracts.OpaqueIDPattern)

// EvidenceSummary identifies the latest persisted telemetry sample observed at
// or before the evaluation clock.
type EvidenceSummary struct {
	Sequence               uint64
	CollectedAt            time.Time
	PayloadSHA256          string
	TelemetrySchemaVersion string
}

// FaultSummary aggregates ML10 fault comparison counts without collapsing
// unobserved windows or empty log references into a healthy claim.
type FaultSummary struct {
	TotalTypes               int
	RecurrentTypes           int
	IsolatedTypes            int
	BaselineOnlyTypes        int
	InsufficientHistoryTypes int
	CurrentReports           int
	BaselineReports          int
	DuplicateReports         int
}

// AssessmentInput supplies the evaluated model, triggering telemetry summary,
// CT03 feature vector, and ML10 fault comparison for one device at AsOf.
type AssessmentInput struct {
	DeviceID       string
	AsOf           time.Time
	MaxEvidenceAge time.Duration
	Model          *EvaluatedModel
	ModelFailure   error
	LatestEvidence *EvidenceSummary
	Features       *contracts.FeatureVectorV1
	FaultHistory   *FaultHistory
}

// Assessment is the attributable health verdict and validated PredictionV2
// produced under HealthRulesVersion. Prediction is nil only when no telemetry
// sample exists at or before AsOf (because PredictionV2 requires an evidence
// digest and never fabricates one).
type Assessment struct {
	RulesVersion         string
	DeviceID             string
	AsOf                 time.Time
	Model                *contracts.ModelReferenceV2
	PolicyVersion        string
	PolicySHA256         string
	EvaluationSHA256     string
	ModelStatus          string
	RuleReason           string
	FaultObservationNote string
	FaultSummary         FaultSummary
	Health               contracts.HealthV2
	Prediction           *contracts.PredictionV2
}

// AssessHealth assigns evidence-backed health under health-rules.v1:
//
//  1. Model missing, rejected, or failed evaluation/scoring -> unknown (model_unavailable, Model: nil).
//  2. Missing telemetry at or before AsOf -> unknown (insufficient_evidence, Prediction: nil).
//  3. Latest telemetry older than MaxEvidenceAge (default 1h) or ahead of AsOf -> unknown (stale_evidence).
//  4. Incomplete CT03 feature vector or insufficiently sampled current fault window -> unknown (insufficient_evidence).
//  5. Combined known verdicts (preserving the model's probability and horizon without inventing numbers):
//     - critical model -> critical
//     - degraded model + recurrent fault with increased rate -> critical
//     - degraded model otherwise -> degraded
//     - healthy model + recurrent fault -> degraded
//     - healthy model + insufficient fault baseline or insufficient_history fault -> unknown (insufficient_evidence)
//     - healthy model + isolated/baseline_only/no-report in sufficient windows -> healthy
func AssessHealth(input AssessmentInput) (Assessment, error) {
	if !opaqueDeviceIDPattern.MatchString(input.DeviceID) || input.AsOf.IsZero() || input.MaxEvidenceAge < 0 {
		return Assessment{}, errors.New("valid device_id, non-zero as_of, and non-negative max_evidence_age are required")
	}
	asOf := input.AsOf.UTC()
	maxAge := input.MaxEvidenceAge
	if maxAge == 0 {
		maxAge = MaxEvidenceAge
	}
	if err := validateAssessmentEvidence(input.LatestEvidence); err != nil {
		return Assessment{}, err
	}
	if err := validateAssessmentWindows(asOf, input.Features, input.FaultHistory); err != nil {
		return Assessment{}, err
	}

	out := Assessment{
		RulesVersion: HealthRulesVersion,
		DeviceID:     input.DeviceID,
		AsOf:         asOf,
		ModelStatus:  HealthStatusUnknown,
		Health: contracts.HealthV2{
			Status:          HealthStatusUnknown,
			ProbabilityUnit: "probability",
		},
	}
	if input.FaultHistory != nil {
		out.FaultSummary, out.FaultObservationNote = summarizeFaults(*input.FaultHistory)
	} else {
		out.FaultObservationNote = "fault_history_unavailable"
	}

	if input.Model == nil || input.ModelFailure != nil {
		out.Health.UnknownReason = UnknownReasonModelUnavailable
		out.RuleReason = "model_unavailable"
		return finalizeAssessment(out, input.LatestEvidence, maxAge)
	}

	ref := input.Model.Reference()
	out.Model = &ref
	out.PolicyVersion = input.Model.PolicyVersion
	out.PolicySHA256 = input.Model.PolicySHA256
	out.EvaluationSHA256 = input.Model.EvaluationSHA256

	if input.LatestEvidence == nil {
		out.Health.UnknownReason = UnknownReasonInsufficientEvidence
		out.RuleReason = "no_telemetry_evidence"
		return finalizeAssessment(out, nil, maxAge)
	}

	collected := input.LatestEvidence.CollectedAt.UTC()
	if collected.After(asOf) || asOf.Sub(collected) >= maxAge {
		out.Health.UnknownReason = UnknownReasonStaleEvidence
		out.RuleReason = "stale_telemetry_evidence"
		return finalizeAssessment(out, input.LatestEvidence, maxAge)
	}

	if input.Features == nil {
		out.Health.UnknownReason = UnknownReasonInsufficientEvidence
		out.RuleReason = "missing_feature_vector"
		return finalizeAssessment(out, input.LatestEvidence, maxAge)
	}

	pred, err := input.Model.Predict(*input.Features)
	if err != nil {
		if errors.Is(err, ErrIncompleteFeatures) {
			out.Health.UnknownReason = UnknownReasonInsufficientEvidence
			out.RuleReason = "incomplete_feature_vector"
			return finalizeAssessment(out, input.LatestEvidence, maxAge)
		}
		out.Model = nil
		out.PolicyVersion = ""
		out.PolicySHA256 = ""
		out.EvaluationSHA256 = ""
		out.Health.UnknownReason = UnknownReasonModelUnavailable
		out.RuleReason = "model_inference_failed"
		return finalizeAssessment(out, input.LatestEvidence, maxAge)
	}
	out.ModelStatus = pred.Status

	if input.FaultHistory == nil || !input.FaultHistory.Current.Sufficient {
		out.Health.UnknownReason = UnknownReasonInsufficientEvidence
		out.RuleReason = "insufficient_current_fault_window"
		return finalizeAssessment(out, input.LatestEvidence, maxAge)
	}

	finalStatus, unknownReason, ruleReason := combineModelAndFaults(pred.Status, *input.FaultHistory, out.FaultSummary)
	if finalStatus == HealthStatusUnknown {
		out.Health.UnknownReason = unknownReason
		out.RuleReason = ruleReason
		return finalizeAssessment(out, input.LatestEvidence, maxAge)
	}

	prob := pred.Probability
	horizon := pred.HorizonHours
	out.Health = contracts.HealthV2{
		Status:          finalStatus,
		Probability:     &prob,
		ProbabilityUnit: "probability",
		HorizonHours:    &horizon,
	}
	out.RuleReason = ruleReason
	return finalizeAssessment(out, input.LatestEvidence, maxAge)
}

func validateAssessmentEvidence(e *EvidenceSummary) error {
	if e == nil {
		return nil
	}
	if e.CollectedAt.IsZero() || !lowerHexSHA256Pattern.MatchString(e.PayloadSHA256) || e.TelemetrySchemaVersion != contracts.TelemetryV2Version {
		return errors.New("valid collected_at, payload_sha256, and telemetry.v2 schema_version are required")
	}
	return nil
}

func validateAssessmentWindows(asOf time.Time, features *contracts.FeatureVectorV1, history *FaultHistory) error {
	end := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	start := end.AddDate(0, 0, -(contracts.FeatureWindowDays - 1))
	if features != nil {
		if err := features.Validate(); err != nil {
			return fmt.Errorf("invalid feature vector: %w", err)
		}
		if features.AsOf != asOf.Truncate(time.Second).Format(time.RFC3339) ||
			features.WindowStart != start.Format(time.DateOnly) || features.WindowEnd != end.Format(time.DateOnly) {
			return errors.New("feature vector window does not match as_of")
		}
	}
	if history != nil {
		if !history.AsOf.UTC().Equal(asOf) || !history.Current.From.Equal(start) {
			return errors.New("fault history window does not match as_of")
		}
	}
	return nil
}

func summarizeFaults(history FaultHistory) (FaultSummary, string) {
	var summary FaultSummary
	summary.TotalTypes = len(history.Faults)
	for _, f := range history.Faults {
		summary.CurrentReports += f.CurrentReports
		summary.BaselineReports += f.BaselineReports
		summary.DuplicateReports += f.DuplicateReports
		switch f.Recurrence {
		case FaultRecurrent:
			summary.RecurrentTypes++
		case FaultIsolated:
			summary.IsolatedTypes++
		case FaultBaselineOnly:
			summary.BaselineOnlyTypes++
		case FaultInsufficientHistory:
			summary.InsufficientHistoryTypes++
		}
	}
	if len(history.Faults) == 0 {
		if history.Current.Sufficient && history.Baseline.Sufficient {
			return summary, "no_log_references_observed_in_sufficient_windows; error collection status is unconfirmed"
		}
		return summary, "no_log_references_observed_with_insufficient_history; missing days are unobserved"
	}
	return summary, "log_references_compared_against_baseline_window"
}

func combineModelAndFaults(modelStatus string, history FaultHistory, summary FaultSummary) (status, unknownReason, ruleReason string) {
	hasRecurrentIncreased := false
	for _, f := range history.Faults {
		if f.Recurrence == FaultRecurrent && f.CountChange == FaultCountIncreased {
			hasRecurrentIncreased = true
			break
		}
	}
	switch modelStatus {
	case HealthStatusCritical:
		if summary.RecurrentTypes > 0 {
			return HealthStatusCritical, "", "model_critical_with_recurrent_faults"
		}
		return HealthStatusCritical, "", "model_critical"
	case HealthStatusDegraded:
		if hasRecurrentIncreased {
			return HealthStatusCritical, "", "model_degraded_escalated_by_increasing_recurrent_faults"
		}
		if summary.RecurrentTypes > 0 {
			return HealthStatusDegraded, "", "model_degraded_with_recurrent_faults"
		}
		return HealthStatusDegraded, "", "model_degraded"
	case HealthStatusHealthy:
		if summary.RecurrentTypes > 0 {
			return HealthStatusDegraded, "", "model_healthy_escalated_by_recurrent_faults"
		}
		if summary.InsufficientHistoryTypes > 0 {
			return HealthStatusUnknown, UnknownReasonInsufficientEvidence, "insufficient_fault_history_for_healthy"
		}
		if !history.Baseline.Sufficient {
			return HealthStatusUnknown, UnknownReasonInsufficientEvidence, "insufficient_fault_baseline_for_healthy"
		}
		if summary.IsolatedTypes > 0 {
			return HealthStatusHealthy, "", "model_healthy_with_isolated_fault"
		}
		if summary.BaselineOnlyTypes > 0 {
			return HealthStatusHealthy, "", "model_healthy_with_baseline_only_fault"
		}
		return HealthStatusHealthy, "", "model_healthy_with_sufficient_baseline"
	default:
		return HealthStatusUnknown, UnknownReasonModelUnavailable, "model_unavailable"
	}
}

func finalizeAssessment(out Assessment, latest *EvidenceSummary, maxAge time.Duration) (Assessment, error) {
	if latest == nil {
		return out, nil
	}
	expires := out.AsOf.Add(maxAge)
	if out.Health.Status != HealthStatusUnknown {
		expires = latest.CollectedAt.Add(maxAge)
	}
	prediction := contracts.PredictionV2{
		SchemaVersion: contracts.PredictionV2Version,
		DeviceID:      out.DeviceID,
		Model:         out.Model,
		Evidence: &contracts.EvidenceV2{
			Digest:                 latest.PayloadSHA256,
			TelemetrySchemaVersion: latest.TelemetrySchemaVersion,
		},
		GeneratedAt: out.AsOf,
		ExpiresAt:   expires,
		Health:      out.Health,
		Forecasts:   []contracts.FaultForecastV2{},
	}
	if err := prediction.Validate(); err != nil {
		return Assessment{}, fmt.Errorf("invalid prediction output: %w", err)
	}
	out.Prediction = &prediction
	return out, nil
}
