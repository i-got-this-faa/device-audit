package contracts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"time"
)

const LifecycleV2Version = "device-audit.lifecycle.v2"
const SustainabilityMethodologyV2 = "carbon-reduction.v1"

// LifecycleV2 is an off-chain batch report proposal, not an implemented evaluator.
type LifecycleV2 struct {
	SchemaVersion   string                  `json:"schema_version"`
	GeneratedAt     time.Time               `json:"generated_at"`
	Provenance      LifecycleProvenanceV2   `json:"provenance"`
	Recommendations []BatchRecommendationV2 `json:"recommendations"`
	ComponentTrends []ComponentTrendV2      `json:"component_trends"`
}

type LifecycleProvenanceV2 struct {
	CohortID            string    `json:"cohort_id"`
	CohortSize          uint32    `json:"cohort_size"`
	BaselineWindowStart time.Time `json:"baseline_window_start"`
	BaselineWindowEnd   time.Time `json:"baseline_window_end"`
	WindowStart         time.Time `json:"window_start"`
	WindowEnd           time.Time `json:"window_end"`
	EvidenceDigest      *string   `json:"evidence_digest"`
}

type RecommendationEvidenceV2 struct {
	TelemetrySchemaVersion  string  `json:"telemetry_schema_version"`
	PredictionSchemaVersion string  `json:"prediction_schema_version"`
	TelemetryDigest         *string `json:"telemetry_digest"`
	PredictionDigest        *string `json:"prediction_digest"`
}

// CostAgeInputsV2 describes a homogeneous batch; costs are per device in currency major units.
type CostAgeInputsV2 struct {
	AgeMonths            *float64 `json:"age_months"`
	Currency             string   `json:"currency"`
	RepairCostMajor      *float64 `json:"repair_cost_major"`
	UpgradeCostMajor     *float64 `json:"upgrade_cost_major"`
	ReplacementCostMajor *float64 `json:"replacement_cost_major"`
}

type BatchRecommendationV2 struct {
	BatchID             string                   `json:"batch_id"`
	AffectedDeviceCount uint32                   `json:"affected_device_count"`
	Action              string                   `json:"action"`
	Evidence            RecommendationEvidenceV2 `json:"evidence"`
	Inputs              CostAgeInputsV2          `json:"inputs"`
	Sustainability      SustainabilityV2         `json:"sustainability"`
	Longevity           LongevityV2              `json:"longevity"`
}

type SustainabilityInputsV2 struct {
	AssessmentHorizonMonths *float64 `json:"assessment_horizon_months"`
	BaselineCarbonKGCO2e    *float64 `json:"baseline_carbon_kg_co2e"`
	ScenarioCarbonKGCO2e    *float64 `json:"scenario_carbon_kg_co2e"`
	BaselineEWasteKG        *float64 `json:"baseline_e_waste_kg"`
	ScenarioEWasteKG        *float64 `json:"scenario_e_waste_kg"`
}

type SustainabilityV2 struct {
	MethodologyVersion  string                 `json:"methodology_version"`
	Status              string                 `json:"status"`
	Inputs              SustainabilityInputsV2 `json:"inputs"`
	ScorePercent        *float64               `json:"score_percent"`
	CarbonAvoidedKGCO2e *float64               `json:"carbon_avoided_kg_co2e"`
	EWasteAvoidedKG     *float64               `json:"e_waste_avoided_kg"`
}

type LongevityV2 struct {
	Status                string   `json:"status"`
	RemainingMonths       *float64 `json:"remaining_months"`
	LowerBoundMonths      *float64 `json:"lower_bound_months"`
	UpperBoundMonths      *float64 `json:"upper_bound_months"`
	ConfidenceProbability *float64 `json:"confidence_probability"`
}

// ComponentTrendV2 compares failure rates across the two provenance windows.
type ComponentTrendV2 struct {
	Category                   string   `json:"category"`
	Status                     string   `json:"status"`
	BaselineSampleCount        uint32   `json:"baseline_sample_count"`
	SampleCount                uint32   `json:"sample_count"`
	BaselineFailureRatePercent *float64 `json:"baseline_failure_rate_percent"`
	FailureRatePercent         *float64 `json:"failure_rate_percent"`
	ChangePercentagePoints     *float64 `json:"change_percentage_points"`
}

// Every lifecycle field is required. Only explicitly listed fields accept null.
func decodeLifecycleObject(data []byte, target interface{}, nullable []string, required ...string) error {
	if err := requireJSONFieldNames(data, required...); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok {
			return fmt.Errorf("%s is required", name)
		}
		allowsNull := false
		for _, candidate := range nullable {
			if name == candidate {
				allowsNull = true
			}
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) && !allowsNull {
			return fmt.Errorf("%s cannot be null", name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func (v *LifecycleV2) UnmarshalJSON(data []byte) error {
	type alias LifecycleV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, nil, "schema_version", "generated_at", "provenance", "recommendations", "component_trends"); err != nil {
		return err
	}
	*v = LifecycleV2(decoded)
	return nil
}

func (v *LifecycleProvenanceV2) UnmarshalJSON(data []byte) error {
	type alias LifecycleProvenanceV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, []string{"evidence_digest"}, "cohort_id", "cohort_size", "baseline_window_start", "baseline_window_end", "window_start", "window_end", "evidence_digest"); err != nil {
		return err
	}
	*v = LifecycleProvenanceV2(decoded)
	return nil
}

func (v *RecommendationEvidenceV2) UnmarshalJSON(data []byte) error {
	type alias RecommendationEvidenceV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, []string{"telemetry_digest", "prediction_digest"}, "telemetry_schema_version", "prediction_schema_version", "telemetry_digest", "prediction_digest"); err != nil {
		return err
	}
	*v = RecommendationEvidenceV2(decoded)
	return nil
}

func (v *CostAgeInputsV2) UnmarshalJSON(data []byte) error {
	type alias CostAgeInputsV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, []string{"age_months", "repair_cost_major", "upgrade_cost_major", "replacement_cost_major"}, "age_months", "currency", "repair_cost_major", "upgrade_cost_major", "replacement_cost_major"); err != nil {
		return err
	}
	*v = CostAgeInputsV2(decoded)
	return nil
}

func (v *BatchRecommendationV2) UnmarshalJSON(data []byte) error {
	type alias BatchRecommendationV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, nil, "batch_id", "affected_device_count", "action", "evidence", "inputs", "sustainability", "longevity"); err != nil {
		return err
	}
	*v = BatchRecommendationV2(decoded)
	return nil
}

func (v *SustainabilityInputsV2) UnmarshalJSON(data []byte) error {
	type alias SustainabilityInputsV2
	var decoded alias
	names := []string{"assessment_horizon_months", "baseline_carbon_kg_co2e", "scenario_carbon_kg_co2e", "baseline_e_waste_kg", "scenario_e_waste_kg"}
	if err := decodeLifecycleObject(data, &decoded, names, names...); err != nil {
		return err
	}
	*v = SustainabilityInputsV2(decoded)
	return nil
}

func (v *SustainabilityV2) UnmarshalJSON(data []byte) error {
	type alias SustainabilityV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, []string{"score_percent", "carbon_avoided_kg_co2e", "e_waste_avoided_kg"}, "methodology_version", "status", "inputs", "score_percent", "carbon_avoided_kg_co2e", "e_waste_avoided_kg"); err != nil {
		return err
	}
	*v = SustainabilityV2(decoded)
	return nil
}

func (v *LongevityV2) UnmarshalJSON(data []byte) error {
	type alias LongevityV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, []string{"remaining_months", "lower_bound_months", "upper_bound_months", "confidence_probability"}, "status", "remaining_months", "lower_bound_months", "upper_bound_months", "confidence_probability"); err != nil {
		return err
	}
	*v = LongevityV2(decoded)
	return nil
}

func (v *ComponentTrendV2) UnmarshalJSON(data []byte) error {
	type alias ComponentTrendV2
	var decoded alias
	if err := decodeLifecycleObject(data, &decoded, []string{"baseline_failure_rate_percent", "failure_rate_percent", "change_percentage_points"}, "category", "status", "baseline_sample_count", "sample_count", "baseline_failure_rate_percent", "failure_rate_percent", "change_percentage_points"); err != nil {
		return err
	}
	*v = ComponentTrendV2(decoded)
	return nil
}

var lifecycleCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)

func (v LifecycleV2) Validate() error {
	p := v.Provenance
	if v.SchemaVersion != LifecycleV2Version || v.GeneratedAt.IsZero() || !opaqueIDPattern.MatchString(p.CohortID) || !nullableLifecycleDigest(p.EvidenceDigest) {
		return fmt.Errorf("invalid lifecycle version, generation time or cohort provenance")
	}
	if p.BaselineWindowStart.IsZero() || p.BaselineWindowEnd.IsZero() || p.WindowStart.IsZero() || p.WindowEnd.IsZero() || !p.BaselineWindowEnd.After(p.BaselineWindowStart) || p.WindowStart.Before(p.BaselineWindowEnd) || !p.WindowEnd.After(p.WindowStart) || v.GeneratedAt.Before(p.WindowEnd) {
		return fmt.Errorf("non-zero, increasing, non-overlapping windows ending by generation are required")
	}
	if v.Recommendations == nil || len(v.Recommendations) > 64 || v.ComponentTrends == nil || len(v.ComponentTrends) > 8 {
		return fmt.Errorf("recommendations and component_trends are required bounded arrays")
	}
	seen := map[string]bool{}
	for _, r := range v.Recommendations {
		if !opaqueIDPattern.MatchString(r.BatchID) || seen[r.BatchID] || r.AffectedDeviceCount == 0 || r.AffectedDeviceCount > p.CohortSize {
			return fmt.Errorf("batch IDs must be unique and affected counts within the cohort")
		}
		seen[r.BatchID] = true
		if err := r.validate(p.EvidenceDigest != nil); err != nil {
			return fmt.Errorf("batch %s: %w", r.BatchID, err)
		}
	}
	for _, trend := range v.ComponentTrends {
		if !validFaultCategory(trend.Category) || !lifecycleNumber(trend.BaselineFailureRatePercent, 0, 100) || !lifecycleNumber(trend.FailureRatePercent, 0, 100) || !lifecycleNumber(trend.ChangePercentagePoints, -100, 100) {
			return fmt.Errorf("invalid component category or trend values")
		}
		if err := lifecycleOutputState(trend.Status, trend.BaselineSampleCount > 0 && trend.SampleCount > 0 && p.CohortSize > 0 && p.EvidenceDigest != nil, trend.BaselineFailureRatePercent, trend.FailureRatePercent, trend.ChangePercentagePoints); err != nil {
			return err
		}
		if trend.Status == "complete" && !lifecycleClose(*trend.ChangePercentagePoints, *trend.FailureRatePercent-*trend.BaselineFailureRatePercent) {
			return fmt.Errorf("trend change must equal current minus baseline rate")
		}
	}
	return nil
}

func (r BatchRecommendationV2) validate(cohortEvidence bool) error {
	i, e := r.Inputs, r.Evidence
	if e.TelemetrySchemaVersion != TelemetryV2Version || e.PredictionSchemaVersion != PredictionV2Version || !nullableLifecycleDigest(e.TelemetryDigest) || !nullableLifecycleDigest(e.PredictionDigest) || !lifecycleCurrencyPattern.MatchString(i.Currency) {
		return fmt.Errorf("invalid evidence versions, digests or currency")
	}
	ready := cohortEvidence && e.TelemetryDigest != nil && e.PredictionDigest != nil
	for _, value := range []*float64{i.AgeMonths, i.RepairCostMajor, i.UpgradeCostMajor, i.ReplacementCostMajor} {
		if !lifecycleNumber(value, 0, math.MaxFloat64) {
			return fmt.Errorf("cost and age inputs must be finite and nonnegative or null")
		}
		ready = ready && value != nil
	}
	switch r.Action {
	case "repair", "upgrade", "replace", "retain":
		if !ready {
			return fmt.Errorf("recommendation requires cohort, telemetry, prediction, cost and age evidence")
		}
	case "insufficient_evidence":
		ready = false
	default:
		return fmt.Errorf("invalid recommendation action")
	}
	if err := r.Sustainability.validate(ready); err != nil {
		return err
	}
	l := r.Longevity
	for _, value := range []*float64{l.RemainingMonths, l.LowerBoundMonths, l.UpperBoundMonths} {
		if !lifecycleNumber(value, 0, math.MaxFloat64) {
			return fmt.Errorf("longevity must use nonnegative finite months or null")
		}
	}
	if !lifecycleNumber(l.ConfidenceProbability, math.SmallestNonzeroFloat64, 1) {
		return fmt.Errorf("confidence_probability must be within (0,1]")
	}
	if err := lifecycleOutputState(l.Status, ready, l.RemainingMonths, l.LowerBoundMonths, l.UpperBoundMonths, l.ConfidenceProbability); err != nil {
		return err
	}
	if l.Status == "complete" && (*l.LowerBoundMonths > *l.RemainingMonths || *l.RemainingMonths > *l.UpperBoundMonths) {
		return fmt.Errorf("longevity estimate must lie within its uncertainty interval")
	}
	return nil
}

func (s SustainabilityV2) validate(ready bool) error {
	if s.MethodologyVersion != SustainabilityMethodologyV2 {
		return fmt.Errorf("unsupported sustainability methodology")
	}
	i := s.Inputs
	for _, value := range []*float64{i.AssessmentHorizonMonths, i.BaselineCarbonKGCO2e, i.ScenarioCarbonKGCO2e, i.BaselineEWasteKG, i.ScenarioEWasteKG} {
		if !lifecycleNumber(value, 0, math.MaxFloat64) {
			return fmt.Errorf("sustainability inputs must be nonnegative finite quantities or null")
		}
		ready = ready && value != nil
	}
	ready = ready && *i.AssessmentHorizonMonths > 0 && *i.BaselineCarbonKGCO2e > 0
	if !lifecycleNumber(s.ScorePercent, 0, 100) || !lifecycleNumber(s.CarbonAvoidedKGCO2e, -math.MaxFloat64, math.MaxFloat64) || !lifecycleNumber(s.EWasteAvoidedKG, -math.MaxFloat64, math.MaxFloat64) {
		return fmt.Errorf("invalid sustainability output quantities")
	}
	if err := lifecycleOutputState(s.Status, ready, s.ScorePercent, s.CarbonAvoidedKGCO2e, s.EWasteAvoidedKG); err != nil {
		return err
	}
	if s.Status == "complete" {
		carbon := *i.BaselineCarbonKGCO2e - *i.ScenarioCarbonKGCO2e
		ewaste := *i.BaselineEWasteKG - *i.ScenarioEWasteKG
		score := math.Max(0, carbon / *i.BaselineCarbonKGCO2e * 100)
		if !lifecycleClose(*s.CarbonAvoidedKGCO2e, carbon) || !lifecycleClose(*s.EWasteAvoidedKG, ewaste) || !lifecycleClose(*s.ScorePercent, score) {
			return fmt.Errorf("sustainability outputs do not match carbon-reduction.v1 inputs")
		}
	}
	return nil
}

func nullableLifecycleDigest(value *string) bool {
	return value == nil || sha256Pattern.MatchString(*value)
}

func lifecycleNumber(value *float64, minimum, maximum float64) bool {
	return value == nil || (!math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= minimum && *value <= maximum)
}

func lifecycleOutputState(status string, ready bool, values ...*float64) error {
	if status != "complete" && status != "insufficient_evidence" {
		return fmt.Errorf("output status must be complete or insufficient_evidence")
	}
	for _, value := range values {
		if status == "complete" && (!ready || value == nil) {
			return fmt.Errorf("complete output requires all inputs, evidence and output quantities")
		}
		if status == "insufficient_evidence" && value != nil {
			return fmt.Errorf("insufficient_evidence output quantities must be null")
		}
	}
	return nil
}

func lifecycleClose(actual, expected float64) bool {
	return math.Abs(actual-expected) <= 1e-9*math.Max(1, math.Abs(expected))
}
