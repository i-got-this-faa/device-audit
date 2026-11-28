package federated

import (
	"fmt"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// FED10 #115 promotion policy. The gates below were declared on 28 November
// 2026 before any federated candidate was evaluated. They sit on top of the
// frozen ML05 thresholds in health and mirror
// models/evaluation/promotion-policy.json; a test fails if the two drift.
const PromotionPolicyVersion = "fed10.v1"

// Outcome is the recorded result of one promotion decision.
type Outcome = contracts.ModelPromotionOutcomeV1

const (
	// OutcomePromoted means the candidate passed every gate and became active.
	OutcomePromoted = contracts.ModelPromotionPromoted
	// OutcomeRejected means the active model stays as it was.
	OutcomeRejected = contracts.ModelPromotionRejected
)

// RegressionGate bounds how far a candidate's point estimate may fall behind
// the active model's on the same frozen held-out examples. MaxDegradation is
// absolute, in the metric's own unit; zero allows no loss at all.
type RegressionGate struct {
	ID             string
	Metric         string
	HigherIsBetter bool
	MaxDegradation float64
}

// RegressionGates are checked only when an active model exists. Point
// estimates are compared on purpose: with a few dozen held-out events an
// interval overlap cannot show that a candidate is no worse.
var RegressionGates = []RegressionGate{
	{"active_average_precision", "average_precision", true, 0.0},
	{"active_roc_auc", "roc_auc", true, 0.005},
	{"active_event_recall", "event_recall_within_horizon", true, 0.02},
	{"active_window_fpr_degraded", "window_false_positive_rate_degraded", false, 0.001},
	{"active_window_fpr_critical", "window_false_positive_rate_critical", false, 0.0003},
	{"active_device_false_alarm", "never_positive_device_alert_fraction", false, 0.01},
}

// RegressionCheck records one gate's comparison so a decision can be audited.
type RegressionCheck = contracts.ModelRegressionCheckV1

// Decision is the controller's reading of one candidate. It has no actor and
// no time: the repository records who asked and when.
type Decision struct {
	Outcome Outcome
	// Reasons is empty only when promoted. Each is a stable code.
	Reasons []string
	// Checks is empty when there is no active baseline or no comparison ran.
	Checks []RegressionCheck
}

// Decide applies the frozen policy. active is nil when no model is active, and
// then only the ML05 gates apply. A candidate that did not pass, or whose
// evidence cannot be compared with the active model's, is rejected.
func Decide(candidate health.EvaluationAssessment, active *health.EvaluationAssessment) Decision {
	if candidate.Verdict != health.EvaluationPass {
		reasons := []string{"evaluation_" + string(candidate.Verdict)}
		return Decision{Outcome: OutcomeRejected, Reasons: append(reasons, candidate.Reasons...)}
	}
	if active == nil {
		return Decision{Outcome: OutcomePromoted}
	}
	if active.Verdict != health.EvaluationPass || active.TestPartitionSHA256 != candidate.TestPartitionSHA256 {
		return Decision{Outcome: OutcomeRejected, Reasons: []string{"baseline_not_comparable"}}
	}
	decision := Decision{Outcome: OutcomePromoted}
	for _, gate := range RegressionGates {
		candidateValue, activeValue := candidate.Metrics[gate.Metric].Point, active.Metrics[gate.Metric].Point
		loss := activeValue - candidateValue
		if !gate.HigherIsBetter {
			loss = candidateValue - activeValue
		}
		check := RegressionCheck{GateID: gate.ID, Metric: gate.Metric, Candidate: candidateValue, Active: activeValue, Status: "pass"}
		if loss > gate.MaxDegradation {
			check.Status = "fail"
			decision.Outcome = OutcomeRejected
			decision.Reasons = append(decision.Reasons, fmt.Sprintf("regression:%s", gate.ID))
		}
		decision.Checks = append(decision.Checks, check)
	}
	return decision
}
