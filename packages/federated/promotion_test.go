package federated

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/health"
)

type vectorSide struct {
	Verdict             health.EvaluationVerdict `json:"verdict"`
	Reasons             []string                 `json:"reasons"`
	TestPartitionSHA256 string                   `json:"test_partition_sha256"`
	Metrics             map[string]float64       `json:"metrics"`
}

func (v vectorSide) assessment() *health.EvaluationAssessment {
	metrics := make(map[string]health.MetricInterval, len(v.Metrics))
	for name, point := range v.Metrics {
		metrics[name] = health.MetricInterval{Point: point, Lower: point, Upper: point}
	}
	return &health.EvaluationAssessment{Verdict: v.Verdict, Reasons: v.Reasons, TestPartitionSHA256: v.TestPartitionSHA256, Metrics: metrics}
}

func readEvaluationJSON(t *testing.T, name string, target any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "models", "evaluation", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, target); err != nil {
		t.Fatal(err)
	}
}

// The vectors are shared with models/tests/test_promotion.py, so the Go
// controller and the offline Python check cannot disagree about a candidate.
func TestDecideMatchesSharedVectors(t *testing.T) {
	var vectors struct {
		PolicyVersion string `json:"policy_version"`
		Cases         []struct {
			Name      string      `json:"name"`
			Candidate vectorSide  `json:"candidate"`
			Active    *vectorSide `json:"active"`
			Outcome   Outcome     `json:"outcome"`
			Reasons   []string    `json:"reasons"`
		} `json:"cases"`
	}
	readEvaluationJSON(t, "promotion-vectors.json", &vectors)
	if vectors.PolicyVersion != PromotionPolicyVersion || len(vectors.Cases) == 0 {
		t.Fatalf("vectors %q do not cover %q", vectors.PolicyVersion, PromotionPolicyVersion)
	}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			var active *health.EvaluationAssessment
			if c.Active != nil {
				active = c.Active.assessment()
			}
			got := Decide(*c.Candidate.assessment(), active)
			if got.Outcome != c.Outcome || !slices.Equal(append([]string{}, got.Reasons...), c.Reasons) {
				t.Fatalf("Decide = %s %v, want %s %v", got.Outcome, got.Reasons, c.Outcome, c.Reasons)
			}
			if c.Outcome == OutcomePromoted && c.Active != nil && len(got.Checks) != len(RegressionGates) {
				t.Fatalf("a comparison must record every gate, got %d checks", len(got.Checks))
			}
		})
	}
}

func TestRegressionGatesMatchFrozenPolicyFile(t *testing.T) {
	var policy struct {
		PolicyVersion string `json:"policy_version"`
		Gates         []struct {
			ID             string  `json:"id"`
			Metric         string  `json:"metric"`
			HigherIsBetter bool    `json:"higher_is_better"`
			MaxDegradation float64 `json:"max_degradation"`
		} `json:"regression_gates"`
	}
	readEvaluationJSON(t, "promotion-policy.json", &policy)
	if policy.PolicyVersion != PromotionPolicyVersion || len(policy.Gates) != len(RegressionGates) {
		t.Fatalf("policy file %q with %d gates drifted from the Go constants", policy.PolicyVersion, len(policy.Gates))
	}
	for i, gate := range policy.Gates {
		want := RegressionGates[i]
		if gate.ID != want.ID || gate.Metric != want.Metric || gate.HigherIsBetter != want.HigherIsBetter || gate.MaxDegradation != want.MaxDegradation {
			t.Fatalf("gate %d differs: file %+v, Go %+v", i, gate, want)
		}
	}
}
