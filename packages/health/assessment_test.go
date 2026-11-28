package health_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func assess(t *testing.T, manifest contracts.ModelManifestV1, edit func(report map[string]any)) health.EvaluationAssessment {
	t.Helper()
	// Round-trip through JSON so every nested value is an editable map.
	encoded, _ := marshalEvaluation(t, buildPassingEvaluationMap(manifest, 0, 2))
	var report map[string]any
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(report)
	}
	raw, _ := marshalEvaluation(t, report)
	return health.AssessEvaluationReport(raw, manifest)
}

func TestAssessEvaluationReportSeparatesFailedFromBlocked(t *testing.T) {
	manifest := contracts.ModelManifestV1{ModelVersion: "candidate.1"}
	manifest.ArtifactSHA256 = "7a9d3b1c5e2f4a6b8c0d1e3f5a7b9c1d3e5f7a9b1c3d5e7f9a1b3c5d7e9f1a3b"

	if got := assess(t, manifest, nil); got.Verdict != health.EvaluationPass || len(got.Reasons) != 0 ||
		got.Metrics["average_precision"].Point != 0.20 || got.TestPartitionSHA256 == "" {
		t.Fatalf("passing report assessed as %+v", got)
	}

	poor := assess(t, manifest, func(report map[string]any) {
		report["metrics"].(map[string]any)["calibration_slope"] = map[string]any{"point": 0.4, "lower": 0.3, "upper": 0.5}
	})
	if poor.Verdict != health.EvaluationFail || !slices.Equal(poor.Reasons, []string{"gate_failed:calibration_slope_low"}) || poor.Metrics == nil {
		t.Fatalf("poor calibration assessed as %+v", poor)
	}

	// Evidence that cannot decide blocks. It is neither a pass nor a fail.
	cases := map[string]struct {
		edit   func(report map[string]any)
		reason string
	}{
		"too few test devices": {func(r map[string]any) { r["counts"].(map[string]any)["test_devices"] = 10 }, "insufficient:test_devices"},
		"missing count":        {func(r map[string]any) { delete(r["counts"].(map[string]any), "test_devices") }, "missing_count:test_devices"},
		"missing metric":       {func(r map[string]any) { delete(r["metrics"].(map[string]any), "roc_auc") }, "missing_metric:roc_auc"},
		"interrupted":          {func(r map[string]any) { r["evaluation_error"] = "evaluation_interrupted_or_in_progress" }, "evaluation_error"},
		"test set reused":      {func(r map[string]any) { r["test_evaluations_for_candidate"] = 2 }, "held_out_reuse_or_unrecorded"},
		"another model":        {func(r map[string]any) { r["model"].(map[string]any)["version"] = "candidate.2" }, "model_mismatch"},
		"unfrozen bootstrap":   {func(r map[string]any) { r["bootstrap"].(map[string]any)["replicates"] = 10 }, "bootstrap_procedure_mismatch"},
		"no test partition":    {func(r map[string]any) { delete(r, "partition_examples_sha256") }, "test_partition_digest_missing"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := assess(t, manifest, c.edit)
			if got.Verdict != health.EvaluationBlocked || !slices.Contains(got.Reasons, c.reason) {
				t.Fatalf("assessed as %s %v, want blocked with %q", got.Verdict, got.Reasons, c.reason)
			}
		})
	}

	// A report whose own gate claims pass cannot override the metrics.
	liar := assess(t, manifest, func(report map[string]any) {
		report["metrics"].(map[string]any)["brier_skill_vs_prevalence"] = map[string]any{"point": -1.0, "lower": -2.0, "upper": -0.5}
	})
	if liar.Verdict != health.EvaluationFail || !slices.Contains(liar.Reasons, "gate_failed:brier_skill") {
		t.Fatalf("an embedded passing gate overrode the metrics: %+v", liar)
	}
}

// The recorded ML06 report is the real example of a model that must not be promoted.
func TestAssessEvaluationReportFailsTheRecordedML06Candidate(t *testing.T) {
	manifest := contracts.ModelManifestV1{ModelVersion: "logistic-baseline.backblaze-2013.v1",
		ArtifactSHA256: "e5cbc59e4bb6cebe348e7d3edfab1bbe998720ed27c3445f1409b7ecc7c3d3c8"}
	got := health.AssessEvaluationReport(loadRealFailedEvaluationReport(t), manifest)
	want := []string{"gate_failed:baseline_average_precision", "gate_failed:brier_skill", "gate_failed:observed_expected_low", "gate_failed:calibration_slope_low"}
	if got.Verdict != health.EvaluationFail || !slices.Equal(got.Reasons, want) {
		t.Fatalf("recorded report assessed as %s %v, want fail %v", got.Verdict, got.Reasons, want)
	}
}
