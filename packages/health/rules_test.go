package health_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func loadRealBaselineArtifact(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "models", "baseline", "backblaze-2013", "artifact.json"))
	if err != nil {
		t.Fatalf("read baseline artifact: %v", err)
	}
	return data
}

func loadRealFailedEvaluationReport(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "models", "evaluation", "results", "logistic-baseline.backblaze-2013.v1.json"))
	if err != nil {
		t.Fatalf("read ML06 evaluation report: %v", err)
	}
	return data
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func artifactModelVersion(t *testing.T, artifact []byte) string {
	t.Helper()
	var meta struct {
		ModelVersion string `json:"model_version"`
	}
	if err := json.Unmarshal(artifact, &meta); err != nil || meta.ModelVersion == "" {
		t.Fatalf("read artifact model_version: %v", err)
	}
	return meta.ModelVersion
}

func signTestManifest(t *testing.T, key ed25519.PrivateKey, artifact []byte, runtime contracts.ModelRuntimeV1, purposes ...string) contracts.ModelManifestV1 {
	t.Helper()
	features, _, err := contracts.FeatureNamesV1(contracts.FeatureVersionHDDSMART7DV1)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := contracts.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	m := contracts.ModelManifestV1{
		SchemaVersion:  contracts.ModelManifestV1Version,
		ModelVersion:   artifactModelVersion(t, artifact),
		ArtifactSHA256: sha256Hex(artifact),
		Architecture:   "logistic-baseline.v1",
		ParameterCount: uint32(len(features) + 1),
		RuntimeName:    runtime.Name,
		RuntimeVersion: runtime.Version,
		FeatureVersion: contracts.FeatureVersionHDDSMART7DV1,
		Features:       features,
		Purposes:       purposes,
		SigningKeyID:   keyID,
	}
	msg, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(key, msg))
	return m
}

func buildPassingEvaluationMap(manifest contracts.ModelManifestV1, degradedLogit, criticalLogit float64) map[string]any {
	metrics := map[string]map[string]float64{
		"average_precision_minus_best_baseline": {"point": 0.12, "lower": 0.05, "upper": 0.19},
		"event_recall_minus_smart_rule":         {"point": 0.05, "lower": 0.01, "upper": 0.09},
		"roc_auc":                               {"point": 0.82, "lower": 0.76, "upper": 0.88},
		"window_false_positive_rate_degraded":   {"point": 0.005, "lower": 0.003, "upper": 0.008},
		"window_false_positive_rate_critical":   {"point": 0.001, "lower": 0.0005, "upper": 0.0015},
		"never_positive_device_alert_fraction":  {"point": 0.04, "lower": 0.02, "upper": 0.08},
		"brier_skill_vs_prevalence":             {"point": 0.15, "lower": 0.08, "upper": 0.22},
		"observed_to_expected_ratio":            {"point": 1.02, "lower": 0.85, "upper": 1.20},
		"calibration_slope":                     {"point": 0.98, "lower": 0.82, "upper": 1.14},
		"event_recall_within_horizon":           {"point": 0.45, "lower": 0.28, "upper": 0.62},
		"median_first_alert_lead_days":          {"point": 3.5, "lower": 2.2, "upper": 4.8},
		"average_precision":                     {"point": 0.20, "lower": 0.10, "upper": 0.30},
	}
	checks := []map[string]any{
		{"id": "baseline_average_precision", "kind": "baseline", "metric": "average_precision_minus_best_baseline", "bound": "lower", "op": ">", "threshold": 0.0, "observed": metrics["average_precision_minus_best_baseline"]["lower"], "status": "pass"},
		{"id": "baseline_event_recall", "kind": "baseline", "metric": "event_recall_minus_smart_rule", "bound": "lower", "op": ">=", "threshold": -0.05, "observed": metrics["event_recall_minus_smart_rule"]["lower"], "status": "pass"},
		{"id": "discrimination_roc_auc", "kind": "baseline", "metric": "roc_auc", "bound": "lower", "op": ">=", "threshold": 0.70, "observed": metrics["roc_auc"]["lower"], "status": "pass"},
		{"id": "window_fpr_degraded", "kind": "false_positive", "metric": "window_false_positive_rate_degraded", "bound": "upper", "op": "<=", "threshold": 0.01, "observed": metrics["window_false_positive_rate_degraded"]["upper"], "status": "pass"},
		{"id": "window_fpr_critical", "kind": "false_positive", "metric": "window_false_positive_rate_critical", "bound": "upper", "op": "<=", "threshold": 0.002, "observed": metrics["window_false_positive_rate_critical"]["upper"], "status": "pass"},
		{"id": "device_false_alarm", "kind": "false_positive", "metric": "never_positive_device_alert_fraction", "bound": "upper", "op": "<=", "threshold": 0.10, "observed": metrics["never_positive_device_alert_fraction"]["upper"], "status": "pass"},
		{"id": "brier_skill", "kind": "calibration", "metric": "brier_skill_vs_prevalence", "bound": "lower", "op": ">", "threshold": 0.0, "observed": metrics["brier_skill_vs_prevalence"]["lower"], "status": "pass"},
		{"id": "observed_expected_low", "kind": "calibration", "metric": "observed_to_expected_ratio", "bound": "point", "op": ">=", "threshold": 0.67, "observed": metrics["observed_to_expected_ratio"]["point"], "status": "pass"},
		{"id": "observed_expected_high", "kind": "calibration", "metric": "observed_to_expected_ratio", "bound": "point", "op": "<=", "threshold": 1.5, "observed": metrics["observed_to_expected_ratio"]["point"], "status": "pass"},
		{"id": "calibration_slope_low", "kind": "calibration", "metric": "calibration_slope", "bound": "point", "op": ">=", "threshold": 0.7, "observed": metrics["calibration_slope"]["point"], "status": "pass"},
		{"id": "calibration_slope_high", "kind": "calibration", "metric": "calibration_slope", "bound": "point", "op": "<=", "threshold": 1.3, "observed": metrics["calibration_slope"]["point"], "status": "pass"},
		{"id": "event_recall_point", "kind": "horizon", "metric": "event_recall_within_horizon", "bound": "point", "op": ">=", "threshold": 0.30, "observed": metrics["event_recall_within_horizon"]["point"], "status": "pass"},
		{"id": "event_recall_lower", "kind": "horizon", "metric": "event_recall_within_horizon", "bound": "lower", "op": ">=", "threshold": 0.15, "observed": metrics["event_recall_within_horizon"]["lower"], "status": "pass"},
		{"id": "median_lead_time", "kind": "horizon", "metric": "median_first_alert_lead_days", "bound": "point", "op": ">=", "threshold": 2.0, "observed": metrics["median_first_alert_lead_days"]["point"], "status": "pass"},
	}
	return map[string]any{
		"schema_version":                 health.EvaluationReportV1Version,
		"policy_sha256":                  health.ML05PolicySHA256,
		"partition_manifest_sha256":      health.ML01PartitionManifestSHA256,
		"partition":                      "test",
		"horizon_hours":                  health.ML05HorizonHours,
		"test_evaluations_for_candidate": 1,
		"label_status":                   "both_classes_present",
		"evaluation_error":               "",
		"bootstrap": map[string]any{
			"unit":       "device",
			"replicates": 2000,
			"seed":       86,
			"interval":   0.95,
			"method":     "percentile",
		},
		"model": map[string]any{
			"version":         manifest.ModelVersion,
			"artifact_sha256": manifest.ArtifactSHA256,
		},
		"counts": map[string]any{
			"test_positive_events":        35,
			"test_positive_windows":       120,
			"test_negative_windows":       12000,
			"test_devices":                1200,
			"validation_negative_windows": 12000,
		},
		"metrics":                   metrics,
		"partition_examples_sha256": map[string]any{"test": strings.Repeat("7", 64)},
		"operating_points": map[string]any{
			"degraded_logit": degradedLogit,
			"critical_logit": criticalLogit,
		},
		"gate": map[string]any{
			"schema_version":   health.EvaluationGateV1Version,
			"status":           "pass",
			"policy_sha256":    health.ML05PolicySHA256,
			"blocking_reasons": []string{},
			"checks":           checks,
			"model": map[string]any{
				"version":         manifest.ModelVersion,
				"artifact_sha256": manifest.ArtifactSHA256,
			},
		},
	}
}

func marshalEvaluation(t *testing.T, m map[string]any) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sha256Hex(raw)
}

func i64(v int64) *int64 { return &v }

func completeWeekReadings(anchor time.Time) []health.SMARTReading {
	return smartWeekReadings(anchor, []int64{0, 0, 0, 0, 8, 8, 16})
}

func healthyWeekReadings(anchor time.Time) []health.SMARTReading {
	return smartWeekReadings(anchor, []int64{0, 0, 0, 0, 0, 0, 0})
}

func smartWeekReadings(anchor time.Time, smart5 []int64) []health.SMARTReading {
	day := time.Date(anchor.Year(), anchor.Month(), anchor.Day(), 12, 0, 0, 0, time.UTC)
	smart9 := []int64{11000, 11024, 11048, 11072, 11096, 11120, 11144}
	smart197 := []int64{0, 0, 0, 0, 0, 0, 0}
	out := make([]health.SMARTReading, 7)
	for i := range 7 {
		out[i] = health.SMARTReading{
			ObservedAt:  day.AddDate(0, 0, i-6),
			SMART5Raw:   i64(smart5[i]),
			SMART9Raw:   i64(smart9[i]),
			SMART197Raw: i64(smart197[i]),
		}
	}
	return out
}

func allSampleDays(asOf time.Time, totalDays int) []time.Time {
	endDay := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 12, 0, 0, 0, time.UTC)
	days := make([]time.Time, totalDays)
	for i := range totalDays {
		days[i] = endDay.AddDate(0, 0, -(totalDays - 1 - i))
	}
	return days
}

func TestControllerInferenceRuntimeCompatibility(t *testing.T) {
	ctrl := health.ControllerInferenceRuntime()
	endp := health.EndpointInferenceRuntime()
	if ctrl.Name != "device-audit-controller-go" || ctrl.Name == endp.Name {
		t.Fatalf("unexpected runtimes: controller=%+v endpoint=%+v", ctrl, endp)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub := key.Public().(ed25519.PublicKey)
	artifact := loadRealBaselineArtifact(t)

	endpManifest := signTestManifest(t, key, artifact, endp, contracts.ModelPurposeInference)
	report, digest := marshalEvaluation(t, buildPassingEvaluationMap(endpManifest, 0.0, 1.0))

	if _, err := health.LoadControllerModel(endpManifest, artifact, pub, report, digest); !errors.Is(err, contracts.ModelRejectionRuntimeMismatch) {
		t.Fatalf("expected ModelRejectionRuntimeMismatch for endpoint manifest on controller, got %v", err)
	}
	if _, err := health.VerifyEvaluatedModel(endpManifest, artifact, pub, endp, report, digest); err != nil {
		t.Fatalf("VerifyEvaluatedModel for endpoint runtime failed: %v", err)
	}
}

func TestVerifyEvaluationReportAndRealBaselineModel(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	pub := key.Public().(ed25519.PublicKey)
	artifact := loadRealBaselineArtifact(t)
	manifest := signTestManifest(t, key, artifact, health.ControllerInferenceRuntime(), contracts.ModelPurposeInference)

	// Real ML06 failed report must never be accepted.
	failedReport := loadRealFailedEvaluationReport(t)
	if _, err := health.VerifyEvaluationReport(failedReport, sha256Hex(failedReport), manifest); !errors.Is(err, health.ErrEvaluationRejected) {
		t.Fatalf("expected ML06 failed report to be rejected, got %v", err)
	}
	if _, err := health.LoadControllerModel(manifest, artifact, pub, failedReport, sha256Hex(failedReport)); !errors.Is(err, health.ErrEvaluationRejected) {
		t.Fatalf("expected LoadControllerModel to reject failed ML06 report, got %v", err)
	}

	// Forged pass status with a failing metric must still be rejected by direct ML05 gate checks.
	forged := buildPassingEvaluationMap(manifest, 0.0, 1.0)
	forgedMetrics := forged["metrics"].(map[string]map[string]float64)
	forgedMetrics["brier_skill_vs_prevalence"] = map[string]float64{"point": 0.02, "lower": -0.01, "upper": 0.05}
	for _, check := range forged["gate"].(map[string]any)["checks"].([]map[string]any) {
		if check["metric"] == "brier_skill_vs_prevalence" {
			check["observed"] = -0.01
		}
	}
	forgedBytes, forgedDigest := marshalEvaluation(t, forged)
	if _, err := health.VerifyEvaluationReport(forgedBytes, forgedDigest, manifest); !errors.Is(err, health.ErrEvaluationRejected) {
		t.Fatalf("expected forged passing status over failing metric to be rejected, got %v", err)
	}

	// Systematic rejection table for tampered evaluation reports.
	rejectCases := []struct {
		name   string
		mutate func(map[string]any) ([]byte, string)
	}{
		{"bad expected sha256", func(m map[string]any) ([]byte, string) {
			b, _ := marshalEvaluation(t, m)
			return b, "not-a-sha"
		}},
		{"digest mismatch", func(m map[string]any) ([]byte, string) {
			b, _ := marshalEvaluation(t, m)
			return b, strings.Repeat("0", 64)
		}},
		{"empty body", func(map[string]any) ([]byte, string) {
			return nil, sha256Hex(nil)
		}},
		{"trailing garbage", func(m map[string]any) ([]byte, string) {
			b, _ := marshalEvaluation(t, m)
			b = append(b, []byte("{}")...)
			return b, sha256Hex(b)
		}},
		{"wrong schema version", func(m map[string]any) ([]byte, string) {
			m["schema_version"] = "other"
			return marshalEvaluation(t, m)
		}},
		{"wrong policy sha", func(m map[string]any) ([]byte, string) {
			m["policy_sha256"] = strings.Repeat("a", 64)
			return marshalEvaluation(t, m)
		}},
		{"wrong partition manifest", func(m map[string]any) ([]byte, string) {
			m["partition_manifest_sha256"] = strings.Repeat("b", 64)
			return marshalEvaluation(t, m)
		}},
		{"non test partition", func(m map[string]any) ([]byte, string) {
			m["partition"] = "validation"
			return marshalEvaluation(t, m)
		}},
		{"wrong horizon hours", func(m map[string]any) ([]byte, string) {
			m["horizon_hours"] = 24
			return marshalEvaluation(t, m)
		}},
		{"multiple test evaluations", func(m map[string]any) ([]byte, string) {
			m["test_evaluations_for_candidate"] = 2
			return marshalEvaluation(t, m)
		}},
		{"missing class labels", func(m map[string]any) ([]byte, string) {
			m["label_status"] = "single_class"
			return marshalEvaluation(t, m)
		}},
		{"non-empty evaluation error", func(m map[string]any) ([]byte, string) {
			m["evaluation_error"] = "failed"
			return marshalEvaluation(t, m)
		}},
		{"mismatched artifact digest", func(m map[string]any) ([]byte, string) {
			m["model"] = map[string]any{"version": manifest.ModelVersion, "artifact_sha256": strings.Repeat("c", 64)}
			return marshalEvaluation(t, m)
		}},
		{"wrong bootstrap replicates", func(m map[string]any) ([]byte, string) {
			m["bootstrap"].(map[string]any)["replicates"] = 500
			return marshalEvaluation(t, m)
		}},
		{"ROC AUC above one", func(m map[string]any) ([]byte, string) {
			m["metrics"].(map[string]map[string]float64)["roc_auc"]["upper"] = 1.01
			return marshalEvaluation(t, m)
		}},
		{"insufficient test positive events", func(m map[string]any) ([]byte, string) {
			m["counts"].(map[string]any)["test_positive_events"] = 29
			return marshalEvaluation(t, m)
		}},
		{"insufficient validation negative windows", func(m map[string]any) ([]byte, string) {
			m["counts"].(map[string]any)["validation_negative_windows"] = 9999
			return marshalEvaluation(t, m)
		}},
		{"calibration slope above max", func(m map[string]any) ([]byte, string) {
			metrics := m["metrics"].(map[string]map[string]float64)
			metrics["calibration_slope"] = map[string]float64{"point": 1.35, "lower": 1.2, "upper": 1.5}
			checks := m["gate"].(map[string]any)["checks"].([]map[string]any)
			for _, c := range checks {
				if c["metric"] == "calibration_slope" {
					c["observed"] = 1.35
				}
			}
			return marshalEvaluation(t, m)
		}},
		{"missing gate check", func(m map[string]any) ([]byte, string) {
			checks := m["gate"].(map[string]any)["checks"].([]map[string]any)
			m["gate"].(map[string]any)["checks"] = checks[:len(checks)-1]
			return marshalEvaluation(t, m)
		}},
		{"tampered gate check observed", func(m map[string]any) ([]byte, string) {
			checks := m["gate"].(map[string]any)["checks"].([]map[string]any)
			checks[0]["observed"] = 0.999
			return marshalEvaluation(t, m)
		}},
		{"reversed operating points", func(m map[string]any) ([]byte, string) {
			m["operating_points"] = map[string]any{"degraded_logit": 0.5, "critical_logit": -0.5}
			return marshalEvaluation(t, m)
		}},
	}
	for _, tc := range rejectCases {
		t.Run(tc.name, func(t *testing.T) {
			raw, exp := tc.mutate(buildPassingEvaluationMap(manifest, 0.0, 1.0))
			if _, err := health.VerifyEvaluationReport(raw, exp, manifest); !errors.Is(err, health.ErrEvaluationRejected) {
				t.Fatalf("expected ErrEvaluationRejected for %s, got %v", tc.name, err)
			}
		})
	}

	// Model bundle verification and numerical parity with Python CT03 baseline.
	passingBytes, passingDigest := marshalEvaluation(t, buildPassingEvaluationMap(manifest, 0.0, 2.0))
	if _, err := health.LoadControllerModel(manifest, artifact, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{99}, 32)).Public().(ed25519.PublicKey), passingBytes, passingDigest); !errors.Is(err, contracts.ModelRejectionKeyMismatch) {
		t.Fatalf("expected key mismatch, got %v", err)
	}
	trainingManifest := signTestManifest(t, key, artifact, health.ControllerInferenceRuntime(), contracts.ModelPurposeTraining)
	if _, err := health.LoadControllerModel(trainingManifest, artifact, pub, passingBytes, passingDigest); !errors.Is(err, contracts.ModelRejectionPurposeUnsupported) {
		t.Fatalf("expected unsupported purpose, got %v", err)
	}

	model, err := health.LoadControllerModel(manifest, artifact, pub, passingBytes, passingDigest)
	if err != nil {
		t.Fatalf("LoadControllerModel failed: %v", err)
	}
	asOf := time.Date(2013, 11, 7, 23, 59, 59, 0, time.UTC)
	healthyVec, err := health.Preprocess(asOf, healthyWeekReadings(asOf))
	if err != nil {
		t.Fatalf("Preprocess healthy failed: %v", err)
	}
	healthyPred, err := model.Predict(healthyVec)
	if err != nil {
		t.Fatalf("Predict healthy failed: %v", err)
	}
	const wantHealthyProb = 0.24889408556703072
	if math.Abs(healthyPred.Probability-wantHealthyProb) >= 1e-12 {
		t.Fatalf("healthy probability %.17f differs from Python %.17f", healthyPred.Probability, wantHealthyProb)
	}
	if healthyPred.Status != health.HealthStatusHealthy || healthyPred.HorizonHours != 168 ||
		healthyPred.Model.Version != manifest.ModelVersion || healthyPred.Model.SHA256 != manifest.ArtifactSHA256 {
		t.Fatalf("unexpected healthy prediction: %+v", healthyPred)
	}

	degradedVec, err := health.Preprocess(asOf, completeWeekReadings(asOf))
	if err != nil {
		t.Fatalf("Preprocess complete week failed: %v", err)
	}
	degradedPred, err := model.Predict(degradedVec)
	if err != nil {
		t.Fatalf("Predict degraded failed: %v", err)
	}
	const wantDegradedProb = 0.79956738641351921
	if math.Abs(degradedPred.Probability-wantDegradedProb) >= 1e-12 {
		t.Fatalf("degraded probability %.17f differs from Python %.17f", degradedPred.Probability, wantDegradedProb)
	}
	if degradedPred.Status != health.HealthStatusDegraded {
		t.Fatalf("expected degraded model prediction, got %+v", degradedPred)
	}

	criticalBytes, criticalDigest := marshalEvaluation(t, buildPassingEvaluationMap(manifest, 0.0, 1.0))
	criticalModel, err := health.LoadControllerModel(manifest, artifact, pub, criticalBytes, criticalDigest)
	if err != nil {
		t.Fatal(err)
	}
	criticalPred, err := criticalModel.Predict(degradedVec)
	if err != nil || criticalPred.Status != health.HealthStatusCritical {
		t.Fatalf("expected critical model prediction, got pred=%+v err=%v", criticalPred, err)
	}
}

func TestAssessHealthRules(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{15}, 32))
	pub := key.Public().(ed25519.PublicKey)
	artifact := loadRealBaselineArtifact(t)
	manifest := signTestManifest(t, key, artifact, health.ControllerInferenceRuntime(), contracts.ModelPurposeInference)

	loadModel := func(degradedLogit, criticalLogit float64) *health.EvaluatedModel {
		t.Helper()
		b, d := marshalEvaluation(t, buildPassingEvaluationMap(manifest, degradedLogit, criticalLogit))
		m, err := health.LoadControllerModel(manifest, artifact, pub, b, d)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	model := loadModel(0.0, 2.0)
	criticalThresholdModel := loadModel(0.0, 1.0)

	asOf := time.Date(2013, 11, 7, 23, 59, 59, 0, time.UTC)
	healthyVec, err := health.Preprocess(asOf, healthyWeekReadings(asOf))
	if err != nil {
		t.Fatal(err)
	}
	degradedVec, err := health.Preprocess(asOf, completeWeekReadings(asOf))
	if err != nil {
		t.Fatal(err)
	}
	telemetryBytes, err := os.ReadFile(filepath.Join("..", "..", "packages", "contracts", "fixtures", "telemetry", "v2-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var tv struct {
		Vectors []struct {
			Valid     bool            `json:"valid"`
			Telemetry json.RawMessage `json:"telemetry"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(telemetryBytes, &tv); err != nil {
		t.Fatal(err)
	}
	var realSample contracts.TelemetryV2
	if err := json.Unmarshal(tv.Vectors[0].Telemetry, &realSample); err != nil {
		t.Fatal(err)
	}
	realSample.CollectedAt = asOf.Add(-10 * time.Minute)
	incompleteVec, err := health.Preprocess(asOf, []health.SMARTReading{health.ReadingFromTelemetry(realSample)})
	if err != nil {
		t.Fatal(err)
	}

	freshEvidence := &health.EvidenceSummary{
		Sequence:               29,
		CollectedAt:            asOf.Add(-10 * time.Minute),
		PayloadSHA256:          strings.Repeat("a", 64),
		TelemetrySchemaVersion: contracts.TelemetryV2Version,
	}

	buildHistory := func(totalDays int, reports []health.FaultReport) *health.FaultHistory {
		t.Helper()
		h, err := health.CompareFaultHistory(asOf, health.FaultEvidence{
			SampleDays: allSampleDays(asOf, totalDays),
			Reports:    reports,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &h
	}

	day := func(offsetDays int) time.Time {
		return time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 12, 0, 0, 0, time.UTC).AddDate(0, 0, offsetDays)
	}

	cleanHistory := buildHistory(28, nil)
	isolatedHistory := buildHistory(28, []health.FaultReport{
		{Type: "unclassified", ReportedAt: day(-1), EvidenceSHA256: strings.Repeat("1", 64), Sequence: 28},
	})
	baselineOnlyHistory := buildHistory(28, []health.FaultReport{
		{Type: "unclassified", ReportedAt: day(-14), EvidenceSHA256: strings.Repeat("2", 64), Sequence: 15},
	})
	recurrentSteadyHistory := buildHistory(28, []health.FaultReport{
		{Type: "unclassified", ReportedAt: day(-20), EvidenceSHA256: strings.Repeat("3", 64), Sequence: 9},
		{Type: "unclassified", ReportedAt: day(-15), EvidenceSHA256: strings.Repeat("4", 64), Sequence: 14},
		{Type: "unclassified", ReportedAt: day(-10), EvidenceSHA256: strings.Repeat("5", 64), Sequence: 19},
		{Type: "unclassified", ReportedAt: day(-1), EvidenceSHA256: strings.Repeat("6", 64), Sequence: 28},
	})
	recurrentIncreasedHistory := buildHistory(28, []health.FaultReport{
		{Type: "unclassified", ReportedAt: day(-15), EvidenceSHA256: strings.Repeat("7", 64), Sequence: 14},
		{Type: "unclassified", ReportedAt: day(-3), EvidenceSHA256: strings.Repeat("8", 64), Sequence: 26},
		{Type: "unclassified", ReportedAt: day(-2), EvidenceSHA256: strings.Repeat("9", 64), Sequence: 27},
		{Type: "unclassified", ReportedAt: day(-1), EvidenceSHA256: strings.Repeat("a", 64), Sequence: 28},
	})
	insufficientBaselineHistory := buildHistory(7, nil)
	insufficientHistoryFault := buildHistory(7, []health.FaultReport{
		{Type: "unclassified", ReportedAt: day(-1), EvidenceSHA256: strings.Repeat("b", 64), Sequence: 7},
	})
	insufficientCurrentHistory := buildHistory(3, nil)

	const wantHealthyProb = 0.24889408556703072
	const wantDegradedProb = 0.79956738641351921

	tests := []struct {
		name          string
		input         health.AssessmentInput
		wantStatus    string
		wantReason    string
		wantRule      string
		wantModelRef  bool
		wantProb      float64
		wantNoPred    bool
		wantFaultNote string
	}{
		{
			name:          "healthy model + clean sufficient baseline",
			input:         health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: cleanHistory},
			wantStatus:    health.HealthStatusHealthy,
			wantRule:      "model_healthy_with_sufficient_baseline",
			wantModelRef:  true,
			wantProb:      wantHealthyProb,
			wantFaultNote: "no_log_references_observed_in_sufficient_windows",
		},
		{
			name:         "healthy model + isolated fault",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: isolatedHistory},
			wantStatus:   health.HealthStatusHealthy,
			wantRule:     "model_healthy_with_isolated_fault",
			wantModelRef: true,
			wantProb:     wantHealthyProb,
		},
		{
			name:         "healthy model + baseline-only fault",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: baselineOnlyHistory},
			wantStatus:   health.HealthStatusHealthy,
			wantRule:     "model_healthy_with_baseline_only_fault",
			wantModelRef: true,
			wantProb:     wantHealthyProb,
		},
		{
			name:         "healthy model + recurrent fault escalates to degraded",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: recurrentIncreasedHistory},
			wantStatus:   health.HealthStatusDegraded,
			wantRule:     "model_healthy_escalated_by_recurrent_faults",
			wantModelRef: true,
			wantProb:     wantHealthyProb,
		},
		{
			name:         "degraded model + non-increasing recurrent faults stays degraded",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &degradedVec, FaultHistory: recurrentSteadyHistory},
			wantStatus:   health.HealthStatusDegraded,
			wantRule:     "model_degraded_with_recurrent_faults",
			wantModelRef: true,
			wantProb:     wantDegradedProb,
		},
		{
			name:         "degraded model + increasing recurrent faults escalates to critical",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &degradedVec, FaultHistory: recurrentIncreasedHistory},
			wantStatus:   health.HealthStatusCritical,
			wantRule:     "model_degraded_escalated_by_increasing_recurrent_faults",
			wantModelRef: true,
			wantProb:     wantDegradedProb,
		},
		{
			name:         "critical model + clean history stays critical",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: criticalThresholdModel, LatestEvidence: freshEvidence, Features: &degradedVec, FaultHistory: cleanHistory},
			wantStatus:   health.HealthStatusCritical,
			wantRule:     "model_critical",
			wantModelRef: true,
			wantProb:     wantDegradedProb,
		},
		{
			name:          "healthy model + insufficient fault baseline stays unknown without invented risk",
			input:         health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: insufficientBaselineHistory},
			wantStatus:    health.HealthStatusUnknown,
			wantReason:    health.UnknownReasonInsufficientEvidence,
			wantRule:      "insufficient_fault_baseline_for_healthy",
			wantModelRef:  true,
			wantFaultNote: "missing days are unobserved",
		},
		{
			name:         "healthy model + insufficient history fault stays unknown",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: insufficientHistoryFault},
			wantStatus:   health.HealthStatusUnknown,
			wantReason:   health.UnknownReasonInsufficientEvidence,
			wantRule:     "insufficient_fault_history_for_healthy",
			wantModelRef: true,
		},
		{
			name:         "insufficient current fault window stays unknown",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: criticalThresholdModel, LatestEvidence: freshEvidence, Features: &degradedVec, FaultHistory: insufficientCurrentHistory},
			wantStatus:   health.HealthStatusUnknown,
			wantReason:   health.UnknownReasonInsufficientEvidence,
			wantRule:     "insufficient_current_fault_window",
			wantModelRef: true,
		},
		{
			name:         "real telemetry v2 incomplete SMART vector yields unknown",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &incompleteVec, FaultHistory: cleanHistory},
			wantStatus:   health.HealthStatusUnknown,
			wantReason:   health.UnknownReasonInsufficientEvidence,
			wantRule:     "incomplete_feature_vector",
			wantModelRef: true,
		},
		{
			name:         "stale evidence at 1h boundary yields stale_evidence",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: &health.EvidenceSummary{Sequence: 29, CollectedAt: asOf.Add(-time.Hour), PayloadSHA256: freshEvidence.PayloadSHA256, TelemetrySchemaVersion: contracts.TelemetryV2Version}, Features: &healthyVec, FaultHistory: cleanHistory},
			wantStatus:   health.HealthStatusUnknown,
			wantReason:   health.UnknownReasonStaleEvidence,
			wantRule:     "stale_telemetry_evidence",
			wantModelRef: true,
		},
		{
			name:         "evidence ahead of asOf yields stale_evidence",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: &health.EvidenceSummary{Sequence: 29, CollectedAt: asOf.Add(time.Second), PayloadSHA256: freshEvidence.PayloadSHA256, TelemetrySchemaVersion: contracts.TelemetryV2Version}, Features: &healthyVec, FaultHistory: cleanHistory},
			wantStatus:   health.HealthStatusUnknown,
			wantReason:   health.UnknownReasonStaleEvidence,
			wantRule:     "stale_telemetry_evidence",
			wantModelRef: true,
		},
		{
			name:         "59m59s evidence stays fresh",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: &health.EvidenceSummary{Sequence: 29, CollectedAt: asOf.Add(-59*time.Minute - 59*time.Second), PayloadSHA256: freshEvidence.PayloadSHA256, TelemetrySchemaVersion: contracts.TelemetryV2Version}, Features: &healthyVec, FaultHistory: cleanHistory},
			wantStatus:   health.HealthStatusHealthy,
			wantRule:     "model_healthy_with_sufficient_baseline",
			wantModelRef: true,
			wantProb:     wantHealthyProb,
		},
		{
			name:         "missing latest evidence yields unknown without fabricated prediction",
			input:        health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: nil, Features: &incompleteVec, FaultHistory: cleanHistory},
			wantStatus:   health.HealthStatusUnknown,
			wantReason:   health.UnknownReasonInsufficientEvidence,
			wantRule:     "no_telemetry_evidence",
			wantModelRef: true,
			wantNoPred:   true,
		},
		{
			name:       "model unavailable omits model reference and numeric risk",
			input:      health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: nil, ModelFailure: health.ErrEvaluationRejected, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: cleanHistory},
			wantStatus: health.HealthStatusUnknown,
			wantReason: health.UnknownReasonModelUnavailable,
			wantRule:   "model_unavailable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := health.AssessHealth(tc.input)
			if err != nil {
				t.Fatalf("AssessHealth unexpected error: %v", err)
			}
			if got.RulesVersion != health.HealthRulesVersion {
				t.Fatalf("rules version %q != %q", got.RulesVersion, health.HealthRulesVersion)
			}
			if got.Health.Status != tc.wantStatus || got.Health.UnknownReason != tc.wantReason || got.RuleReason != tc.wantRule {
				t.Fatalf("got status=%q reason=%q rule=%q; want status=%q reason=%q rule=%q",
					got.Health.Status, got.Health.UnknownReason, got.RuleReason, tc.wantStatus, tc.wantReason, tc.wantRule)
			}
			if tc.wantModelRef {
				if got.Model == nil || got.Model.Version != manifest.ModelVersion || got.PolicyVersion != health.ML05PolicyVersion {
					t.Fatalf("expected model & policy attribution, got model=%+v policy=%q", got.Model, got.PolicyVersion)
				}
			} else if got.Model != nil {
				t.Fatalf("expected nil model reference, got %+v", got.Model)
			}
			if tc.wantProb > 0 {
				if got.Health.Probability == nil || got.Health.HorizonHours == nil {
					t.Fatalf("expected probability and horizon, got prob=%v horizon=%v", got.Health.Probability, got.Health.HorizonHours)
				}
				if !(math.Abs(*got.Health.Probability-tc.wantProb) < 1e-12) || *got.Health.HorizonHours != 168 {
					t.Fatalf("unexpected prob/horizon: %v (want %.17f) / %v", *got.Health.Probability, tc.wantProb, *got.Health.HorizonHours)
				}
			} else if got.Health.Probability != nil || got.Health.HorizonHours != nil {
				t.Fatalf("expected nil probability & horizon for unknown status, got prob=%v horizon=%v", got.Health.Probability, got.Health.HorizonHours)
			}
			if tc.wantNoPred {
				if got.Prediction != nil {
					t.Fatalf("expected nil prediction when no evidence exists, got %+v", got.Prediction)
				}
			} else {
				if got.Prediction == nil {
					t.Fatal("expected non-nil PredictionV2")
				}
				if err := got.Prediction.Validate(); err != nil {
					t.Fatalf("PredictionV2 failed contract validation: %v", err)
				}
				if tc.wantProb > 0 && !got.Prediction.ExpiresAt.Equal(tc.input.LatestEvidence.CollectedAt.Add(health.MaxEvidenceAge)) {
					t.Fatalf("prediction outlives freshness window: %v", got.Prediction.ExpiresAt)
				}
				if len(got.Prediction.Forecasts) != 0 {
					t.Fatalf("expected empty forecasts without horizon model, got %d", len(got.Prediction.Forecasts))
				}
			}
			if tc.wantFaultNote != "" && !strings.Contains(got.FaultObservationNote, tc.wantFaultNote) {
				t.Fatalf("fault note %q does not contain %q", got.FaultObservationNote, tc.wantFaultNote)
			}
			if tc.input.Features != nil {
				if got.Features == nil || got.Features.FeatureVersion != tc.input.Features.FeatureVersion ||
					got.Features.WindowStart != tc.input.Features.WindowStart ||
					got.Features.WindowEnd != tc.input.Features.WindowEnd ||
					got.Features.Status != tc.input.Features.Status ||
					got.Features.FeatureCount != len(tc.input.Features.Features) {
					t.Fatalf("unexpected feature provenance: %+v", got.Features)
				}
			}
			if tc.input.FaultHistory != nil {
				if got.CurrentFaultWindow == nil || got.BaselineFaultWindow == nil ||
					got.CurrentFaultWindow.SampledDays != tc.input.FaultHistory.Current.SampledDays ||
					got.BaselineFaultWindow.SampledDays != tc.input.FaultHistory.Baseline.SampledDays {
					t.Fatalf("unexpected fault window provenance: current=%+v baseline=%+v", got.CurrentFaultWindow, got.BaselineFaultWindow)
				}
			}
		})
	}

	// Verify model status attribution when model scores successfully despite insufficient current fault window.
	res, err := health.AssessHealth(health.AssessmentInput{
		DeviceID: "device:a", AsOf: asOf, Model: criticalThresholdModel, LatestEvidence: freshEvidence, Features: &degradedVec, FaultHistory: insufficientCurrentHistory,
	})
	if err != nil || res.ModelStatus != health.HealthStatusCritical || res.Health.Status != health.HealthStatusUnknown {
		t.Fatalf("expected model_status=critical with final status=unknown, got model=%q status=%q err=%v", res.ModelStatus, res.Health.Status, err)
	}

	// Invalid arguments and misaligned windows fail explicitly.
	if _, err := health.AssessHealth(health.AssessmentInput{DeviceID: "bad id", AsOf: asOf}); err == nil {
		t.Fatal("expected invalid device_id error")
	}
	if _, err := health.AssessHealth(health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, MaxEvidenceAge: -time.Second}); err == nil {
		t.Fatal("expected negative max_evidence_age error")
	}
	wrongAsOf := asOf.AddDate(0, 0, -1)
	wrongVec, err := health.Preprocess(wrongAsOf, completeWeekReadings(wrongAsOf))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := health.AssessHealth(health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &wrongVec, FaultHistory: cleanHistory}); err == nil {
		t.Fatal("expected mismatched feature window error")
	}
	wrongHist, err := health.CompareFaultHistory(wrongAsOf, health.FaultEvidence{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := health.AssessHealth(health.AssessmentInput{DeviceID: "device:a", AsOf: asOf, Model: model, LatestEvidence: freshEvidence, Features: &healthyVec, FaultHistory: &wrongHist}); err == nil {
		t.Fatal("expected mismatched fault window error")
	}
}
