package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func loadBaselineModelBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "models", "baseline", "backblaze-2013", "artifact.json"))
	if err != nil {
		t.Fatalf("read baseline artifact: %v", err)
	}
	return data
}

func loadML06FailedBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "models", "evaluation", "results", "logistic-baseline.backblaze-2013.v1.json"))
	if err != nil {
		t.Fatalf("read ML06 report: %v", err)
	}
	return data
}

func sha256DigestHex(data []byte) string {
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

func artifactWithVersion(t *testing.T, baseArtifact []byte, version string) []byte {
	t.Helper()
	var doc map[string]any
	if err := json.Unmarshal(baseArtifact, &doc); err != nil {
		t.Fatal(err)
	}
	doc["model_version"] = version
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func buildSignedControllerManifest(t *testing.T, key ed25519.PrivateKey, artifact []byte, runtime contracts.ModelRuntimeV1) contracts.ModelManifestV1 {
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
		ArtifactSHA256: sha256DigestHex(artifact),
		Architecture:   "logistic-baseline.v1",
		ParameterCount: uint32(len(features) + 1),
		RuntimeName:    runtime.Name,
		RuntimeVersion: runtime.Version,
		FeatureVersion: contracts.FeatureVersionHDDSMART7DV1,
		Features:       features,
		Purposes:       []string{contracts.ModelPurposeInference},
		SigningKeyID:   keyID,
	}
	msg, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(key, msg))
	return m
}

func buildPassingML05Report(t *testing.T, manifest contracts.ModelManifestV1, degradedLogit, criticalLogit float64) ([]byte, string) {
	t.Helper()
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
	report := map[string]any{
		"schema_version":                 health.EvaluationReportV1Version,
		"policy_sha256":                  health.ML05PolicySHA256,
		"partition_manifest_sha256":      health.ML01PartitionManifestSHA256,
		"partition":                      "test",
		"horizon_hours":                  health.ML05HorizonHours,
		"test_evaluations_for_candidate": 1,
		"label_status":                   "both_classes_present",
		"evaluation_error":               "",
		"bootstrap": map[string]any{
			"unit": "device", "replicates": 2000, "seed": 86, "interval": 0.95, "method": "percentile",
		},
		"model": map[string]any{
			"version": manifest.ModelVersion, "artifact_sha256": manifest.ArtifactSHA256,
		},
		"counts": map[string]any{
			"test_positive_events": 35, "test_positive_windows": 120, "test_negative_windows": 12000,
			"test_devices": 1200, "validation_negative_windows": 12000,
		},
		"metrics":                   metrics,
		"partition_examples_sha256": map[string]string{"test": strings.Repeat("7", 64)},
		"operating_points":          map[string]any{"degraded_logit": degradedLogit, "critical_logit": criticalLogit},
		"gate": map[string]any{
			"schema_version": health.EvaluationGateV1Version, "status": "pass",
			"policy_sha256": health.ML05PolicySHA256, "blocking_reasons": []string{},
			"checks": checks,
			"model":  map[string]any{"version": manifest.ModelVersion, "artifact_sha256": manifest.ArtifactSHA256},
		},
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sha256DigestHex(raw)
}

func writeEvalReportFile(t *testing.T, dir, digest string, content []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, digest+".json"), content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func registerAndActivateModel(t *testing.T, repo *PostgresRepository, publisher ed25519.PrivateKey, artifact []byte, runtime contracts.ModelRuntimeV1, evalDigest, policyVersion string) contracts.ModelManifestV1 {
	t.Helper()
	ctx := context.Background()
	pub := publisher.Public().(ed25519.PublicKey)
	actor := contracts.ModelActorV1{Issuer: "console:local", Subject: "admin@example.com"}
	manifest := buildSignedControllerManifest(t, publisher, artifact, runtime)
	version := manifest.ModelVersion
	up := contracts.ModelArtifactUploadV1{
		SchemaVersion:   contracts.ModelArtifactUploadV1Version,
		Manifest:        manifest,
		Artifact:        artifact,
		SourceReference: "eval-run:" + version,
	}
	if _, _, err := repo.PutModelArtifact(ctx, up, pub, actor); err != nil {
		t.Fatalf("PutModelArtifact %s: %v", version, err)
	}
	approveWithoutEvaluationGate(t, repo, version, manifest.ArtifactSHA256, evalDigest, policyVersion)
	if _, err := repo.SetModelReference(ctx, contracts.ModelSlotActive, contracts.ModelReferenceRequestV1{
		SchemaVersion:  contracts.ModelReferenceRequestV1Version,
		ModelVersion:   version,
		ArtifactSHA256: manifest.ArtifactSHA256,
	}, actor); err != nil {
		t.Fatalf("SetModelReference %s: %v", version, err)
	}
	return manifest
}

func enrollTestDevice(t *testing.T, b *enrollmentTestBed, device string) enrollmentKeys {
	t.Helper()
	keys := newEnrollmentKeys(t)
	token := b.issue(t, device)
	challenge := b.challenge(t, token, keys)
	adm := admissionForChallenge(t, b.clock, challenge, keys)
	signAdmission(t, &adm, keys.signing)
	b.submit(t, token, adm, http.StatusCreated)
	return keys
}

func acceptTelemetrySample(t *testing.T, b *enrollmentTestBed, device string, keys enrollmentKeys, seq uint64, collected time.Time, logRefs []contracts.LogReferenceV2) string {
	t.Helper()
	if delta := collected.Sub(b.clock.Now()); delta > 0 {
		b.clock.Advance(delta)
	}
	if logRefs == nil {
		logRefs = []contracts.LogReferenceV2{}
	}
	cpuVal, memVal := 21.5, 48.0
	payloadBytes, err := json.Marshal(contracts.TelemetryV2{
		SchemaVersion: contracts.TelemetryV2Version,
		DeviceID:      device,
		CollectedAt:   collected.UTC(),
		Source:        "endpoint",
		Metrics: contracts.MetricsV2{
			CPUUtilization: &contracts.MetricV2{Value: &cpuVal, Unit: "percent"},
			MemoryPercent:  &contracts.MetricV2{Value: &memVal, Unit: "percent"},
		},
		Inventory:     contracts.InventoryV2{Components: []contracts.ComponentV2{}},
		LogReferences: logRefs,
	})
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := contracts.SigningKeyIDV1(keys.signing.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	issued := b.clock.Now().UTC()
	env := contracts.EvidenceEnvelopeV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.EvidenceEnvelopeV1Version,
			DeploymentID:  b.repo.deploymentID,
			DeviceID:      device,
			SigningKeyID:  keyID,
			Sequence:      seq,
			IssuedAt:      issued.Format(time.RFC3339),
			ExpiresAt:     issued.Add(time.Hour).Format(time.RFC3339),
		},
		PayloadSchemaVersion: contracts.TelemetryV2Version,
		PayloadBase64:        base64.StdEncoding.EncodeToString(payloadBytes),
		PayloadSHA256:        sha256DigestHex(payloadBytes),
	}
	msg, err := env.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = hex.EncodeToString(ed25519.Sign(keys.signing, msg))
	if _, err := b.repo.AcceptEvidence(context.Background(), env); err != nil {
		t.Fatalf("AcceptEvidence seq=%d: %v", seq, err)
	}
	return env.PayloadSHA256
}

func makeSMARTMapReader(smartBySeq map[uint64][3]int64) func(evidenceRef) health.SMARTReading {
	return func(ref evidenceRef) health.SMARTReading {
		vals, ok := smartBySeq[ref.Sequence]
		if !ok {
			return health.SMARTReading{ObservedAt: ref.CollectedAt}
		}
		s5, s9, s197 := vals[0], vals[1], vals[2]
		return health.SMARTReading{
			ObservedAt:  ref.CollectedAt,
			SMART5Raw:   &s5,
			SMART9Raw:   &s9,
			SMART197Raw: &s197,
		}
	}
}

func TestEvaluateDeviceHealthEndToEnd(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	publisher := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{21}, 32))
	pubKey := publisher.Public().(ed25519.PublicKey)
	artifact := loadBaselineModelBytes(t)
	evalDir := t.TempDir()

	// Enroll all test devices before advancing the simulated test clock past the
	// initial console admin session window.
	realDev := "device:real-telemetry"
	cleanDev := "device:fixture-clean"
	faultDev := "device:fixture-faults"
	shortDev := "device:fixture-7d-only"
	realKeys := enrollTestDevice(t, b, realDev)
	cleanKeys := enrollTestDevice(t, b, cleanDev)
	faultKeys := enrollTestDevice(t, b, faultDev)
	shortKeys := enrollTestDevice(t, b, shortDev)

	day0 := b.clock.Now().UTC().Truncate(24 * time.Hour).Add(12 * time.Hour)
	latestDigest := acceptTelemetrySample(t, b, realDev, realKeys, 2, day0.Add(15*time.Minute), nil)

	healthyArtifact := artifactWithVersion(t, artifact, "baseline.healthy.v1")
	manifestV1 := buildSignedControllerManifest(t, publisher, healthyArtifact, health.ControllerInferenceRuntime())
	healthyReport, healthyEvalDigest := buildPassingML05Report(t, manifestV1, 0.0, 2.0)
	writeEvalReportFile(t, evalDir, healthyEvalDigest, healthyReport)
	registerAndActivateModel(t, b.repo, publisher, healthyArtifact, health.ControllerInferenceRuntime(), healthyEvalDigest, health.ML05PolicyVersion)

	cfg := HealthConfig{
		PublisherKey:      pubKey,
		EvaluationReports: EvaluationReportDir(evalDir),
	}
	realHealth, err := b.repo.EvaluateDeviceHealth(ctx, cfg, realDev, b.clock.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("EvaluateDeviceHealth real telemetry failed: %v", err)
	}
	if realHealth.ModelStatus != "ready" || realHealth.Assessment.Health.Status != health.HealthStatusUnknown ||
		realHealth.Assessment.Health.UnknownReason != health.UnknownReasonInsufficientEvidence ||
		realHealth.Assessment.Health.Probability != nil || realHealth.Assessment.Health.HorizonHours != nil {
		t.Fatalf("expected ready model + unknown(insufficient_evidence) for telemetry v2, got status=%q assessment=%+v",
			realHealth.ModelStatus, realHealth.Assessment)
	}
	if realHealth.Model == nil || realHealth.Model.Version != "baseline.healthy.v1" ||
		realHealth.LatestSample == nil || realHealth.LatestSample.PayloadSHA256 != latestDigest ||
		realHealth.Assessment.Prediction == nil || realHealth.Assessment.Prediction.Evidence.Digest != latestDigest {
		t.Fatalf("missing provenance on telemetry v2 result: %+v", realHealth)
	}

	// Known CT03 SMART fixture over 28 daily persisted PostgreSQL samples:
	// Days 0..20 = baseline window, days 21..27 = 7-day current window with complete SMART counters.
	startDay := b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	healthySMART7d := map[uint64][3]int64{
		23: {0, 11000, 0},
		24: {0, 11024, 0},
		25: {0, 11048, 0},
		26: {0, 11072, 0},
		27: {0, 11096, 0},
		28: {0, 11120, 0},
		29: {0, 11144, 0},
	}
	degradedSMART7d := map[uint64][3]int64{
		23: {0, 11000, 0},
		24: {0, 11024, 0},
		25: {0, 11048, 0},
		26: {0, 11072, 0},
		27: {8, 11096, 0},
		28: {8, 11120, 0},
		29: {16, 11144, 0},
	}
	for i := range 28 {
		seq := uint64(2 + i)
		acceptTelemetrySample(t, b, cleanDev, cleanKeys, seq, startDay.AddDate(0, 0, i), nil)
	}
	asOf := startDay.AddDate(0, 0, 27).Add(20 * time.Minute)
	b.clock.Advance(asOf.Sub(b.clock.Now()))

	gotHealthy, err := b.repo.evaluateDeviceHealth(ctx, cfg, cleanDev, asOf, makeSMARTMapReader(healthySMART7d))
	if err != nil {
		t.Fatalf("evaluateDeviceHealth clean fixture: %v", err)
	}
	const wantHealthyProb = 0.24889408556703072
	if gotHealthy.Assessment.Health.Status != health.HealthStatusHealthy ||
		gotHealthy.Assessment.Health.Probability == nil ||
		math.Abs(*gotHealthy.Assessment.Health.Probability-wantHealthyProb) >= 1e-12 ||
		*gotHealthy.Assessment.Health.HorizonHours != 168 {
		t.Fatalf("expected healthy fixture probability %.17f horizon 168, got %+v", wantHealthyProb, gotHealthy.Assessment)
	}

	// Stale boundary: asOf + 1h from latest sample (startDay + 27d) -> stale_evidence.
	staleHealth, err := b.repo.evaluateDeviceHealth(ctx, cfg, cleanDev, startDay.AddDate(0, 0, 27).Add(time.Hour), makeSMARTMapReader(healthySMART7d))
	if err != nil {
		t.Fatal(err)
	}
	if staleHealth.Assessment.Health.Status != health.HealthStatusUnknown ||
		staleHealth.Assessment.Health.UnknownReason != health.UnknownReasonStaleEvidence ||
		staleHealth.Assessment.Health.Probability != nil {
		t.Fatalf("expected stale_evidence at 1h boundary, got %+v", staleHealth.Assessment)
	}

	// Future sample exclusion: add seq 30 at asOf+10m, then query at asOf; must still read seq 29.
	acceptTelemetrySample(t, b, cleanDev, cleanKeys, 30, asOf.Add(10*time.Minute), nil)
	futureIsolated, err := b.repo.evaluateDeviceHealth(ctx, cfg, cleanDev, asOf, makeSMARTMapReader(healthySMART7d))
	if err != nil || futureIsolated.LatestSample == nil || futureIsolated.LatestSample.Sequence != 29 {
		t.Fatalf("future sample leaked into evaluation at asOf: sample=%+v err=%v", futureIsolated.LatestSample, err)
	}

	// Fault escalation with persisted log_references across baseline & current windows:
	// 1 report in 21-day baseline + 3 reports in 7-day current -> recurrent + increased rate.
	faultStart := b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	for i := range 28 {
		seq := uint64(2 + i)
		ts := faultStart.AddDate(0, 0, i)
		var refs []contracts.LogReferenceV2
		if i == 10 || i == 24 || i == 25 || i == 26 {
			refs = []contracts.LogReferenceV2{{
				ReferenceID: fmt.Sprintf("log:err-%02d", i),
				SHA256:      sha256DigestHex([]byte{byte(i), 'f'}),
				ByteSize:    1024,
				WindowStart: ts.Add(-time.Hour),
				WindowEnd:   ts,
			}}
		}
		acceptTelemetrySample(t, b, faultDev, faultKeys, seq, ts, refs)
	}
	faultAsOf := faultStart.AddDate(0, 0, 27).Add(15 * time.Minute)
	b.clock.Advance(faultAsOf.Sub(b.clock.Now()))

	// Healthy model + recurrent persisted faults -> degraded.
	faultDegraded, err := b.repo.evaluateDeviceHealth(ctx, cfg, faultDev, faultAsOf, makeSMARTMapReader(healthySMART7d))
	if err != nil || faultDegraded.Assessment.Health.Status != health.HealthStatusDegraded ||
		faultDegraded.Assessment.FaultSummary.RecurrentTypes != 1 {
		t.Fatalf("expected degraded from healthy model + recurrent faults, got %+v err=%v", faultDegraded.Assessment, err)
	}

	// Same active model scores complete-week reallocations as degraded (0.79956738641351921);
	// increasing recurrent persisted faults escalate degraded -> critical.
	faultCritical, err := b.repo.evaluateDeviceHealth(ctx, cfg, faultDev, faultAsOf, makeSMARTMapReader(degradedSMART7d))
	if err != nil || faultCritical.Assessment.Health.Status != health.HealthStatusCritical ||
		faultCritical.Assessment.RuleReason != "model_degraded_escalated_by_increasing_recurrent_faults" {
		t.Fatalf("expected critical escalation, got %+v err=%v", faultCritical.Assessment, err)
	}

	// Only 7 days of evidence (insufficient 21-day baseline) keeps healthy model unknown.
	shortStart := b.clock.Now().UTC().Truncate(24*time.Hour).AddDate(0, 0, 2).Add(12 * time.Hour)
	shortSMART := map[uint64][3]int64{
		2: {0, 11000, 0}, 3: {0, 11024, 0}, 4: {0, 11048, 0}, 5: {0, 11072, 0}, 6: {0, 11096, 0}, 7: {0, 11120, 0}, 8: {0, 11144, 0},
	}
	for i := range 7 {
		acceptTelemetrySample(t, b, shortDev, shortKeys, uint64(2+i), shortStart.AddDate(0, 0, i), nil)
	}
	shortAsOf := shortStart.AddDate(0, 0, 6).Add(10 * time.Minute)
	shortHealth, err := b.repo.evaluateDeviceHealth(ctx, cfg, shortDev, shortAsOf, makeSMARTMapReader(shortSMART))
	if err != nil || shortHealth.Assessment.Health.Status != health.HealthStatusUnknown ||
		shortHealth.Assessment.Health.UnknownReason != health.UnknownReasonInsufficientEvidence ||
		shortHealth.Assessment.Health.Probability != nil {
		t.Fatalf("expected unknown(insufficient_evidence) for 7d-only baseline, got %+v err=%v", shortHealth.Assessment, err)
	}
}

func TestEvaluateDeviceHealthModelFailuresAndBoundaries(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	publisher := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{33}, 32))
	pubKey := publisher.Public().(ed25519.PublicKey)
	artifact := loadBaselineModelBytes(t)
	evalDir := t.TempDir()

	dev := "device:failures"
	keys := enrollTestDevice(t, b, dev)
	ts := b.clock.Now().UTC().Add(time.Minute)
	acceptTelemetrySample(t, b, dev, keys, 2, ts, nil)
	asOf := ts.Add(5 * time.Minute)

	cfg := HealthConfig{PublisherKey: pubKey, EvaluationReports: EvaluationReportDir(evalDir)}

	// 1. No active model configured (and setting candidate slot must not activate inference).
	got, err := b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != "no_active_model" || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable || got.Model != nil {
		t.Fatalf("expected no_active_model unknown, got %+v err=%v", got, err)
	}
	candArtifact := artifactWithVersion(t, artifact, "baseline.candidate.v1")
	candManifest := buildSignedControllerManifest(t, publisher, candArtifact, health.ControllerInferenceRuntime())
	candEvalBytes, candEvalDigest := buildPassingML05Report(t, candManifest, 0.0, 1.0)
	writeEvalReportFile(t, evalDir, candEvalDigest, candEvalBytes)
	candActor := contracts.ModelActorV1{Issuer: "console:local", Subject: "admin@example.com"}
	if _, _, err := b.repo.PutModelArtifact(ctx, contracts.ModelArtifactUploadV1{
		SchemaVersion: contracts.ModelArtifactUploadV1Version, Manifest: candManifest, Artifact: candArtifact, SourceReference: "cand:1",
	}, pubKey, candActor); err != nil {
		t.Fatal(err)
	}
	if _, err := b.repo.SetModelReference(ctx, contracts.ModelSlotCandidate, contracts.ModelReferenceRequestV1{
		SchemaVersion: contracts.ModelReferenceRequestV1Version, ModelVersion: candManifest.ModelVersion, ArtifactSHA256: candManifest.ArtifactSHA256,
	}, candActor); err != nil {
		t.Fatal(err)
	}
	got, err = b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != "no_active_model" || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable || got.Model != nil {
		t.Fatalf("expected candidate-only slot to stay model_unavailable, got %+v err=%v", got, err)
	}

	// 2. Active model pointing to real failed ML06 report -> evaluation_rejected.
	failedBytes := loadML06FailedBytes(t)
	failedDigest := sha256DigestHex(failedBytes)
	writeEvalReportFile(t, evalDir, failedDigest, failedBytes)
	registerAndActivateModel(t, b.repo, publisher, artifact, health.ControllerInferenceRuntime(), failedDigest, health.ML05PolicyVersion)
	got, err = b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != "evaluation_rejected" || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable ||
		got.Model != nil || got.Assessment.Health.Probability != nil || got.Assessment.Health.HorizonHours != nil {
		t.Fatalf("expected evaluation_rejected for ML06 failed report, got %+v err=%v", got, err)
	}

	// 3. Passing report, but model manifest targets endpoint runtime instead of controller runtime.
	endpArtifact := artifactWithVersion(t, artifact, "baseline.endpoint.v1")
	endpManifest := buildSignedControllerManifest(t, publisher, endpArtifact, health.EndpointInferenceRuntime())
	endpEvalBytes, endpEvalDigest := buildPassingML05Report(t, endpManifest, 0.0, 1.0)
	writeEvalReportFile(t, evalDir, endpEvalDigest, endpEvalBytes)
	registerAndActivateModel(t, b.repo, publisher, endpArtifact, health.EndpointInferenceRuntime(), endpEvalDigest, health.ML05PolicyVersion)
	got, err = b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != string(contracts.ModelRejectionRuntimeMismatch) || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable {
		t.Fatalf("expected runtime_mismatch, got %+v err=%v", got, err)
	}

	// 4. Unsupported approval policy version.
	polArtifact := artifactWithVersion(t, artifact, "baseline.oldpol.v1")
	polManifest := buildSignedControllerManifest(t, publisher, polArtifact, health.ControllerInferenceRuntime())
	polEvalBytes, polEvalDigest := buildPassingML05Report(t, polManifest, 0.0, 1.0)
	writeEvalReportFile(t, evalDir, polEvalDigest, polEvalBytes)
	registerAndActivateModel(t, b.repo, publisher, polArtifact, health.ControllerInferenceRuntime(), polEvalDigest, "ml05.v0")
	got, err = b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != "unsupported_policy_version" || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable {
		t.Fatalf("expected unsupported_policy_version, got %+v err=%v", got, err)
	}

	// 5. Missing evaluation report file on disk.
	missingArtifact := artifactWithVersion(t, artifact, "baseline.missing.v1")
	missingManifest := buildSignedControllerManifest(t, publisher, missingArtifact, health.ControllerInferenceRuntime())
	_, missingDigest := buildPassingML05Report(t, missingManifest, 0.0, 1.0)
	registerAndActivateModel(t, b.repo, publisher, missingArtifact, health.ControllerInferenceRuntime(), missingDigest, health.ML05PolicyVersion)
	got, err = b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != "evaluation_report_unavailable" || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable {
		t.Fatalf("expected evaluation_report_unavailable, got %+v err=%v", got, err)
	}

	// 6. Tampered evaluation report file content (digest mismatch).
	writeEvalReportFile(t, evalDir, missingDigest, []byte(`{"tampered":true}`))
	got, err = b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf)
	if err != nil || got.ModelError != "evaluation_rejected" || got.Assessment.Health.UnknownReason != health.UnknownReasonModelUnavailable {
		t.Fatalf("expected evaluation_rejected for tampered report, got %+v err=%v", got, err)
	}

	// 7. Unknown device, invalid input, and closed DB errors.
	if _, err := b.repo.EvaluateDeviceHealth(ctx, cfg, "device:unknown", asOf); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("expected ErrRepositoryNotFound, got %v", err)
	}
	if _, err := b.repo.EvaluateDeviceHealth(ctx, cfg, "bad id", asOf); !errors.Is(err, ErrDeviceStateInvalid) {
		t.Fatalf("expected ErrDeviceStateInvalid, got %v", err)
	}
	if _, err := b.repo.EvaluateDeviceHealth(ctx, cfg, dev, time.Time{}); !errors.Is(err, ErrDeviceStateInvalid) {
		t.Fatalf("expected ErrDeviceStateInvalid for zero asOf, got %v", err)
	}

	// EvaluationReportDir traversal / symlink confinement check.
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, failedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	symlinkDigest := strings.Repeat("d", 64)
	if err := os.Symlink(outside, filepath.Join(evalDir, symlinkDigest+".json")); err != nil {
		t.Fatal(err)
	}
	if _, err := EvaluationReportDir(evalDir).EvaluationReport(ctx, symlinkDigest); err == nil {
		t.Fatal("expected EvaluationReportDir to block escaping symlink")
	}
	if _, err := EvaluationReportDir(evalDir).EvaluationReport(ctx, "../escape"); err == nil {
		t.Fatal("expected EvaluationReportDir to reject non-digest filename")
	}

	_ = b.db.Close()
	if _, err := b.repo.EvaluateDeviceHealth(ctx, cfg, dev, asOf); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("expected ErrRepositoryUnavailable on closed db, got %v", err)
	}
}
