package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func testInferenceBundle(t *testing.T) (inferenceRequest, contracts.ModelManifestV1, ed25519.PrivateKey, []byte) {
	t.Helper()
	dir := t.TempDir()
	cfg := inferenceConfig{
		ManifestFile: filepath.Join(dir, "manifest.json"), ArtifactFile: filepath.Join(dir, "artifact.json"),
		PublisherKeyFile: filepath.Join(dir, "publisher.pem"), EvaluationFile: filepath.Join(dir, "evaluation.json"),
	}
	artifact, err := os.ReadFile("../../models/baseline/backblaze-2013/artifact.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.ArtifactFile, artifact, 0600); err != nil {
		t.Fatal(err)
	}
	// Generate a test-only publisher key. This does not sign or approve the
	// repository's artifact for deployment.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.PublisherKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	keyID, _ := contracts.SigningKeyIDV1(public)
	names, _, _ := contracts.FeatureNamesV1(contracts.FeatureVersionHDDSMART7DV1)
	runtime := health.EndpointInferenceRuntime()
	sum := sha256.Sum256(artifact)
	manifest := contracts.ModelManifestV1{
		SchemaVersion: contracts.ModelManifestV1Version, ModelVersion: "logistic-baseline.backblaze-2013.v1",
		ArtifactSHA256: hex.EncodeToString(sum[:]), Architecture: runtime.Architectures[0], ParameterCount: 7,
		RuntimeName: runtime.Name, RuntimeVersion: runtime.Version, FeatureVersion: contracts.FeatureVersionHDDSMART7DV1,
		Features: names, Purposes: []string{"inference"}, SigningKeyID: keyID,
	}
	signInferenceManifest(t, cfg, manifest, private)

	report, err := os.ReadFile("../../models/evaluation/results/logistic-baseline.backblaze-2013.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)
	var readings []health.SMARTReading
	var zero int64
	for n := 0; n < contracts.FeatureWindowDays; n++ {
		hours := int64(400 + 24*n)
		readings = append(readings, health.SMARTReading{ObservedAt: at.AddDate(0, 0, n-6), SMART5Raw: &zero, SMART9Raw: &hours, SMART197Raw: &zero})
	}
	vector, err := health.Preprocess(at, readings)
	if err != nil {
		t.Fatal(err)
	}
	return inferenceRequest{Config: cfg, Features: vector}, manifest, private, report
}

func signInferenceManifest(t *testing.T, cfg inferenceConfig, manifest contracts.ModelManifestV1, private ed25519.PrivateKey) {
	t.Helper()
	payload, err := manifest.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(private, payload))
	writeJSON(t, cfg.ManifestFile, manifest)
}

func pinInferenceReport(t *testing.T, req *inferenceRequest, report []byte) {
	t.Helper()
	if err := os.WriteFile(req.Config.EvaluationFile, report, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(report)
	req.Config.EvaluationSHA256 = hex.EncodeToString(sum[:])
}

func passingInferenceFixture(t *testing.T, report []byte) []byte {
	t.Helper()
	var synthetic map[string]any
	if err := json.Unmarshal(report, &synthetic); err != nil {
		t.Fatal(err)
	}
	synthetic["gate"] = map[string]any{"status": "pass", "policy_sha256": inferencePolicy}
	synthetic["operating_points"] = map[string]float64{"degraded_logit": -0.3, "critical_logit": 5}
	payload, err := json.Marshal(synthetic)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestInferenceWorkerEnforcesActivationAndEvaluation(t *testing.T) {
	req, manifest, private, recordedReport := testInferenceBundle(t)
	pinInferenceReport(t, &req, recordedReport)
	if _, err := infer(req); err == nil || !strings.Contains(err.Error(), "passing evaluation") {
		t.Fatalf("recorded failed candidate was not rejected: %v", err)
	}
	pinInferenceReport(t, &req, passingInferenceFixture(t, recordedReport))
	result, err := infer(req)
	if err != nil || result.Health.Status != "degraded" || result.Model.SHA256 != manifest.ArtifactSHA256 {
		t.Fatalf("fixture inference = %+v, %v", result, err)
	}
	// Python ML02 computes this probability for the same CT03 fixture.
	if math.Abs(*result.Health.Probability-0.44727414821244543) > 1e-12 {
		t.Fatalf("probability = %.17g", *result.Health.Probability)
	}

	for _, tc := range []struct {
		name string
		code contracts.ModelRejection
		edit func(*contracts.ModelManifestV1)
	}{
		{"runtime", contracts.ModelRejectionRuntimeMismatch, func(m *contracts.ModelManifestV1) { m.RuntimeVersion = "2.0.0" }},
		{"artifact digest", contracts.ModelRejectionDigestMismatch, func(m *contracts.ModelManifestV1) { m.ArtifactSHA256 = strings.Repeat("a", 64) }},
		{"feature order", contracts.ModelRejectionFeatureOrder, func(m *contracts.ModelManifestV1) {
			m.Features[0], m.Features[1] = m.Features[1], m.Features[0]
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := manifest
			changed.Features = append([]string(nil), manifest.Features...)
			tc.edit(&changed)
			signInferenceManifest(t, req.Config, changed, private)
			if _, err := infer(req); !errors.Is(err, tc.code) {
				t.Fatalf("got %v, want %s", err, tc.code)
			}
		})
	}

	var signed contracts.ModelManifestV1
	signInferenceManifest(t, req.Config, manifest, private)
	data, err := os.ReadFile(req.Config.ManifestFile)
	if err != nil || json.Unmarshal(data, &signed) != nil {
		t.Fatal("could not read signed fixture")
	}
	signed.Signature = strings.Repeat("0", 128)
	writeJSON(t, req.Config.ManifestFile, signed)
	if _, err := infer(req); !errors.Is(err, contracts.ModelRejectionInvalidSignature) {
		t.Fatalf("invalid signature: %v", err)
	}
	signInferenceManifest(t, req.Config, manifest, private)
	req.Config.EvaluationSHA256 = strings.Repeat("b", 64)
	if _, err := infer(req); err == nil {
		t.Fatal("unapproved evaluation bytes were accepted")
	}
}

func TestInferenceSubprocess(t *testing.T) {
	if len(os.Args) > 1 && os.Args[len(os.Args)-2] == "--" {
		switch os.Args[len(os.Args)-1] {
		case "crash":
			os.Exit(42)
		case "hang":
			time.Sleep(time.Minute)
			os.Exit(43)
		case "infer":
			os.Exit(runInferenceWorker(os.Stdin, os.Stdout, os.Stderr))
		}
	}

	req, _, _, report := testInferenceBundle(t)
	pinInferenceReport(t, &req, passingInferenceFixture(t, report))
	at, err := time.Parse(time.RFC3339, req.Features.AsOf)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	child := func(mode string) inferenceRunner {
		return func(ctx context.Context, _ inferenceRequest) (inferenceResult, error) {
			return runInferenceProcess(ctx, req, os.Args[0], "-test.run=^TestInferenceSubprocess$", "--", mode)
		}
	}
	sample := inferenceSample{deviceID: "fixture-device", digest: strings.Repeat("a", 64), at: at}
	for _, mode := range []string{"crash", "hang"} {
		got := predictSample(t.Context(), req.Config, sample, at, child(mode))
		if got.Validate() != nil || got.Health.Status != "unknown" || got.Health.UnknownReason != "model_unavailable" || got.Model != nil {
			t.Fatalf("%s reply = %+v", mode, got)
		}
	}
	if got := predictSample(t.Context(), req.Config, sample, at, child("infer")); got.Validate() != nil || got.Health.Status != "degraded" {
		t.Fatalf("restarted worker health = %+v", got.Health)
	}
}

func TestInferenceFailureDoesNotStopSignedServiceSampling(t *testing.T) {
	store, stateDir, identity, receipt := admittedStore(t)
	store.close()
	cfg := testServiceConfig(t, stateDir)
	cfg.MaxEvidenceBytes = 16 << 20
	cfg.Inference = &inferenceConfig{}
	var calls atomic.Int32
	var logs []contracts.PredictionV2
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), inferenceCadence+15*time.Second)
		defer cancel()
		logf := func(format string, args ...any) {
			if format == "endpoint inference: %s" {
				var prediction contracts.PredictionV2
				if err := json.Unmarshal(args[0].([]byte), &prediction); err != nil {
					t.Errorf("prediction decode: %v", err)
				}
				logs = append(logs, prediction)
			}
		}
		run := func(ctx context.Context, req inferenceRequest) (inferenceResult, error) {
			if calls.Add(1) == 1 {
				return inferenceResult{}, errors.New("test worker crashed")
			}
			return infer(req)
		}
		if err := runServicePipelineWithInference(ctx, cfg, cpuSource(new(atomic.Bool), false), logf, run); err != nil {
			t.Fatal(err)
		}
	})
	envelopes := readEnvelopes(t, identity, receipt, cfg.EvidenceDir)
	if len(envelopes) < 2 || calls.Load() != 2 || len(logs) != 2 {
		t.Fatalf("signed telemetry=%d, worker starts=%d, predictions=%d", len(envelopes), calls.Load(), len(logs))
	}
	if logs[0].Health.UnknownReason != "model_unavailable" || logs[1].Health.UnknownReason != "insufficient_evidence" {
		t.Fatalf("unexpected unknown health: %+v %+v", logs[0].Health, logs[1].Health)
	}
	for _, prediction := range logs {
		matched := false
		for _, envelope := range envelopes {
			if prediction.Evidence.Digest == envelope.PayloadSHA256 && prediction.DeviceID == envelope.DeviceID {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatal("prediction did not reference its signed telemetry")
		}
	}
}
