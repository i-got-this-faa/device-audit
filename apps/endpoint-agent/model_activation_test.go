package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func activationFixture(t *testing.T) (inferenceRequest, contracts.ModelManifestV1, ed25519.PrivateKey, []byte) {
	t.Helper()
	req, manifest, key, report := testInferenceBundle(t)
	report = passingInferenceFixture(t, report)
	pinInferenceReport(t, &req, report)
	req.Config.StagedEvaluationFile = filepath.Join(filepath.Dir(req.Config.EvaluationFile), "staged-evaluation.json")
	return req, manifest, key, report
}

func activationStage(t *testing.T, store *identityStore, req inferenceRequest, manifest contracts.ModelManifestV1, key ed25519.PrivateKey, report []byte, deployment, version string) stagedModel {
	t.Helper()
	artifact, err := os.ReadFile(req.Config.ArtifactFile)
	if err != nil {
		t.Fatal(err)
	}
	artifact = bytes.ReplaceAll(artifact, []byte(manifest.ModelVersion), []byte(version))
	manifest.ModelVersion = version
	digest := sha256.Sum256(artifact)
	manifest.ArtifactSHA256 = hex.EncodeToString(digest[:])
	message, err := manifest.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(key, message))

	var evaluation map[string]json.RawMessage
	if err := json.Unmarshal(report, &evaluation); err != nil {
		t.Fatal(err)
	}
	evaluation["model"], err = json.Marshal(map[string]string{"version": version, "artifact_sha256": manifest.ArtifactSHA256})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(evaluation)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(req.Config.StagedEvaluationFile, payload, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(payload)
	stage := stagedModel{Metadata: contracts.ModelDownloadV1{
		SchemaVersion: contracts.ModelDownloadV1Version, DeploymentID: deployment, Manifest: manifest,
		ArtifactByteSize: len(artifact), EvaluationSHA256: hex.EncodeToString(sum[:]),
	}, Artifact: artifact}
	writeActivationStage(t, store, stage)
	return stage
}

func writeActivationStage(t *testing.T, store *identityStore, staged stagedModel) {
	t.Helper()
	data, err := json.Marshal(staged)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.replace(stagedModelFile, stagedModelFile+".tmp", data); err != nil {
		t.Fatal(err)
	}
}

func runActivationInference(_ context.Context, req inferenceRequest) (inferenceResult, error) {
	return infer(req)
}

func assertInferenceVersion(t *testing.T, req inferenceRequest, config inferenceConfig, version string) {
	t.Helper()
	req.Config = config
	reply, err := infer(req)
	if err != nil || reply.Model == nil || reply.Model.Version != version {
		t.Fatalf("expected %s, got %+v: %v", version, reply.Model, err)
	}
}

func TestActivateStagedModel(t *testing.T) {
	req, base, key, report := activationFixture(t)
	store, dir, _, receipt := admittedStore(t)
	defer func() { store.close() }()
	activate := func(run inferenceRunner, logf func(string, ...any)) inferenceConfig {
		return activateStagedModel(t.Context(), req.Config, store, receipt.DeploymentID, run, logf)
	}
	logf := func(string, ...any) {}
	deployment := receipt.DeploymentID
	activationStage(t, store, req, base, key, report, deployment, "registry.1")
	cfg := activate(runActivationInference, logf)
	assertInferenceVersion(t, req, cfg, "registry.1")
	state, err := loadModelActivation(store)
	if err != nil || state.Outcome != activationApplied {
		t.Fatalf("activation journal: %+v (%v)", state, err)
	}
	assertInferenceVersion(t, req, state.LastWorking.config(dir, req.Config.PublisherKeyFile), base.ModelVersion)

	secondStage := activationStage(t, store, req, base, key, report, deployment, "registry.2")
	cfg = activate(runActivationInference, logf)
	assertInferenceVersion(t, req, cfg, "registry.2")
	state, err = loadModelActivation(store)
	if err != nil || state.Outcome != activationApplied {
		t.Fatalf("second activation journal: %+v (%v)", state, err)
	}
	assertInferenceVersion(t, req, state.LastWorking.config(dir, req.Config.PublisherKeyFile), "registry.1")
	secondStage.AttemptID = "restaged"
	writeActivationStage(t, store, secondStage)
	cfg = activate(func(context.Context, inferenceRequest) (inferenceResult, error) {
		t.Fatal("restaging the active model triggered another probe")
		return inferenceResult{}, nil
	}, logf)
	assertInferenceVersion(t, req, cfg, "registry.2")
	unchanged, err := loadModelActivation(store)
	if err != nil || unchanged.Outcome != activationAlreadyActive ||
		unchanged.Active != state.Active || unchanged.LastWorking != state.LastWorking {
		t.Fatalf("restaging changed the committed slots: %+v (%v)", unchanged, err)
	}

	for _, tc := range []struct {
		reason string
		alter  func(*stagedModel)
		run    inferenceRunner
	}{
		{"invalid_stage", func(stage *stagedModel) { stage.Metadata.DeploymentID = "wrong" }, nil},
		{"verification_failed", func(stage *stagedModel) { stage.Artifact[0] ^= 1 }, nil},
		{"evaluation_rejected", func(stage *stagedModel) { stage.Metadata.EvaluationSHA256 = strings.Repeat("0", 64) }, nil},
		{"health_check_failed", nil, func(_ context.Context, req inferenceRequest) (inferenceResult, error) {
			reply, err := infer(req)
			reply.Model = &contracts.ModelReferenceV2{Version: "wrong"}
			return reply, err
		}},
	} {
		stage := activationStage(t, store, req, base, key, report, deployment, "registry.3")
		if tc.alter != nil {
			tc.alter(&stage)
			writeActivationStage(t, store, stage)
		}
		run := tc.run
		if run == nil {
			run = func(context.Context, inferenceRequest) (inferenceResult, error) {
				t.Fatal("invalid stage reached health check")
				return inferenceResult{}, nil
			}
		}
		var logged string
		cfg = activate(run, func(format string, args ...any) { logged = fmt.Sprintf(format, args...) })
		if logged != "endpoint model activation rejected: "+tc.reason {
			t.Fatalf("rejection log = %q, want %s", logged, tc.reason)
		}
		assertInferenceVersion(t, req, cfg, "registry.2")
		current, err := loadModelActivation(store)
		if err != nil || current.Outcome != tc.reason || current.Active != state.Active || current.LastWorking != state.LastWorking {
			t.Fatalf("rejected activation changed committed slots: %+v (%v)", current, err)
		}
	}

	if err := os.Remove(req.Config.StagedEvaluationFile); err != nil {
		t.Fatal(err)
	}
	store.close()
	store, err = openIdentityStore(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	cfg = activate(func(context.Context, inferenceRequest) (inferenceResult, error) {
		t.Fatal("retried the rejected stage without restaging")
		return inferenceResult{}, nil
	}, logf)
	assertInferenceVersion(t, req, cfg, "registry.2")
}

func TestModelActivationCrashRecovery(t *testing.T) {
	if mode := os.Getenv("DEVICE_AUDIT_TEST_ACTIVATION_CRASH"); mode != "" {
		cfg, err := loadServiceConfig(os.Getenv("DEVICE_AUDIT_TEST_ACTIVATION_CONFIG"))
		if err != nil {
			t.Fatal(err)
		}
		store, err := openIdentityStore(cfg.StateDir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		_, receipt, err := store.admitted()
		if err != nil {
			t.Fatal(err)
		}
		run := func(ctx context.Context, req inferenceRequest) (inferenceResult, error) {
			reply, err := runActivationInference(ctx, req)
			if err == nil && reply.Model != nil && reply.Model.Version == "registry.2" {
				sequenceStage = func(point string) {
					if point == mode {
						os.Exit(51)
					}
				}
			}
			return reply, err
		}
		activateStagedModel(t.Context(), *cfg.Inference, store, receipt.DeploymentID, run, t.Logf)
		t.Fatal("activation did not reach crash point")
	}

	for _, mode := range []string{"before-commit", "after-commit"} {
		t.Run(mode, func(t *testing.T) {
			req, base, key, report := activationFixture(t)
			store, dir, _, receipt := admittedStore(t)
			activationStage(t, store, req, base, key, report, receipt.DeploymentID, "registry.1")
			original := activateStagedModel(t.Context(), req.Config, store, receipt.DeploymentID, runActivationInference, t.Logf)
			assertInferenceVersion(t, req, original, "registry.1")
			activationStage(t, store, req, base, key, report, receipt.DeploymentID, "registry.2")
			store.close()
			cfg := testServiceConfig(t, dir)
			cfg.Inference = &req.Config
			path := filepath.Join(t.TempDir(), "service.json")
			writeJSON(t, path, cfg)
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestModelActivationCrashRecovery$")
			cmd.Env = append(os.Environ(), "DEVICE_AUDIT_TEST_ACTIVATION_CRASH="+mode, "DEVICE_AUDIT_TEST_ACTIVATION_CONFIG="+path, "GORACE=atexit_sleep_ms=0")
			out, err := cmd.CombinedOutput()
			var status *exec.ExitError
			if !errors.As(err, &status) || status.ExitCode() != 51 {
				t.Fatalf("activation subprocess: %v %s", err, out)
			}
			store, err = openIdentityStore(dir, false)
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			var logged string
			recovered := activateStagedModel(t.Context(), req.Config, store, receipt.DeploymentID, func(context.Context, inferenceRequest) (inferenceResult, error) {
				t.Fatal("restart retried the interrupted or committed attempt")
				return inferenceResult{}, nil
			}, func(format string, args ...any) { logged = fmt.Sprintf(format, args...) })
			state, err := loadModelActivation(store)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "before-commit" {
				assertInferenceVersion(t, req, recovered, "registry.1")
				if state.Outcome != activationInterrupted || logged != "endpoint model activation rejected: interrupted" {
					t.Fatalf("rollback report: %q, %+v", logged, state)
				}
				assertInferenceVersion(t, req, state.LastWorking.config(dir, req.Config.PublisherKeyFile), base.ModelVersion)
			} else {
				assertInferenceVersion(t, req, recovered, "registry.2")
				if state.Outcome != activationApplied || logged != "" {
					t.Fatalf("committed activation report: %q, %+v", logged, state)
				}
				assertInferenceVersion(t, req, state.LastWorking.config(dir, req.Config.PublisherKeyFile), "registry.1")
			}
		})
	}
}

func TestServiceSamplingContinuesThroughActivationRejection(t *testing.T) {
	req, base, key, report := activationFixture(t)
	store, dir, identity, receipt := admittedStore(t)
	activationStage(t, store, req, base, key, report, receipt.DeploymentID, "registry.1")
	active := activateStagedModel(t.Context(), req.Config, store, receipt.DeploymentID, runActivationInference, t.Logf)
	activationStage(t, store, req, base, key, report, receipt.DeploymentID, "registry.2")
	store.close()

	cfg := testServiceConfig(t, dir)
	cfg.Inference = &req.Config
	synctest.Test(t, func(t *testing.T) {
		serviceCtx, cancel := context.WithCancel(t.Context())
		defer cancel()
		probing, release, rejected := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var previousModelRuns atomic.Int32
		run := func(_ context.Context, req inferenceRequest) (inferenceResult, error) {
			if req.Config.ArtifactFile == active.ArtifactFile {
				previousModelRuns.Add(1)
				return infer(req)
			}
			close(probing)
			select {
			case <-release:
				return inferenceResult{}, errors.New("test worker failed")
			case <-serviceCtx.Done():
				return inferenceResult{}, serviceCtx.Err()
			}
		}
		logf := func(format string, args ...any) {
			if fmt.Sprintf(format, args...) == "endpoint model activation rejected: health_check_failed" {
				close(rejected)
			}
		}
		done := make(chan error, 1)
		go func() {
			done <- runServicePipelineWithInference(serviceCtx, cfg, cpuSource(new(atomic.Bool), false), logf, run)
		}()
		select {
		case <-probing:
		case err := <-done:
			t.Fatalf("service exited before the probe: %v", err)
		}
		// Hold the test worker across several ticks to inspect the signed spool
		// before rollback finishes. The real subprocess enforces its deadline.
		time.Sleep(12 * time.Second)
		synctest.Wait()
		during := readEnvelopes(t, identity, receipt, cfg.EvidenceDir)
		close(release)
		select {
		case <-rejected:
		case err := <-done:
			t.Fatalf("service exited before reporting rejection: %v", err)
		}
		time.Sleep(8 * time.Second)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		after := readEnvelopes(t, identity, receipt, cfg.EvidenceDir)
		if len(during) == 0 || len(after) <= len(during) {
			t.Fatalf("signed snapshots during probe = %d, after rejection = %d", len(during), len(after))
		}
		if previousModelRuns.Load() == 0 {
			t.Fatal("the inference worker did not resume with the previous model")
		}
	})
}
