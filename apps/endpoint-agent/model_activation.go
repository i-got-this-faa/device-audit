package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

const modelActivationFile = "model-activation.json"

const (
	activationPending       = "pending"
	activationApplied       = "applied"
	activationInterrupted   = "interrupted"
	activationAlreadyActive = "already_active"
)

// A slot is written only while it is unreferenced. The journal is the single
// commit point for both active and last-working slots.
type modelSlot struct {
	Number           int    `json:"number"`
	EvaluationSHA256 string `json:"evaluation_sha256"`
	ArtifactSHA256   string `json:"artifact_sha256"`
}

func (s modelSlot) config(dir, key string) inferenceConfig {
	return inferenceConfig{
		ManifestFile:     filepath.Join(dir, s.file("manifest")),
		ArtifactFile:     filepath.Join(dir, s.file("artifact")),
		EvaluationFile:   filepath.Join(dir, s.file("evaluation")),
		PublisherKeyFile: key, EvaluationSHA256: s.EvaluationSHA256,
	}
}

func (s modelSlot) file(kind string) string {
	return fmt.Sprintf("inference-slot-%d-%s.json", s.Number, kind)
}

func (s modelSlot) valid() bool {
	return (s == modelSlot{}) || (s.Number >= 1 && s.Number <= 3 &&
		validActivationDigest(s.EvaluationSHA256) && validActivationDigest(s.ArtifactSHA256))
}

func validActivationDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == sha256.Size
}

type modelActivation struct {
	Active      modelSlot `json:"active"`
	LastWorking modelSlot `json:"last_working"`
	StageSHA256 string    `json:"stage_sha256"`
	Outcome     string    `json:"outcome"`
}

func (a modelActivation) save(store *identityStore) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return store.replace(modelActivationFile, modelActivationFile+".tmp", data)
}

func loadModelActivation(store *identityStore) (modelActivation, error) {
	var a modelActivation
	data, err := store.read(modelActivationFile)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	if json.Unmarshal(data, &a) != nil || !a.Active.valid() || !a.LastWorking.valid() ||
		(a.LastWorking.Number != 0 && (a.Active.Number == 0 || a.Active.Number == a.LastWorking.Number)) {
		return a, errors.New("invalid activation journal")
	}
	if !validActivationDigest(a.StageSHA256) || a.Outcome == "" ||
		(a.Outcome == activationApplied && a.LastWorking.Number == 0) {
		return a, errors.New("invalid activation attempt")
	}
	return a, nil
}

func activateStagedModel(ctx context.Context, base inferenceConfig, store *identityStore, deployment string, run inferenceRunner, logf func(string, ...any)) inferenceConfig {
	active := base
	active.StagedEvaluationFile = ""
	reject := func(reason string) { logf("endpoint model activation rejected: %s", reason) }
	state, err := loadModelActivation(store)
	if err != nil {
		reject("journal_unavailable")
		return active
	}
	dir := store.root.Name()
	if state.Active.Number != 0 {
		active = state.Active.config(dir, base.PublisherKeyFile)
	}
	if state.Outcome == activationPending {
		state.Outcome = activationInterrupted
		reject(state.Outcome)
		if err := state.save(store); err != nil {
			reject("journal_write_failed")
			return active
		}
	}

	const maxStagedModel = (contracts.ModelArtifactMaxBytesV1+2)/3*4 + maxModelMetadata
	data, err := store.readBounded(stagedModelFile, maxStagedModel)
	if errors.Is(err, os.ErrNotExist) {
		return active
	}
	if err != nil {
		reject("staging_unreadable")
		return active
	}
	sum := sha256.Sum256(data)
	stage := hex.EncodeToString(sum[:])
	if state.StageSHA256 == stage {
		return active
	}

	state.StageSHA256, state.Outcome = stage, activationPending
	if err := state.save(store); err != nil {
		reject("journal_write_failed")
		return active
	}
	candidate, previous, model, reason := prepareActivation(ctx, store, state, base, deployment, data, run)
	if ctx.Err() != nil {
		// Recovery reports the interrupted attempt and keeps the old slot.
		return active
	}
	if reason != "" {
		if reason != activationAlreadyActive {
			reject(reason)
		}
		state.Outcome = reason
		if err := state.save(store); err != nil {
			reject("journal_write_failed")
		}
		return active
	}

	state.Active, state.LastWorking, state.Outcome = candidate, previous, activationApplied
	if err := state.save(store); err != nil {
		// A flush can fail after rename. Restart resolves the outcome from the
		// journal that actually survived.
		logf("endpoint model activation commit uncertain: journal_write_failed")
		return active
	}
	logf("endpoint model activated: %s %s", model.ModelVersion, model.ArtifactSHA256)
	return candidate.config(dir, base.PublisherKeyFile)
}

func prepareActivation(ctx context.Context, store *identityStore, state modelActivation, base inferenceConfig, deployment string, data []byte, run inferenceRunner) (candidate, previous modelSlot, manifest contracts.ModelManifestV1, reason string) {
	var staged stagedModel
	if json.Unmarshal(data, &staged) != nil || staged.Metadata.Validate() != nil || staged.Metadata.DeploymentID != deployment {
		return candidate, previous, manifest, "invalid_stage"
	}
	manifest = staged.Metadata.Manifest
	key, err := loadPinnedEd25519Key(base.PublisherKeyFile)
	if err != nil || manifest.CheckCompatibility(health.EndpointInferenceRuntime(), contracts.ModelPurposeInference, key) != nil ||
		validateStagedArtifact(staged.Metadata, staged.Artifact) != nil {
		return candidate, previous, manifest, "verification_failed"
	}
	if manifest.ArtifactSHA256 == state.Active.ArtifactSHA256 &&
		staged.Metadata.EvaluationSHA256 == state.Active.EvaluationSHA256 {
		return candidate, previous, manifest, activationAlreadyActive
	}
	evaluation, err := readInferenceFile(base.StagedEvaluationFile, maxModelMetadata)
	if err != nil {
		return candidate, previous, manifest, "evaluation_unavailable"
	}
	if _, err := checkInferenceEvaluation(staged.Metadata.EvaluationSHA256, manifest, evaluation); err != nil {
		return candidate, previous, manifest, "evaluation_rejected"
	}

	previous = state.Active
	used := state.LastWorking.Number
	if previous.Number == 0 {
		// First activation snapshots the provisioned model before committing the
		// new one, so rollback does not depend on later edits to its files.
		previous = modelSlot{Number: 1, EvaluationSHA256: base.EvaluationSHA256}
		oldManifest, artifact, _, err := loadInferenceBundle(base)
		if err != nil {
			return candidate, previous, manifest, "baseline_unavailable"
		}
		previous.ArtifactSHA256 = oldManifest.ArtifactSHA256
		report, err := readInferenceFile(base.EvaluationFile, maxModelMetadata)
		if err != nil || writeModelSlot(store, previous, oldManifest, artifact, report) != nil ||
			!probeInference(ctx, previous.config(store.root.Name(), base.PublisherKeyFile), oldManifest, run) {
			return candidate, previous, manifest, "baseline_unhealthy"
		}
	}
	for n := 1; n <= 3; n++ {
		if n != previous.Number && n != used {
			candidate = modelSlot{Number: n, EvaluationSHA256: staged.Metadata.EvaluationSHA256, ArtifactSHA256: manifest.ArtifactSHA256}
			break
		}
	}
	if err := writeModelSlot(store, candidate, manifest, staged.Artifact, evaluation); err != nil {
		return candidate, previous, manifest, "slot_write_failed"
	}
	if !probeInference(ctx, candidate.config(store.root.Name(), base.PublisherKeyFile), manifest, run) {
		return candidate, previous, manifest, "health_check_failed"
	}
	return candidate, previous, manifest, ""
}

func writeModelSlot(store *identityStore, slot modelSlot, manifest contracts.ModelManifestV1, artifact, evaluation []byte) error {
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	for _, part := range []struct {
		kind string
		data []byte
	}{{"manifest", data}, {"artifact", artifact}, {"evaluation", evaluation}} {
		name := slot.file(part.kind)
		if err := store.replace(name, name+".tmp", part.data); err != nil {
			return err
		}
	}
	return nil
}

func probeInference(ctx context.Context, config inferenceConfig, manifest contracts.ModelManifestV1, run inferenceRunner) bool {
	// A complete synthetic CT03 window exercises scoring even when local
	// telemetry lacks SMART. The probe result is never published as evidence.
	at := time.Now().UTC()
	var readings [contracts.FeatureWindowDays]health.SMARTReading
	var zero int64
	for i := range readings {
		hours := int64(400 + 24*i)
		readings[i] = health.SMARTReading{
			ObservedAt: at.AddDate(0, 0, i-len(readings)+1),
			SMART5Raw:  &zero, SMART9Raw: &hours, SMART197Raw: &zero,
		}
	}
	features, err := health.Preprocess(at, readings[:])
	if err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, inferenceTimeout)
	defer cancel()
	reply, err := run(ctx, inferenceRequest{Config: config, Features: features})
	expected := contracts.ModelReferenceV2{Version: manifest.ModelVersion, SHA256: manifest.ArtifactSHA256}
	h := reply.Health
	return err == nil && ctx.Err() == nil && reply.Model != nil && *reply.Model == expected &&
		(h.Status == "healthy" || h.Status == "degraded" || h.Status == "critical") &&
		h.UnknownReason == "" && h.ProbabilityUnit == "probability" && h.HorizonHours != nil && *h.HorizonHours == inferenceHorizon &&
		h.Probability != nil && !math.IsNaN(*h.Probability) && *h.Probability >= 0 && *h.Probability <= 1
}
