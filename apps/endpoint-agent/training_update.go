package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

const (
	trainingTimeLimit   = 10 * time.Minute
	trainingCadence     = 24 * time.Hour
	trainingAttemptFile = "federated-training.state"
	trainingAttemptTemp = "federated-training.state.tmp"
)

type trainingExecution struct {
	now   func() time.Time
	power func() error
	fit   func(context.Context, string, []byte) ([]byte, inferenceUsage, error)
}

type trainingUpdateReport struct {
	PendingFile         string  `json:"pending_file"`
	TrainingConfig      string  `json:"training_config"`
	SampleCount         uint32  `json:"sample_count"`
	ElapsedMS           float64 `json:"elapsed_ms"`
	CPUTimeMS           float64 `json:"cpu_ms"`
	PeakWorkingSetBytes uint64  `json:"peak_working_set_bytes"`
}

func stageFederatedTraining(ctx context.Context, stateDir, publisherKey string, request []byte, run trainingExecution) (trainingUpdateReport, error) {
	var report trainingUpdateReport
	var head struct {
		Round contracts.FederatedRoundV1 `json:"round"`
	}
	if len(request) > maxLocalTrainingRequest || json.Unmarshal(request, &head) != nil || head.Round.Validate() != nil {
		return report, errors.New("invalid local training request or round")
	}
	if head.Round.FeatureVersion != contracts.FeatureVersionHDDSMART7DV1 {
		return report, health.ErrLocalFeatureMismatch
	}
	opened, _ := time.Parse(time.RFC3339, head.Round.OpenedAt)
	deadline, _ := time.Parse(time.RFC3339, head.Round.Deadline)
	if err := run.power(); err != nil {
		return report, err
	}
	started := run.now()
	if started.Before(opened) || !started.Before(deadline) {
		return report, errors.New("local training outside round window")
	}
	ctx, cancel := context.WithTimeout(ctx, min(trainingTimeLimit, deadline.Sub(started)))
	defer cancel()
	roundDigest := sha256.Sum256([]byte(head.Round.RoundID))
	name := fmt.Sprintf("federated-update-%x.json", roundDigest)
	receipt, err := reserveTrainingAttempt(ctx, stateDir, name, head.Round, started)
	if err != nil {
		return report, err
	}

	data, usage, err := run.fit(ctx, publisherKey, request)
	if err != nil {
		return report, err
	}
	var candidate localCandidate
	if len(data) > 8<<10 || json.Unmarshal(data, &candidate) != nil ||
		candidate.RoundID != head.Round.RoundID || candidate.BaseModelVersion != head.Round.BaseModelVersion ||
		candidate.BaseModelSHA256 != head.Round.BaseModelSHA256 || candidate.CandidateID != head.Round.CandidateID ||
		candidate.FeatureVersion != head.Round.FeatureVersion || candidate.ParameterCount != head.Round.ParameterCount ||
		candidate.TrainingConfig != health.LocalLogisticTrainingV1 || candidate.SampleCount < 1 || candidate.SampleCount > health.MaxLocalExamples {
		return report, errors.New("training result does not match the round")
	}
	if err := run.power(); err != nil {
		return report, err
	}
	if err := publishTrainingUpdate(ctx, stateDir, name, head.Round, receipt, candidate, run.now); err != nil {
		return report, err
	}
	return trainingUpdateReport{
		PendingFile: name, TrainingConfig: candidate.TrainingConfig, SampleCount: uint32(candidate.SampleCount),
		ElapsedMS: float64(usage.Latency) / float64(time.Millisecond),
		CPUTimeMS: float64(usage.CPU) / float64(time.Millisecond), PeakWorkingSetBytes: usage.PeakRSS,
	}, nil
}

func reserveTrainingAttempt(ctx context.Context, stateDir, name string, round contracts.FederatedRoundV1, started time.Time) (contracts.EnrollmentAcceptedV1, error) {
	store, err := openIdentityStore(stateDir, false)
	if err != nil {
		return contracts.EnrollmentAcceptedV1{}, err
	}
	defer store.close()
	_, receipt, err := store.admitted()
	if err != nil {
		return receipt, err
	}
	eligible := false
	for _, participant := range round.Participants {
		if participant.DeviceID == receipt.DeviceID && participant.SigningKeyID == receipt.SigningKeyID && participant.Eligibility == "eligible" {
			eligible = true
			break
		}
	}
	if !eligible || receipt.DeploymentID != round.DeploymentID {
		return receipt, errors.New("admitted identity is not eligible for the local round")
	}
	if _, err := store.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return receipt, errors.New("pending update already exists or cannot be inspected")
	}
	state, err := store.read(trainingAttemptFile)
	switch {
	case err == nil:
		value, ok := verifyChecksum(state)
		previous, parseErr := time.Parse(time.RFC3339Nano, string(value))
		if !ok || parseErr != nil {
			return receipt, errors.New("invalid local training attempt state")
		}
		if started.Sub(previous) < trainingCadence {
			return receipt, errors.New("local training requires at least 24 hours between attempts")
		}
	case !errors.Is(err, os.ErrNotExist):
		return receipt, err
	}
	if err := ctx.Err(); err != nil {
		return receipt, err
	}
	return receipt, store.replace(trainingAttemptFile, trainingAttemptTemp, checksummed([]byte(started.UTC().Format(time.RFC3339Nano))))
}

func publishTrainingUpdate(ctx context.Context, stateDir, name string, round contracts.FederatedRoundV1, expected contracts.EnrollmentAcceptedV1, candidate localCandidate, clock func() time.Time) error {
	store, err := openIdentityStore(stateDir, false)
	if err != nil {
		return err
	}
	defer store.close()
	identity, receipt, err := store.admitted()
	if err != nil {
		return err
	}
	if receipt.DeploymentID != expected.DeploymentID || receipt.DeviceID != expected.DeviceID || receipt.SigningKeyID != expected.SigningKeyID {
		return errors.New("admitted identity changed during training")
	}
	if _, err := store.root.Lstat(name); !errors.Is(err, os.ErrNotExist) {
		return errors.New("pending update already exists or cannot be inspected")
	}
	now := clock().UTC()
	issued := now.Truncate(time.Second)
	deadline, _ := time.Parse(time.RFC3339, round.Deadline)
	expires := issued.Add(evidenceLifetime)
	if deadline.Before(expires) {
		expires = deadline
	}
	update := contracts.FederatedUpdateV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.FederatedUpdateV1Version, DeploymentID: receipt.DeploymentID,
			DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID, Sequence: contracts.FirstEvidenceSequenceV1,
			IssuedAt: issued.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		},
		RoundID: candidate.RoundID, BaseModelVersion: candidate.BaseModelVersion, BaseModelSHA256: candidate.BaseModelSHA256,
		CandidateID: candidate.CandidateID, FeatureVersion: candidate.FeatureVersion, SampleCount: uint32(candidate.SampleCount),
		WeightsBase64: candidate.WeightsBase64, UpdateSHA256: candidate.UpdateSHA256, Signature: strings.Repeat("00", ed25519.SignatureSize),
	}
	if err := update.CheckRound(round, now); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	update.Sequence, err = store.reserveSequence(receipt)
	if err != nil {
		return err
	}
	message, err := update.SigningBytes()
	if err != nil {
		return err
	}
	update.Signature = hex.EncodeToString(ed25519.Sign(identity.signing, message))
	if err := update.VerifySignature(identity.signing.Public().(ed25519.PublicKey)); err != nil {
		return err
	}
	data, err := json.Marshal(update)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := update.CheckRound(round, clock().UTC()); err != nil {
		return err
	}
	return store.replace(name, name+".tmp", data)
}
