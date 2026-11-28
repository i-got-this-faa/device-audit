package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func budgetedTrainingFixture(t *testing.T, at time.Time, receipt contracts.EnrollmentAcceptedV1) (localCandidateRequest, string, []byte) {
	t.Helper()
	inference, manifest, publisher, _ := testInferenceBundle(t)
	manifest.Purposes = []string{"training"}
	signInferenceManifest(t, inference.Config, manifest, publisher)
	req := localCandidateRequest{
		Round: contracts.FederatedRoundV1{
			SchemaVersion: contracts.FederatedRoundV1Version,
			DeploymentID:  receipt.DeploymentID, RoundID: "training-round", CandidateID: "candidate",
			BaseModelVersion: manifest.ModelVersion, BaseModelSHA256: manifest.ArtifactSHA256,
			FeatureVersion: manifest.FeatureVersion, ParameterCount: manifest.ParameterCount,
			OpenedAt: at.Format(time.RFC3339), Deadline: at.Add(time.Hour).Format(time.RFC3339),
			MinParticipants: 2,
			Participants: []contracts.FederatedParticipantV1{
				{DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID, Eligibility: "eligible"},
				{DeviceID: "other-endpoint", SigningKeyID: manifest.SigningKeyID, Eligibility: "eligible"},
			},
		},
		ManifestFile: inference.Config.ManifestFile, ArtifactFile: inference.Config.ArtifactFile,
		Examples: localTrainingFixtureExamples(inference.Features, at),
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return req, inference.Config.PublisherKeyFile, data
}

func TestStageFederatedTraining(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	t.Run("signed update", func(t *testing.T) {
		store, dir, identity, receipt := admittedStore(t)
		store.close()
		req, key, data := budgetedTrainingFixture(t, at, receipt)
		report, err := stageFederatedTraining(t.Context(), dir, key, data, trainingExecution{
			now:   func() time.Time { return at },
			power: func() error { return nil },
			fit: func(ctx context.Context, key string, request []byte) ([]byte, inferenceUsage, error) {
				var result bytes.Buffer
				err := runLocalCandidate(ctx, key, bytes.NewReader(request), &result, func() time.Time { return at })
				return result.Bytes(), inferenceUsage{}, err
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		payload, err := os.ReadFile(filepath.Join(dir, report.PendingFile))
		if err != nil {
			t.Fatal(err)
		}
		var update contracts.FederatedUpdateV1
		if err := json.Unmarshal(payload, &update); err != nil {
			t.Fatal(err)
		}
		if err := update.CheckRound(req.Round, at); err != nil {
			t.Fatal(err)
		}
		if err := update.VerifySignature(identity.signing.Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
		if update.Sequence != contracts.FirstEvidenceSequenceV1 || update.SampleCount != uint32(len(req.Examples)) ||
			bytes.Contains(payload, []byte("failure_within_7d")) || bytes.Contains(payload, []byte("window_start")) {
			t.Fatal("unexpected sequence, sample count or observation in payload")
		}
	})
	t.Run("cancelled attempt", func(t *testing.T) {
		store, dir, _, receipt := admittedStore(t)
		store.close()
		_, key, data := budgetedTrainingFixture(t, at, receipt)
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		called := 0
		run := trainingExecution{
			now:   func() time.Time { return at },
			power: func() error { return nil },
			fit: func(ctx context.Context, key string, request []byte) ([]byte, inferenceUsage, error) {
				called++
				var result bytes.Buffer
				err := runLocalCandidate(ctx, key, bytes.NewReader(request), &result, func() time.Time { return at })
				cancel()
				return result.Bytes(), inferenceUsage{}, err
			},
		}
		if _, err := stageFederatedTraining(ctx, dir, key, data, run); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected cancellation, got %v", err)
		}
		if _, err := stageFederatedTraining(t.Context(), dir, key, data, run); err == nil || called != 1 {
			t.Fatal("cancelled attempt did not retain its cadence reservation")
		}
		matches, err := filepath.Glob(filepath.Join(dir, "federated-update-*"))
		if err != nil || len(matches) != 0 {
			t.Fatalf("cancelled attempt left update files: %v, %v", len(matches), err)
		}
		store, err = openIdentityStore(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		seq, err := store.reserveSequence(receipt)
		if err != nil || seq != contracts.FirstEvidenceSequenceV1 {
			t.Fatalf("cancelled attempt consumed a sequence: %d, %v", seq, err)
		}
	})
}
