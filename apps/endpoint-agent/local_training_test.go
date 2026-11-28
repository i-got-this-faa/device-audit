package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

func TestLocalCandidate(t *testing.T) {
	inference, manifest, publisher, _ := testInferenceBundle(t)
	at, err := time.Parse(time.RFC3339, inference.Features.AsOf)
	if err != nil {
		t.Fatal(err)
	}
	req := localCandidateRequest{
		Round: contracts.FederatedRoundV1{
			SchemaVersion: contracts.FederatedRoundV1Version,
			DeploymentID:  "test-deployment", RoundID: "local-training", CandidateID: "candidate",
			BaseModelVersion: manifest.ModelVersion, BaseModelSHA256: manifest.ArtifactSHA256,
			FeatureVersion: manifest.FeatureVersion, ParameterCount: manifest.ParameterCount,
			OpenedAt: at.Format(time.RFC3339), Deadline: at.Add(time.Hour).Format(time.RFC3339),
			MinParticipants: 2,
			Participants: []contracts.FederatedParticipantV1{
				{DeviceID: "fixture-a", SigningKeyID: manifest.SigningKeyID, Eligibility: "eligible"},
				{DeviceID: "fixture-b", SigningKeyID: manifest.SigningKeyID, Eligibility: "eligible"},
			},
		},
		ManifestFile: inference.Config.ManifestFile, ArtifactFile: inference.Config.ArtifactFile,
	}
	req.Examples = localTrainingFixtureExamples(inference.Features, at)
	fit := func(input localCandidateRequest, now time.Time, out io.Writer) error {
		t.Helper()
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		return runLocalCandidate(t.Context(), inference.Config.PublisherKeyFile, bytes.NewReader(data), out, func() time.Time { return now })
	}
	var output bytes.Buffer
	if err := fit(req, at, &output); !errors.Is(err, contracts.ModelRejectionPurposeUnsupported) || output.Len() != 0 {
		t.Fatalf("inference-only base: %v", err)
	}
	manifest.Purposes = []string{"training"}
	signInferenceManifest(t, inference.Config, manifest, publisher)
	var first, repeat, other bytes.Buffer
	if err := fit(req, at, &first); err != nil {
		t.Fatal(err)
	}
	if err := fit(req, at, &repeat); err != nil || !bytes.Equal(first.Bytes(), repeat.Bytes()) {
		t.Fatalf("nondeterministic candidate: %v", err)
	}
	noFailure := false
	req.Examples[4].FailureWithin7D = &noFailure
	if err := fit(req, at, &other); err != nil || bytes.Equal(first.Bytes(), other.Bytes()) {
		t.Fatalf("distinct local labels produced the same candidate: %v", err)
	}
	for _, data := range [][]byte{first.Bytes(), other.Bytes()} {
		var candidate localCandidate
		if err := json.Unmarshal(data, &candidate); err != nil {
			t.Fatal(err)
		}
		weights, err := contracts.DecodeFederatedWeightsV1(candidate.WeightsBase64)
		raw, _ := base64.StdEncoding.DecodeString(candidate.WeightsBase64)
		digest := sha256.Sum256(raw)
		if err != nil || len(weights) != int(req.Round.ParameterCount) || candidate.ParameterCount != req.Round.ParameterCount ||
			candidate.SampleCount != len(req.Examples) || candidate.BaseModelSHA256 != req.Round.BaseModelSHA256 ||
			candidate.FeatureVersion != req.Round.FeatureVersion || candidate.TrainingConfig != health.LocalLogisticTrainingV1 ||
			candidate.UpdateSHA256 != hex.EncodeToString(digest[:]) || bytes.Contains(data, []byte("failure_within_7d")) ||
			bytes.Contains(data, []byte("window_start")) {
			t.Fatalf("candidate metadata, weights or data boundary failed: %v", err)
		}
	}
	withoutEnough := req
	withoutEnough.Examples = req.Examples[:7]
	if err := fit(withoutEnough, at, &output); !errors.Is(err, health.ErrInsufficientLocalExamples) || output.Len() != 0 {
		t.Fatalf("short history: %v", err)
	}
	req.Examples[0].Features.FeatureVersion = "unsupported.v1"
	if err := fit(req, at, &output); !errors.Is(err, health.ErrLocalFeatureMismatch) || output.Len() != 0 {
		t.Fatalf("feature mismatch: %v", err)
	}
	req.Examples[0].Features.FeatureVersion = manifest.FeatureVersion
	req.Examples[1].Features = req.Examples[0].Features
	if err := fit(req, at, &output); !errors.Is(err, health.ErrInvalidLocalExample) || output.Len() != 0 {
		t.Fatalf("duplicate observation day: %v", err)
	}
	if err := fit(req, at.Add(time.Hour), &output); err == nil || output.Len() != 0 {
		t.Fatalf("expired round: %v", err)
	}
}

func localTrainingFixtureExamples(vector contracts.FeatureVectorV1, at time.Time) localTrainingExamples {
	var examples localTrainingExamples
	for i := range 8 {
		day := at.AddDate(0, 0, i-14)
		vector.AsOf = day.Format(time.RFC3339)
		vector.WindowStart = day.AddDate(0, 0, 1-contracts.FeatureWindowDays).Format(time.DateOnly)
		vector.WindowEnd = day.Format(time.DateOnly)
		failure := i >= 4
		examples = append(examples, health.LocalTrainingExample{Features: vector, FailureWithin7D: &failure})
	}
	return examples
}
