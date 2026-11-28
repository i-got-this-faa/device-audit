package federated

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestWeightedAverageAndReproducibleLogisticCandidate(t *testing.T) {
	baseArtifact, err := os.ReadFile(filepath.Join("..", "..", "models", "baseline", "backblaze-2013", "artifact.json"))
	if err != nil {
		t.Fatal(err)
	}
	baseSum := sha256.Sum256(baseArtifact)
	baseSHA := hex.EncodeToString(baseSum[:])
	features, _, err := contracts.FeatureNamesV1(contracts.FeatureVersionHDDSMART7DV1)
	if err != nil {
		t.Fatal(err)
	}
	baseManifest := contracts.ModelManifestV1{
		SchemaVersion:  contracts.ModelManifestV1Version,
		ModelVersion:   "logistic-baseline.backblaze-2013.v1",
		ArtifactSHA256: baseSHA,
		Architecture:   "logistic-baseline.v1",
		ParameterCount: 7,
		RuntimeName:    "device-audit-controller-go",
		RuntimeVersion: "1.0.0",
		FeatureVersion: contracts.FeatureVersionHDDSMART7DV1,
		Features:       features,
		Purposes:       []string{contracts.ModelPurposeTraining, contracts.ModelPurposeInference},
	}
	round := contracts.FederatedRoundV1{
		SchemaVersion:    contracts.FederatedRoundV1Version,
		DeploymentID:     "deployment:fed03",
		RoundID:          "round:fed03:1",
		BaseModelVersion: baseManifest.ModelVersion,
		BaseModelSHA256:  baseSHA,
		CandidateID:      "candidate:fed03:1",
		FeatureVersion:   contracts.FeatureVersionHDDSMART7DV1,
		ParameterCount:   7,
		OpenedAt:         "2026-11-28T12:00:00Z",
		Deadline:         "2026-11-28T13:00:00Z",
		MinParticipants:  2,
		Participants: []contracts.FederatedParticipantV1{
			{DeviceID: "device:b", SigningKeyID: "ed25519:" + strings.Repeat("b", 64), Eligibility: "eligible"},
			{DeviceID: "device:a", SigningKeyID: "ed25519:" + strings.Repeat("a", 64), Eligibility: "eligible"},
		},
	}
	updates := []AcceptedUpdate{
		{
			DeploymentID: round.DeploymentID, RoundID: round.RoundID, CandidateID: round.CandidateID,
			BaseModelVersion: round.BaseModelVersion, BaseModelSHA256: round.BaseModelSHA256,
			FeatureVersion: round.FeatureVersion, ParameterCount: 7,
			DeviceID: "device:b", SigningKeyID: "ed25519:" + strings.Repeat("b", 64), Sequence: 2,
			SampleCount: 30, Weights: []float64{6, 8, 10, 12, 14, 16, 18},
			UpdateSHA256: strings.Repeat("2", 64), RequestSHA256: strings.Repeat("4", 64),
		},
		{
			DeploymentID: round.DeploymentID, RoundID: round.RoundID, CandidateID: round.CandidateID,
			BaseModelVersion: round.BaseModelVersion, BaseModelSHA256: round.BaseModelSHA256,
			FeatureVersion: round.FeatureVersion, ParameterCount: 7,
			DeviceID: "device:a", SigningKeyID: "ed25519:" + strings.Repeat("a", 64), Sequence: 2,
			SampleCount: 10, Weights: []float64{2, 4, 6, 8, 10, 12, 14},
			UpdateSHA256: strings.Repeat("1", 64), RequestSHA256: strings.Repeat("3", 64),
		},
	}

	weights, total, err := WeightedAverage(round, updates)
	if err != nil || total != 40 {
		t.Fatalf("weighted average failed: total=%d err=%v", total, err)
	}
	wantWeights := []float64{5, 7, 9, 11, 13, 15, 17}
	for i := range wantWeights {
		if weights[i] != wantWeights[i] {
			t.Fatalf("weight[%d]=%v want %v", i, weights[i], wantWeights[i])
		}
	}

	// Ordering of input slices does not affect input_sha256 or candidate bytes.
	reversed := []AcceptedUpdate{updates[1], updates[0]}
	partA := make([]AggregatedParticipant, 2)
	partB := make([]AggregatedParticipant, 2)
	for i, u := range updates {
		partA[i] = AggregatedParticipant{DeviceID: u.DeviceID, SigningKeyID: u.SigningKeyID, Sequence: u.Sequence, SampleCount: u.SampleCount, UpdateSHA256: u.UpdateSHA256, RequestSHA256: u.RequestSHA256}
		ru := reversed[i]
		partB[i] = AggregatedParticipant{DeviceID: ru.DeviceID, SigningKeyID: ru.SigningKeyID, Sequence: ru.Sequence, SampleCount: ru.SampleCount, UpdateSHA256: ru.UpdateSHA256, RequestSHA256: ru.RequestSHA256}
	}
	in1, t1, err := AggregationInputSHA256(round, WeightingPolicySampleCountV1, partA)
	in2, t2, err2 := AggregationInputSHA256(round, WeightingPolicySampleCountV1, partB)
	if err != nil || err2 != nil || t1 != 40 || t2 != 40 || in1 != in2 {
		t.Fatalf("input digest mismatch: in1=%s in2=%s err=%v err2=%v", in1, in2, err, err2)
	}
	rawWeights, err := EncodeBinary64Weights(weights)
	if err != nil {
		t.Fatal(err)
	}
	wSum := sha256.Sum256(rawWeights)
	cand1, err := BuildCandidateArtifact(round, baseManifest, baseArtifact, weights, hex.EncodeToString(wSum[:]), in1, 2, total)
	if err != nil {
		t.Fatal(err)
	}
	cand2, err := BuildCandidateArtifact(round, baseManifest, baseArtifact, weights, hex.EncodeToString(wSum[:]), in2, 2, total)
	if err != nil || string(cand1) != string(cand2) {
		t.Fatalf("non-reproducible candidate: err=%v", err)
	}

	// Verify exact parity digest matches Python reference (pinned by models/tests/test_federated.py).
	const wantInputSHA = "bca4312ae1bf578677a758b61ffcdc80543f724e346ad72eaef45564599299c5"
	const wantCandSHA = "e300389821efb716a3202090b09a4149429894158583301a83a5a89a511d5e77"
	if in1 != wantInputSHA {
		t.Fatalf("input digest=%s want Python parity %s", in1, wantInputSHA)
	}
	candSum := sha256.Sum256(cand1)
	if gotCandSHA := hex.EncodeToString(candSum[:]); gotCandSHA != wantCandSHA {
		t.Fatalf("candidate digest=%s want Python parity %s", gotCandSHA, wantCandSHA)
	}
	// FormatPythonHexFloat edge cases.
	for _, tc := range []struct {
		v    float64
		want string
	}{
		{0.0, "0x0.0p+0"},
		{math.Copysign(0.0, -1), "-0x0.0p+0"},
		{1.0, "0x1.0000000000000p+0"},
		{-0.5, "-0x1.0000000000000p-1"},
	} {
		got, err := FormatPythonHexFloat(tc.v)
		if err != nil || got != tc.want {
			t.Fatalf("FormatPythonHexFloat(%v) = %q, %v want %q", tc.v, got, err, tc.want)
		}
	}

	// Negative zero summation + non-ASCII UTF-8 + scientific numeric metadata parity with Python.
	negZero := math.Copysign(0.0, -1)
	nzRound := round
	nzRound.CandidateID = "candidate:fed03:canonical"
	nzUpdates := []AcceptedUpdate{
		{
			DeploymentID: nzRound.DeploymentID, RoundID: nzRound.RoundID, CandidateID: nzRound.CandidateID,
			BaseModelVersion: nzRound.BaseModelVersion, BaseModelSHA256: nzRound.BaseModelSHA256,
			FeatureVersion: nzRound.FeatureVersion, ParameterCount: 7,
			DeviceID: "device:a", SigningKeyID: "ed25519:" + strings.Repeat("a", 64), Sequence: 2,
			SampleCount: 10, Weights: []float64{negZero, 1, 2, 3, 4, 5, 6},
		},
		{
			DeploymentID: nzRound.DeploymentID, RoundID: nzRound.RoundID, CandidateID: nzRound.CandidateID,
			BaseModelVersion: nzRound.BaseModelVersion, BaseModelSHA256: nzRound.BaseModelSHA256,
			FeatureVersion: nzRound.FeatureVersion, ParameterCount: 7,
			DeviceID: "device:b", SigningKeyID: "ed25519:" + strings.Repeat("b", 64), Sequence: 2,
			SampleCount: 10, Weights: []float64{negZero, 1, 2, 3, 4, 5, 6},
		},
	}
	nzWeights, nzTotal, err := WeightedAverage(nzRound, nzUpdates)
	if err != nil || nzTotal != 20 {
		t.Fatalf("negative zero weighted average failed: total=%d err=%v", nzTotal, err)
	}
	if hex0, _ := FormatPythonHexFloat(nzWeights[0]); hex0 != "0x0.0p+0" {
		t.Fatalf("negative zero weighted average=%s want +0.0 (0x0.0p+0) to match Python fsum", hex0)
	}
	var baseObj map[string]any
	dec := json.NewDecoder(bytes.NewReader(baseArtifact))
	dec.UseNumber()
	if err := dec.Decode(&baseObj); err != nil {
		t.Fatal(err)
	}
	baseObj["label"] = "café\b\f\t<>&\u2028"
	baseObj["raw_sci"] = json.Number("1e0")
	baseObj["neg_zero"] = json.Number("-0.0")
	baseObj["small_exp"] = json.Number("1e-5")
	baseObj["big_exp"] = json.Number("1e16")
	baseObj["int_count"] = 42
	rawMetaBase, err := encodeCanonicalJSON(baseObj)
	if err != nil {
		t.Fatal(err)
	}
	rawMetaBase = bytes.Replace(rawMetaBase, []byte(`"raw_sci":1.0`), []byte(`"raw_sci":1e0`), 1)
	rawMetaBase = bytes.TrimSuffix(rawMetaBase, []byte("\n"))
	metaBaseSum := sha256.Sum256(rawMetaBase)
	nzRound.BaseModelSHA256 = hex.EncodeToString(metaBaseSum[:])
	nzManifest := baseManifest
	nzManifest.ArtifactSHA256 = nzRound.BaseModelSHA256
	nzRawW, _ := EncodeBinary64Weights(nzWeights)
	nzWSum := sha256.Sum256(nzRawW)
	candMeta, err := BuildCandidateArtifact(nzRound, nzManifest, rawMetaBase, nzWeights, hex.EncodeToString(nzWSum[:]), in1, 2, nzTotal)
	if err != nil {
		t.Fatal(err)
	}
	const wantMetaCandSHA = "d0644649a39752895b583494ed90bdccfea5c3ffd79e657dcc7cac78108ee055"
	candMetaSum := sha256.Sum256(candMeta)
	if got := hex.EncodeToString(candMetaSum[:]); got != wantMetaCandSHA {
		t.Fatalf("canonical metadata/negative-zero candidate=%s want Python parity %s\nbody=%s", got, wantMetaCandSHA, candMeta)
	}
}
