package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

const maxLocalTrainingRequest = 8 << 20

type localCandidateRequest struct {
	Round        contracts.FederatedRoundV1 `json:"round"`
	ManifestFile string                     `json:"manifest_file"`
	ArtifactFile string                     `json:"artifact_file"`
	Examples     localTrainingExamples      `json:"examples"`
}

type localTrainingExamples []health.LocalTrainingExample

func (examples *localTrainingExamples) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return errors.New("training examples must be an array")
	}
	var rows localTrainingExamples
	for decoder.More() {
		if len(rows) == health.MaxLocalExamples {
			return errors.New("too many local training examples")
		}
		var row health.LocalTrainingExample
		if err := decoder.Decode(&row); err != nil {
			return err
		}
		rows = append(rows, row)
	}
	_, err = decoder.Token()
	*examples = rows
	return err
}

// This is an operator-local result, not the signed FED03 submission envelope.
type localCandidate struct {
	RoundID          string `json:"round_id"`
	BaseModelVersion string `json:"base_model_version"`
	BaseModelSHA256  string `json:"base_model_sha256"`
	CandidateID      string `json:"candidate_id"`
	FeatureVersion   string `json:"feature_version"`
	TrainingConfig   string `json:"training_config"`
	ParameterCount   uint32 `json:"parameter_count"`
	SampleCount      int    `json:"sample_count"`
	WeightsBase64    string `json:"weights_base64"`
	UpdateSHA256     string `json:"update_sha256"`
}

func runLocalCandidate(ctx context.Context, publisherKeyFile string, input io.Reader, out io.Writer, now func() time.Time) error {
	var req localCandidateRequest
	data, err := readLocalTrainingRequest(input)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(json.RawMessage)) != io.EOF || req.Round.Validate() != nil {
		return errors.New("invalid local training request or round")
	}
	if req.Round.FeatureVersion != contracts.FeatureVersionHDDSMART7DV1 {
		return health.ErrLocalFeatureMismatch
	}
	opened, _ := time.Parse(time.RFC3339, req.Round.OpenedAt)
	deadline, _ := time.Parse(time.RFC3339, req.Round.Deadline)
	started := now()
	if started.Before(opened) || !started.Before(deadline) {
		return errors.New("local training outside round window")
	}
	ctx, cancel := context.WithTimeout(ctx, min(10*time.Minute, deadline.Sub(started)))
	defer cancel()

	manifestData, err := readInferenceFile(req.ManifestFile, maxModelMetadata)
	if err != nil {
		return fmt.Errorf("read training manifest: %w", err)
	}
	var manifest contracts.ModelManifestV1
	if json.Unmarshal(manifestData, &manifest) != nil {
		return errors.New("invalid training manifest")
	}
	if manifest.FeatureVersion != req.Round.FeatureVersion {
		return health.ErrLocalFeatureMismatch
	}
	if manifest.ModelVersion != req.Round.BaseModelVersion || manifest.ArtifactSHA256 != req.Round.BaseModelSHA256 ||
		manifest.ParameterCount != req.Round.ParameterCount {
		return errors.New("training artifact does not match round base")
	}
	artifact, err := readInferenceFile(req.ArtifactFile, contracts.ModelArtifactMaxBytesV1)
	if err != nil {
		return fmt.Errorf("read training artifact: %w", err)
	}
	key, err := loadPinnedEd25519Key(publisherKeyFile)
	if err != nil {
		return fmt.Errorf("load training publisher key: %w", err)
	}
	if err := manifest.CheckActivation(contracts.ModelActivationV1{
		Runtime: health.EndpointInferenceRuntime(), Purpose: "training", Artifact: artifact, TrustedKey: key,
	}); err != nil {
		return fmt.Errorf("verify training base: %w", err)
	}

	weights, err := health.FitLocalLogistic(ctx, manifest, artifact, req.Examples, opened)
	if err != nil {
		return err
	}
	if finished := now(); finished.Before(opened) || !finished.Before(deadline) {
		return errors.New("local training outside round window")
	}
	raw := make([]byte, len(weights)*8)
	for i, weight := range weights {
		binary.BigEndian.PutUint64(raw[i*8:], math.Float64bits(weight))
	}
	digest := sha256.Sum256(raw)
	return json.NewEncoder(out).Encode(localCandidate{
		RoundID: req.Round.RoundID, BaseModelVersion: manifest.ModelVersion,
		BaseModelSHA256: manifest.ArtifactSHA256, CandidateID: req.Round.CandidateID,
		FeatureVersion: manifest.FeatureVersion, TrainingConfig: health.LocalLogisticTrainingV1,
		ParameterCount: manifest.ParameterCount, SampleCount: len(req.Examples),
		WeightsBase64: base64.StdEncoding.EncodeToString(raw), UpdateSHA256: hex.EncodeToString(digest[:]),
	})
}

func readLocalTrainingRequest(input io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(input, maxLocalTrainingRequest+1))
	if err != nil || len(data) > maxLocalTrainingRequest {
		return nil, errors.New("invalid bounded local training request")
	}
	return data, nil
}
