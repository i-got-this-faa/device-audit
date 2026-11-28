package health

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	LocalLogisticTrainingV1 = "local-logistic-full-batch.v1"
	minLocalExamples        = 8
	MaxLocalExamples        = 4096
	localTrainingSteps      = 8
	localLearningRate       = 0.01
)

var (
	ErrLocalFeatureMismatch      = errors.New("incompatible_features")
	ErrInsufficientLocalExamples = errors.New("insufficient_local_data")
	ErrInvalidLocalExample       = errors.New("invalid_local_example")
)

// LocalTrainingExample pairs a CT03 vector with a locally observed seven-day
// outcome. A nil label means the outcome could not be ascertained.
type LocalTrainingExample struct {
	Features        contracts.FeatureVectorV1 `json:"features"`
	FailureWithin7D *bool                     `json:"failure_within_7d"`
}

// FitLocalLogistic starts at the verified base and updates its intercept and
// coefficients in base-artifact order. Normalization and clipping stay fixed.
// The caller authenticates the artifact and supplies the round's opening time
// as the latest time an outcome can have been observed.
func FitLocalLogistic(ctx context.Context, manifest contracts.ModelManifestV1, artifact []byte, examples []LocalTrainingExample, cutoff time.Time) ([]float64, error) {
	model, err := readLogisticParameters(manifest, artifact)
	if err != nil {
		return nil, err
	}
	if len(examples) < minLocalExamples {
		return nil, ErrInsufficientLocalExamples
	}
	if len(examples) > MaxLocalExamples {
		return nil, ErrInvalidLocalExample
	}
	dimension := len(model.weights)
	rows := make([]float64, len(examples)*dimension)
	positive := 0
	var previousDay time.Time
	for i, example := range examples {
		if example.Features.FeatureVersion != manifest.FeatureVersion {
			return nil, ErrLocalFeatureMismatch
		}
		values, err := ModelInput(example.Features)
		if errors.Is(err, ErrIncompleteFeatures) || example.FailureWithin7D == nil {
			return nil, ErrInsufficientLocalExamples
		}
		if err != nil {
			return nil, ErrInvalidLocalExample
		}
		asOf, err := time.Parse(time.RFC3339, example.Features.AsOf)
		day := asOf.UTC().Truncate(24 * time.Hour)
		if err != nil || !day.After(previousDay) || asOf.Add(7*24*time.Hour).After(cutoff) {
			return nil, ErrInvalidLocalExample
		}
		previousDay = day
		if *example.FailureWithin7D {
			positive++
		}
		row := rows[i*dimension : (i+1)*dimension]
		row[0] = 1
		for j, value := range values {
			row[j+1] = (value - model.mean[j]) / model.scale[j]
		}
	}
	if positive == 0 || positive == len(examples) {
		return nil, ErrInsufficientLocalExamples
	}
	gradient := make([]float64, dimension)
	for range localTrainingSteps {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		clear(gradient)
		for i, example := range examples {
			row := rows[i*dimension : (i+1)*dimension]
			logit := model.weights[0]
			for j := 1; j < dimension; j++ {
				logit += model.weights[j] * row[j]
			}
			if math.IsNaN(logit) || math.IsInf(logit, 0) {
				return nil, ErrInvalidLocalExample
			}
			logit = min(model.clip, max(-model.clip, logit))
			residual := 1 / (1 + math.Exp(-logit))
			if *example.FailureWithin7D {
				residual--
			}
			for j, value := range row {
				gradient[j] += residual * value
			}
		}
		for j, value := range gradient {
			model.weights[j] -= localLearningRate * (value / float64(len(examples)))
			if math.IsNaN(model.weights[j]) || math.IsInf(model.weights[j], 0) {
				return nil, ErrInvalidLocalExample
			}
		}
	}
	return model.weights, ctx.Err()
}
