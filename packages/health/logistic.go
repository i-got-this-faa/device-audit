package health

import (
	"encoding/json"
	"errors"
	"math"
	"slices"
	"strconv"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// EndpointInferenceRuntime identifies the exact endpoint implementation of the
// ML02 artifact. A publisher manifest must target this runtime explicitly.
func EndpointInferenceRuntime() contracts.ModelRuntimeV1 {
	return contracts.ModelRuntimeV1{
		Name: "device-audit-endpoint-go", Version: "1.0.0",
		Architectures: []string{"logistic-baseline.v1"},
	}
}

type logisticArtifact struct {
	SchemaVersion  string   `json:"schema_version"`
	Architecture   string   `json:"architecture"`
	ModelVersion   string   `json:"model_version"`
	FeatureVersion string   `json:"feature_version"`
	Features       []string `json:"features"`
	Intercept      string   `json:"intercept"`
	Mean           []string `json:"mean"`
	Scale          []string `json:"scale"`
	Weights        []string `json:"weights"`
	PredictorClip  string   `json:"predictor_clip"`
}

// LogisticLogit scores one complete CT03 vector with an artifact that the
// caller has authenticated through CT10.
func LogisticLogit(manifest contracts.ModelManifestV1, artifact []byte, vector contracts.FeatureVectorV1) (float64, error) {
	values, err := ModelInput(vector)
	if err != nil {
		return 0, err
	}
	var model logisticArtifact
	if json.Unmarshal(artifact, &model) != nil ||
		model.SchemaVersion != "device-audit.logistic-baseline.v1" ||
		model.Architecture != manifest.Architecture || model.ModelVersion != manifest.ModelVersion ||
		model.FeatureVersion != manifest.FeatureVersion || vector.FeatureVersion != manifest.FeatureVersion ||
		!slices.Equal(model.Features, manifest.Features) || manifest.ParameterCount != uint32(len(values)+1) ||
		len(model.Mean) != len(values) || len(model.Scale) != len(values) || len(model.Weights) != len(values) {
		return 0, errors.New("logistic artifact layout mismatch")
	}

	score, scoreOK := modelNumber(model.Intercept)
	clip, clipOK := modelNumber(model.PredictorClip)
	if !scoreOK || !clipOK || clip <= 0 {
		return 0, errors.New("invalid logistic intercept or clip")
	}
	for i, value := range values {
		mean, meanOK := modelNumber(model.Mean[i])
		scale, scaleOK := modelNumber(model.Scale[i])
		weight, weightOK := modelNumber(model.Weights[i])
		if !meanOK || !scaleOK || !weightOK || scale <= 0 {
			return 0, errors.New("invalid logistic feature parameter")
		}
		score += weight * ((value - mean) / scale)
	}
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0, errors.New("logistic score is not finite")
	}
	return min(clip, max(-clip, score)), nil
}

func modelNumber(encoded string) (float64, bool) {
	// ML02 stores exact hexadecimal binary64 values.
	value, err := strconv.ParseFloat(encoded, 64)
	return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
}
