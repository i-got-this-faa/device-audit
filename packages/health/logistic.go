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

type logisticParameters struct {
	weights, mean, scale []float64
	clip                 float64
}

// LogisticLogit scores one complete CT03 vector with an artifact that the
// caller has authenticated through CT10.
func LogisticLogit(manifest contracts.ModelManifestV1, artifact []byte, vector contracts.FeatureVectorV1) (float64, error) {
	values, err := ModelInput(vector)
	if err != nil {
		return 0, err
	}
	if vector.FeatureVersion != manifest.FeatureVersion {
		return 0, errors.New("logistic feature version mismatch")
	}
	model, err := readLogisticParameters(manifest, artifact)
	if err != nil {
		return 0, err
	}
	score := model.weights[0]
	for i, value := range values {
		score += model.weights[i+1] * ((value - model.mean[i]) / model.scale[i])
	}
	if math.IsNaN(score) || math.IsInf(score, 0) {
		return 0, errors.New("logistic score is not finite")
	}
	return min(model.clip, max(-model.clip, score)), nil
}

func readLogisticParameters(manifest contracts.ModelManifestV1, artifact []byte) (logisticParameters, error) {
	var params logisticParameters
	names, _, err := contracts.FeatureNamesV1(manifest.FeatureVersion)
	if err != nil {
		return params, err
	}
	featureCount := len(names)
	var model logisticArtifact
	if json.Unmarshal(artifact, &model) != nil ||
		model.SchemaVersion != "device-audit.logistic-baseline.v1" ||
		model.Architecture != manifest.Architecture || model.ModelVersion != manifest.ModelVersion ||
		model.FeatureVersion != manifest.FeatureVersion || !slices.Equal(model.Features, manifest.Features) ||
		manifest.ParameterCount != uint32(featureCount+1) ||
		len(model.Mean) != featureCount || len(model.Scale) != featureCount || len(model.Weights) != featureCount {
		return params, errors.New("logistic artifact layout mismatch")
	}

	intercept, interceptOK := modelNumber(model.Intercept)
	clip, clipOK := modelNumber(model.PredictorClip)
	if !interceptOK || !clipOK || clip <= 0 {
		return params, errors.New("invalid logistic intercept or clip")
	}
	params = logisticParameters{
		weights: make([]float64, featureCount+1), mean: make([]float64, featureCount),
		scale: make([]float64, featureCount), clip: clip,
	}
	params.weights[0] = intercept
	for i := range featureCount {
		mean, meanOK := modelNumber(model.Mean[i])
		scale, scaleOK := modelNumber(model.Scale[i])
		weight, weightOK := modelNumber(model.Weights[i])
		if !meanOK || !scaleOK || !weightOK || scale <= 0 {
			return logisticParameters{}, errors.New("invalid logistic feature parameter")
		}
		params.mean[i], params.scale[i], params.weights[i+1] = mean, scale, weight
	}
	return params, nil
}

func modelNumber(encoded string) (float64, bool) {
	// ML02 stores exact hexadecimal binary64 values.
	value, err := strconv.ParseFloat(encoded, 64)
	return value, err == nil && !math.IsNaN(value) && !math.IsInf(value, 0)
}
