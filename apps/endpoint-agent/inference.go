package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

const (
	inferenceCadence    = time.Hour
	inferenceTimeout    = 2 * time.Second
	inferenceMaxLatency = time.Second
	inferencePolicy     = "9a5d1e1e490b81b701cd86fb739d80a3b4bdbe2330c489d38265ec40e84e3d48"
	inferenceHorizon    = 168
	maxModelMetadata    = 128 << 10
)

var (
	errInferenceCPU     = errors.New("cpu_budget")
	errInferenceMemory  = errors.New("memory_budget")
	errInferenceLatency = errors.New("latency_budget")
	errInferenceOutput  = errors.New("output_budget")
)

func inferenceFailureCode(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, errInferenceCPU), errors.Is(err, errInferenceMemory),
		errors.Is(err, errInferenceLatency), errors.Is(err, errInferenceOutput):
		return err.Error()
	default:
		return "worker_unavailable"
	}
}

type inferenceConfig struct {
	ManifestFile         string `json:"manifest_file"`
	ArtifactFile         string `json:"artifact_file"`
	PublisherKeyFile     string `json:"publisher_key_file"`
	EvaluationFile       string `json:"evaluation_file"`
	EvaluationSHA256     string `json:"evaluation_sha256"`
	StagedEvaluationFile string `json:"staged_evaluation_file,omitempty"`
}

func (c inferenceConfig) paths() []string {
	paths := []string{c.ManifestFile, c.ArtifactFile, c.PublisherKeyFile, c.EvaluationFile}
	if c.StagedEvaluationFile != "" {
		paths = append(paths, c.StagedEvaluationFile)
	}
	return paths
}

type inferenceRequest struct {
	Config   inferenceConfig           `json:"config"`
	Features contracts.FeatureVectorV1 `json:"features"`
}

type inferenceResult struct {
	Model  *contracts.ModelReferenceV2 `json:"model_reference"`
	Health contracts.HealthV2          `json:"health"`
}

func unknownInference(reason string) inferenceResult {
	return inferenceResult{Health: contracts.HealthV2{
		Status: "unknown", ProbabilityUnit: "probability", UnknownReason: reason,
	}}
}

type inferenceEvaluation struct {
	SchemaVersion  string `json:"schema_version"`
	PolicySHA256   string `json:"policy_sha256"`
	Partition      string `json:"partition"`
	HorizonHours   uint32 `json:"horizon_hours"`
	EvaluationRuns int    `json:"test_evaluations_for_candidate"`
	Model          struct {
		Version string `json:"version"`
		SHA256  string `json:"artifact_sha256"`
	} `json:"model"`
	Gate struct {
		Status       string `json:"status"`
		PolicySHA256 string `json:"policy_sha256"`
	} `json:"gate"`
	OperatingPoints struct {
		Degraded *float64 `json:"degraded_logit"`
		Critical *float64 `json:"critical_logit"`
	} `json:"operating_points"`
}

func approvedEvaluation(c inferenceConfig, m contracts.ModelManifestV1) (inferenceEvaluation, error) {
	var report inferenceEvaluation
	payload, err := readInferenceFile(c.EvaluationFile, maxModelMetadata)
	if err != nil {
		return report, err
	}
	return checkInferenceEvaluation(c.EvaluationSHA256, m, payload)
}

func checkInferenceEvaluation(expectedSHA string, m contracts.ModelManifestV1, payload []byte) (inferenceEvaluation, error) {
	var report inferenceEvaluation
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != expectedSHA ||
		json.Unmarshal(payload, &report) != nil ||
		report.SchemaVersion != "device-audit.evaluation-report.v1" ||
		report.PolicySHA256 != inferencePolicy || report.Gate.PolicySHA256 != inferencePolicy ||
		report.EvaluationRuns != 1 || report.Partition != "test" ||
		report.HorizonHours != inferenceHorizon || report.Model.Version != m.ModelVersion ||
		report.Model.SHA256 != m.ArtifactSHA256 || report.Gate.Status != "pass" {
		return report, errors.New("approved passing evaluation for this artifact is unavailable")
	}
	points := report.OperatingPoints
	if points.Degraded == nil || points.Critical == nil ||
		math.IsNaN(*points.Degraded) || math.IsNaN(*points.Critical) ||
		math.IsInf(*points.Degraded, 0) || math.IsInf(*points.Critical, 0) ||
		*points.Critical < *points.Degraded {
		return report, errors.New("invalid evaluation operating points")
	}
	return report, nil
}

func readInferenceFile(path string, limit int64) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("inference file path must be absolute")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("inference file is unreadable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("invalid inference file type or size")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("inference file is unreadable or too large")
	}
	return data, nil
}

func infer(req inferenceRequest) (inferenceResult, error) {
	if _, err := health.ModelInput(req.Features); err != nil {
		if errors.Is(err, health.ErrIncompleteFeatures) {
			return unknownInference("insufficient_evidence"), nil
		}
		return inferenceResult{}, err
	}
	manifest, artifact, report, err := loadInferenceBundle(req.Config)
	if err != nil {
		return inferenceResult{}, err
	}
	logit, err := health.LogisticLogit(manifest, artifact, req.Features)
	if err != nil {
		return inferenceResult{}, err
	}

	status := "healthy"
	switch {
	case logit >= *report.OperatingPoints.Critical:
		status = "critical"
	case logit >= *report.OperatingPoints.Degraded:
		status = "degraded"
	}
	p := 1 / (1 + math.Exp(-logit))
	return inferenceResult{
		Model:  &contracts.ModelReferenceV2{Version: manifest.ModelVersion, SHA256: manifest.ArtifactSHA256},
		Health: contracts.HealthV2{Status: status, Probability: &p, ProbabilityUnit: "probability", HorizonHours: &report.HorizonHours},
	}, nil
}

func loadInferenceBundle(c inferenceConfig) (contracts.ModelManifestV1, []byte, inferenceEvaluation, error) {
	var manifest contracts.ModelManifestV1
	manifestBytes, err := readInferenceFile(c.ManifestFile, maxModelMetadata)
	if err != nil {
		return manifest, nil, inferenceEvaluation{}, err
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return manifest, nil, inferenceEvaluation{}, err
	}
	key, err := loadPinnedEd25519Key(c.PublisherKeyFile)
	if err != nil {
		return manifest, nil, inferenceEvaluation{}, err
	}
	artifact, err := readInferenceFile(c.ArtifactFile, contracts.ModelArtifactMaxBytesV1)
	if err != nil {
		return manifest, nil, inferenceEvaluation{}, err
	}
	if err := manifest.CheckActivation(contracts.ModelActivationV1{
		Runtime: health.EndpointInferenceRuntime(), Purpose: "inference", Artifact: artifact, TrustedKey: key,
	}); err != nil {
		return manifest, nil, inferenceEvaluation{}, err
	}
	report, err := approvedEvaluation(c, manifest)
	if err != nil {
		return manifest, nil, inferenceEvaluation{}, err
	}
	return manifest, artifact, report, nil
}

func runInferenceWorker(in io.Reader, out, stderr io.Writer) int {
	const maxRequest = 32 << 10
	payload, err := io.ReadAll(io.LimitReader(in, maxRequest+1))
	var req inferenceRequest
	if err != nil || len(payload) > maxRequest || json.Unmarshal(payload, &req) != nil {
		fmt.Fprintln(stderr, "invalid inference request")
		return 1
	}
	result, err := infer(req)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 1
	}
	return 0
}

type inferenceRunner func(context.Context, inferenceRequest) (inferenceResult, error)

func executeInferenceWorker(ctx context.Context, req inferenceRequest) (inferenceResult, error) {
	path, err := os.Executable()
	if err != nil {
		return inferenceResult{}, err
	}
	return runInferenceProcess(ctx, req, path, "--inference-worker")
}

func runInferenceProcess(ctx context.Context, req inferenceRequest, path string, args ...string) (inferenceResult, error) {
	result, _, err := measureInferenceProcess(ctx, req, path, args...)
	return result, err
}

type inferenceUsage struct {
	Latency time.Duration
	CPU     time.Duration
	PeakRSS uint64
}

func measureInferenceProcess(ctx context.Context, req inferenceRequest, path string, args ...string) (inferenceResult, inferenceUsage, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, inferenceTimeout)
	defer cancel()
	data, err := json.Marshal(req)
	if err != nil {
		return inferenceResult{}, inferenceUsage{}, err
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = 100 * time.Millisecond
	output := &limitedWorkerOutput{limit: 4096, cancel: cancel}
	cmd.Stdout = output
	usage, err := runInferenceChild(ctx, cmd, data)
	usage.Latency = time.Since(start)
	if output.exceeded {
		return inferenceResult{}, usage, errInferenceOutput
	}
	if ctx.Err() != nil {
		return inferenceResult{}, usage, ctx.Err()
	}
	if err != nil {
		return inferenceResult{}, usage, err
	}
	if usage.Latency > inferenceMaxLatency {
		return inferenceResult{}, usage, errInferenceLatency
	}
	var result inferenceResult
	if err := json.Unmarshal(output.data, &result); err != nil {
		return inferenceResult{}, usage, errors.New("invalid inference worker reply")
	}
	return result, usage, nil
}

type inferenceSample struct {
	deviceID string
	digest   string
	at       time.Time
	readings []health.SMARTReading
}

func predictSample(ctx context.Context, c inferenceConfig, sample inferenceSample, now time.Time, run inferenceRunner) contracts.PredictionV2 {
	p := contracts.PredictionV2{
		SchemaVersion: contracts.PredictionV2Version, DeviceID: sample.deviceID,
		GeneratedAt: now, ExpiresAt: now.Add(inferenceCadence),
		Evidence:  &contracts.EvidenceV2{Digest: sample.digest, TelemetrySchemaVersion: contracts.TelemetryV2Version},
		Forecasts: []contracts.FaultForecastV2{},
	}
	result := unknownInference("stale_evidence")
	if !sample.at.After(now) && now.Sub(sample.at) < inferenceCadence {
		result = unknownInference("model_unavailable")
		vector, err := health.Preprocess(sample.at, sample.readings)
		if err == nil {
			timeout, cancel := context.WithTimeout(ctx, inferenceTimeout)
			defer cancel()
			if reply, err := run(timeout, inferenceRequest{Config: c, Features: vector}); err == nil && timeout.Err() == nil {
				p.Model, p.Health = reply.Model, reply.Health
				if p.Validate() == nil {
					return p
				}
			}
		}
	}
	p.Model, p.Health = result.Model, result.Health
	return p
}
