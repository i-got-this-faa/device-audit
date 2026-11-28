package health

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// Pinned ML05 evaluation and ML01 dataset policy constants from
// models/evaluation/ml05-policy.json.
const (
	ML05PolicyVersion                  = "ml05.v1"
	ML05PolicySHA256                   = "9a5d1e1e490b81b701cd86fb739d80a3b4bdbe2330c489d38265ec40e84e3d48"
	ML01PartitionManifestSHA256        = "a786dfefa4254308b65d7fd2a9d5a785976b2dc22b8ab26892e4b2f60a1be025"
	ML05HorizonHours            uint32 = 168

	EvaluationReportV1Version = "device-audit.evaluation-report.v1"
	EvaluationGateV1Version   = "device-audit.evaluation-gate.v1"
	MaxEvaluationReportBytes  = 1 << 20
	MaxEvidenceAge            = time.Hour
)

// ErrEvaluationRejected marks an ML05 evaluation report that is malformed,
// tampered, blocked, failed, or mismatched with the policy or artifact.
var ErrEvaluationRejected = errors.New("evaluation report rejected")

var lowerHexSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type ml05GateSpec struct {
	id        string
	kind      string
	metric    string
	bound     string
	op        string
	threshold float64
}

var ml05Gates = []ml05GateSpec{
	{"baseline_average_precision", "baseline", "average_precision_minus_best_baseline", "lower", ">", 0.0},
	{"baseline_event_recall", "baseline", "event_recall_minus_smart_rule", "lower", ">=", -0.05},
	{"discrimination_roc_auc", "baseline", "roc_auc", "lower", ">=", 0.70},
	{"window_fpr_degraded", "false_positive", "window_false_positive_rate_degraded", "upper", "<=", 0.01},
	{"window_fpr_critical", "false_positive", "window_false_positive_rate_critical", "upper", "<=", 0.002},
	{"device_false_alarm", "false_positive", "never_positive_device_alert_fraction", "upper", "<=", 0.10},
	{"brier_skill", "calibration", "brier_skill_vs_prevalence", "lower", ">", 0.0},
	{"observed_expected_low", "calibration", "observed_to_expected_ratio", "point", ">=", 0.67},
	{"observed_expected_high", "calibration", "observed_to_expected_ratio", "point", "<=", 1.5},
	{"calibration_slope_low", "calibration", "calibration_slope", "point", ">=", 0.7},
	{"calibration_slope_high", "calibration", "calibration_slope", "point", "<=", 1.3},
	{"event_recall_point", "horizon", "event_recall_within_horizon", "point", ">=", 0.30},
	{"event_recall_lower", "horizon", "event_recall_within_horizon", "lower", ">=", 0.15},
	{"median_lead_time", "horizon", "median_first_alert_lead_days", "point", ">=", 2.0},
}

type evaluationReportWire struct {
	SchemaVersion           string                    `json:"schema_version"`
	PolicySHA256            string                    `json:"policy_sha256"`
	PartitionManifestSHA256 string                    `json:"partition_manifest_sha256"`
	Partition               string                    `json:"partition"`
	HorizonHours            uint32                    `json:"horizon_hours"`
	Evaluations             int                       `json:"test_evaluations_for_candidate"`
	LabelStatus             string                    `json:"label_status"`
	EvaluationError         string                    `json:"evaluation_error"`
	Bootstrap               evaluationBootstrapWire   `json:"bootstrap"`
	Model                   *evaluationModelWire      `json:"model"`
	Counts                  evaluationCountsWire      `json:"counts"`
	Metrics                 map[string]metricInterval `json:"metrics"`
	OperatingPoints         evaluationOperatingPoints `json:"operating_points"`
	Gate                    evaluationGateWire        `json:"gate"`
}

type evaluationBootstrapWire struct {
	Unit       string  `json:"unit"`
	Replicates int     `json:"replicates"`
	Seed       int     `json:"seed"`
	Interval   float64 `json:"interval"`
	Method     string  `json:"method"`
}

type evaluationModelWire struct {
	Version string `json:"version"`
	SHA256  string `json:"artifact_sha256"`
}

type evaluationCountsWire struct {
	TestPositiveEvents        *int `json:"test_positive_events"`
	TestPositiveWindows       *int `json:"test_positive_windows"`
	TestNegativeWindows       *int `json:"test_negative_windows"`
	TestDevices               *int `json:"test_devices"`
	ValidationNegativeWindows *int `json:"validation_negative_windows"`
}

type metricInterval struct {
	Point *float64 `json:"point"`
	Lower *float64 `json:"lower"`
	Upper *float64 `json:"upper"`
}

type evaluationOperatingPoints struct {
	DegradedLogit *float64 `json:"degraded_logit"`
	CriticalLogit *float64 `json:"critical_logit"`
}

type evaluationGateWire struct {
	SchemaVersion   string               `json:"schema_version"`
	Status          string               `json:"status"`
	PolicySHA256    string               `json:"policy_sha256"`
	BlockingReasons []string             `json:"blocking_reasons"`
	Checks          []evaluationCheck    `json:"checks"`
	Model           *evaluationModelWire `json:"model"`
}

type evaluationCheck struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"`
	Metric    string   `json:"metric"`
	Bound     string   `json:"bound"`
	Op        string   `json:"op"`
	Threshold *float64 `json:"threshold"`
	Observed  *float64 `json:"observed"`
	Status    string   `json:"status"`
}

// EvaluationSummary holds the verified metadata and operating points extracted
// from a passing ML05 evaluation report.
type EvaluationSummary struct {
	EvaluationSHA256 string
	PolicyVersion    string
	PolicySHA256     string
	HorizonHours     uint32
	DegradedLogit    float64
	CriticalLogit    float64
}

// EvaluatedModel is a verified, runtime-compatible model bound to a passing ML05
// evaluation report and ready for deterministic controller inference.
type EvaluatedModel struct {
	Manifest         contracts.ModelManifestV1
	Runtime          contracts.ModelRuntimeV1
	EvaluationSHA256 string
	PolicyVersion    string
	PolicySHA256     string
	HorizonHours     uint32
	DegradedLogit    float64
	CriticalLogit    float64
	model            logisticParameters
}

// ModelPrediction is the raw thresholded output of an evaluated model over one
// complete CT03 feature vector.
type ModelPrediction struct {
	Model        contracts.ModelReferenceV2
	Status       string
	Logit        float64
	Probability  float64
	HorizonHours uint32
}

// LoadControllerModel verifies the artifact manifest, publisher signature,
// controller runtime compatibility, artifact bytes, weights layout, and ML05
// passing evaluation report before returning an active inference model.
func LoadControllerModel(manifest contracts.ModelManifestV1, artifact []byte, trustedKey ed25519.PublicKey, evalReport []byte, expectedEvalSHA256 string) (*EvaluatedModel, error) {
	return VerifyEvaluatedModel(manifest, artifact, trustedKey, ControllerInferenceRuntime(), evalReport, expectedEvalSHA256)
}

// VerifyEvaluatedModel verifies one model bundle against trustedKey, runtime,
// and an ML05 evaluation report pinned by expectedEvalSHA256.
func VerifyEvaluatedModel(manifest contracts.ModelManifestV1, artifact []byte, trustedKey ed25519.PublicKey, runtime contracts.ModelRuntimeV1, evalReport []byte, expectedEvalSHA256 string) (*EvaluatedModel, error) {
	if len(trustedKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: trusted Ed25519 publisher key is required", contracts.ModelRejectionKeyMismatch)
	}
	if len(artifact) == 0 || len(artifact) > contracts.ModelArtifactMaxBytesV1 {
		return nil, contracts.ModelRejectionDigestMismatch
	}
	if err := manifest.CheckActivation(contracts.ModelActivationV1{
		Runtime:    runtime,
		Purpose:    contracts.ModelPurposeInference,
		Artifact:   artifact,
		TrustedKey: trustedKey,
	}); err != nil {
		return nil, err
	}
	parsed, err := readLogisticParameters(manifest, artifact)
	if err != nil {
		return nil, err
	}
	summary, err := VerifyEvaluationReport(evalReport, expectedEvalSHA256, manifest)
	if err != nil {
		return nil, err
	}
	return &EvaluatedModel{
		Manifest:         manifest,
		Runtime:          runtime,
		EvaluationSHA256: summary.EvaluationSHA256,
		PolicyVersion:    summary.PolicyVersion,
		PolicySHA256:     summary.PolicySHA256,
		HorizonHours:     summary.HorizonHours,
		DegradedLogit:    summary.DegradedLogit,
		CriticalLogit:    summary.CriticalLogit,
		model:            parsed,
	}, nil
}

// VerifyEvaluationReport verifies that evalReport matches expectedSHA256, binds
// manifest under the pinned ML05 policy and ML01 manifest, clears every
// minimum-evidence and metric gate, and declares valid logit operating points.
func VerifyEvaluationReport(evalReport []byte, expectedSHA256 string, manifest contracts.ModelManifestV1) (EvaluationSummary, error) {
	if !lowerHexSHA256Pattern.MatchString(expectedSHA256) {
		return EvaluationSummary{}, fmt.Errorf("%w: invalid expected evaluation digest", ErrEvaluationRejected)
	}
	if len(evalReport) == 0 || len(evalReport) > MaxEvaluationReportBytes {
		return EvaluationSummary{}, fmt.Errorf("%w: evaluation report size out of bounds", ErrEvaluationRejected)
	}
	sum := sha256.Sum256(evalReport)
	actualSHA := hex.EncodeToString(sum[:])
	if actualSHA != expectedSHA256 {
		return EvaluationSummary{}, fmt.Errorf("%w: evaluation digest mismatch", ErrEvaluationRejected)
	}
	var report evaluationReportWire
	decoder := json.NewDecoder(bytes.NewReader(evalReport))
	if err := decoder.Decode(&report); err != nil {
		return EvaluationSummary{}, fmt.Errorf("%w: invalid evaluation JSON", ErrEvaluationRejected)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return EvaluationSummary{}, fmt.Errorf("%w: trailing content in evaluation JSON", ErrEvaluationRejected)
	}

	if err := checkEvaluationMetadata(report, manifest); err != nil {
		return EvaluationSummary{}, err
	}
	if err := checkEvaluationCounts(report.Counts); err != nil {
		return EvaluationSummary{}, err
	}
	if err := checkEvaluationMetricsAndGate(report, manifest); err != nil {
		return EvaluationSummary{}, err
	}
	points := report.OperatingPoints
	if !finitePtr(points.DegradedLogit) || !finitePtr(points.CriticalLogit) || *points.CriticalLogit < *points.DegradedLogit {
		return EvaluationSummary{}, fmt.Errorf("%w: invalid operating points", ErrEvaluationRejected)
	}
	return EvaluationSummary{
		EvaluationSHA256: actualSHA,
		PolicyVersion:    ML05PolicyVersion,
		PolicySHA256:     ML05PolicySHA256,
		HorizonHours:     report.HorizonHours,
		DegradedLogit:    *points.DegradedLogit,
		CriticalLogit:    *points.CriticalLogit,
	}, nil
}

func checkEvaluationMetadata(report evaluationReportWire, manifest contracts.ModelManifestV1) error {
	if report.SchemaVersion != EvaluationReportV1Version ||
		report.PolicySHA256 != ML05PolicySHA256 ||
		report.PartitionManifestSHA256 != ML01PartitionManifestSHA256 ||
		report.Partition != "test" ||
		report.HorizonHours != ML05HorizonHours ||
		report.Evaluations != 1 ||
		report.LabelStatus != "both_classes_present" ||
		report.EvaluationError != "" {
		return fmt.Errorf("%w: report procedure, policy, or label status failed", ErrEvaluationRejected)
	}
	if report.Model == nil || report.Model.Version != manifest.ModelVersion || report.Model.SHA256 != manifest.ArtifactSHA256 {
		return fmt.Errorf("%w: evaluation report does not match model artifact", ErrEvaluationRejected)
	}
	if report.Bootstrap.Unit != "device" || report.Bootstrap.Replicates != 2000 ||
		report.Bootstrap.Seed != 86 || report.Bootstrap.Method != "percentile" ||
		report.Bootstrap.Interval != 0.95 {
		return fmt.Errorf("%w: bootstrap procedure mismatch", ErrEvaluationRejected)
	}
	return nil
}

func checkEvaluationCounts(counts evaluationCountsWire) error {
	checks := []struct {
		got *int
		min int
	}{
		{counts.TestPositiveEvents, 30},
		{counts.TestPositiveWindows, 100},
		{counts.TestNegativeWindows, 10000},
		{counts.TestDevices, 1000},
		{counts.ValidationNegativeWindows, 10000},
	}
	for _, check := range checks {
		if check.got == nil || *check.got < check.min {
			return fmt.Errorf("%w: minimum evaluation counts not met", ErrEvaluationRejected)
		}
	}
	return nil
}

func checkEvaluationMetricsAndGate(report evaluationReportWire, manifest contracts.ModelManifestV1) error {
	if report.Gate.SchemaVersion != EvaluationGateV1Version ||
		report.Gate.PolicySHA256 != ML05PolicySHA256 ||
		report.Gate.Status != "pass" ||
		len(report.Gate.BlockingReasons) != 0 {
		return fmt.Errorf("%w: ML05 gate did not pass", ErrEvaluationRejected)
	}
	if report.Gate.Model != nil && (report.Gate.Model.Version != manifest.ModelVersion || report.Gate.Model.SHA256 != manifest.ArtifactSHA256) {
		return fmt.Errorf("%w: gate model provenance mismatch", ErrEvaluationRejected)
	}
	checkByID := make(map[string]evaluationCheck, len(report.Gate.Checks))
	for _, check := range report.Gate.Checks {
		if _, dup := checkByID[check.ID]; dup {
			return fmt.Errorf("%w: duplicate gate check %q", ErrEvaluationRejected, check.ID)
		}
		checkByID[check.ID] = check
	}
	if len(checkByID) != len(ml05Gates) {
		return fmt.Errorf("%w: gate check count mismatch", ErrEvaluationRejected)
	}
	for _, spec := range ml05Gates {
		interval, ok := report.Metrics[spec.metric]
		if !ok || !finitePtr(interval.Point) || !finitePtr(interval.Lower) || !finitePtr(interval.Upper) {
			return fmt.Errorf("%w: missing or non-finite metric %q", ErrEvaluationRejected, spec.metric)
		}
		if *interval.Lower > *interval.Point || *interval.Point > *interval.Upper {
			return fmt.Errorf("%w: inconsistent interval for %q", ErrEvaluationRejected, spec.metric)
		}
		observed, ok := intervalBound(interval, spec.bound)
		if !ok || !evalOp(observed, spec.op, spec.threshold) {
			return fmt.Errorf("%w: gate %q failed threshold", ErrEvaluationRejected, spec.id)
		}
		check, ok := checkByID[spec.id]
		if !ok || check.Status != "pass" || check.Kind != spec.kind || check.Metric != spec.metric ||
			check.Bound != spec.bound || check.Op != spec.op || !finitePtr(check.Threshold) ||
			*check.Threshold != spec.threshold || !finitePtr(check.Observed) || *check.Observed != observed {
			return fmt.Errorf("%w: gate check %q inconsistent or not passing", ErrEvaluationRejected, spec.id)
		}
	}
	return nil
}

func finitePtr(v *float64) bool {
	return v != nil && !math.IsNaN(*v) && !math.IsInf(*v, 0)
}

func intervalBound(interval metricInterval, bound string) (float64, bool) {
	switch bound {
	case "point":
		return *interval.Point, true
	case "lower":
		return *interval.Lower, true
	case "upper":
		return *interval.Upper, true
	default:
		return 0, false
	}
}

func evalOp(observed float64, op string, threshold float64) bool {
	switch op {
	case ">":
		return observed > threshold
	case ">=":
		return observed >= threshold
	case "<":
		return observed < threshold
	case "<=":
		return observed <= threshold
	default:
		return false
	}
}

// Reference returns the versioned model provenance reference.
func (m *EvaluatedModel) Reference() contracts.ModelReferenceV2 {
	return contracts.ModelReferenceV2{
		Version: m.Manifest.ModelVersion,
		SHA256:  m.Manifest.ArtifactSHA256,
	}
}

// Predict scores one complete CT03 feature vector and maps its logit through
// the approved ML05 validation-negative operating points.
func (m *EvaluatedModel) Predict(vector contracts.FeatureVectorV1) (ModelPrediction, error) {
	if m == nil {
		return ModelPrediction{}, errors.New("evaluated model is nil")
	}
	values, err := ModelInput(vector)
	if err != nil {
		return ModelPrediction{}, err
	}
	if vector.FeatureVersion != m.Manifest.FeatureVersion {
		return ModelPrediction{}, contracts.ErrUnsupportedFeatureVersion
	}
	logit, err := m.model.score(values)
	if err != nil {
		return ModelPrediction{}, err
	}
	prob := 1 / (1 + math.Exp(-logit))
	if math.IsNaN(prob) || math.IsInf(prob, 0) || prob < 0 || prob > 1 {
		return ModelPrediction{}, errors.New("model probability out of bounds")
	}
	status := HealthStatusHealthy
	switch {
	case logit >= m.CriticalLogit:
		status = HealthStatusCritical
	case logit >= m.DegradedLogit:
		status = HealthStatusDegraded
	}
	return ModelPrediction{
		Model:        m.Reference(),
		Status:       status,
		Logit:        logit,
		Probability:  prob,
		HorizonHours: m.HorizonHours,
	}, nil
}
