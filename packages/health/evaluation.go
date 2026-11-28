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
	"slices"
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
	PartitionExamplesSHA256 map[string]string         `json:"partition_examples_sha256"`
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

// EvaluationVerdict is the outcome of checking one ML05 report against the
// frozen policy. Blocked means the evidence cannot decide; it is not a failed
// model and a blocked report never passes.
type EvaluationVerdict string

const (
	EvaluationPass    EvaluationVerdict = "pass"
	EvaluationFail    EvaluationVerdict = "fail"
	EvaluationBlocked EvaluationVerdict = "blocked"
)

// MetricInterval is one reported metric with its device-bootstrap interval.
type MetricInterval struct {
	Point float64 `json:"point"`
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// EvaluationAssessment is the controller's own reading of a report. It never
// trusts the verdict embedded in the report: every metric is rechecked.
type EvaluationAssessment struct {
	Verdict          EvaluationVerdict
	Reasons          []string
	EvaluationSHA256 string
	ModelVersion     string
	ModelSHA256      string
	// TestPartitionSHA256 identifies the frozen held-out examples scored.
	TestPartitionSHA256 string
	// Metrics holds every policy metric when the report is well formed.
	Metrics map[string]MetricInterval
	// Summary is valid only when Verdict is EvaluationPass.
	Summary EvaluationSummary
}

// VerifyEvaluationReport verifies that evalReport matches expectedSHA256, binds
// manifest under the pinned ML05 policy and ML01 manifest, clears every
// minimum-evidence and metric gate, and declares valid logit operating points.
func VerifyEvaluationReport(evalReport []byte, expectedSHA256 string, manifest contracts.ModelManifestV1) (EvaluationSummary, error) {
	if !lowerHexSHA256Pattern.MatchString(expectedSHA256) {
		return EvaluationSummary{}, fmt.Errorf("%w: invalid expected evaluation digest", ErrEvaluationRejected)
	}
	assessment := AssessEvaluationReport(evalReport, manifest)
	if assessment.EvaluationSHA256 != expectedSHA256 {
		return EvaluationSummary{}, fmt.Errorf("%w: evaluation digest mismatch", ErrEvaluationRejected)
	}
	if assessment.Verdict != EvaluationPass {
		return EvaluationSummary{}, fmt.Errorf("%w: %s: %v", ErrEvaluationRejected, assessment.Verdict, assessment.Reasons)
	}
	return assessment.Summary, nil
}

// AssessEvaluationReport reads one ML05 report for manifest and returns pass,
// fail or blocked with stable reason codes. Structural problems, missing or
// inconsistent evidence and procedure mismatches block; a well-formed report
// whose metrics miss a threshold fails.
func AssessEvaluationReport(evalReport []byte, manifest contracts.ModelManifestV1) EvaluationAssessment {
	sum := sha256.Sum256(evalReport)
	out := EvaluationAssessment{Verdict: EvaluationBlocked, EvaluationSHA256: hex.EncodeToString(sum[:])}
	block := func(reasons ...string) EvaluationAssessment {
		out.Verdict, out.Reasons = EvaluationBlocked, append(out.Reasons, reasons...)
		slices.Sort(out.Reasons)
		out.Reasons = slices.Compact(out.Reasons)
		return out
	}
	if len(evalReport) == 0 || len(evalReport) > MaxEvaluationReportBytes {
		return block("report_size_out_of_bounds")
	}
	var report evaluationReportWire
	decoder := json.NewDecoder(bytes.NewReader(evalReport))
	if err := decoder.Decode(&report); err != nil {
		return block("invalid_report_json")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return block("invalid_report_json")
	}
	if report.Model != nil {
		out.ModelVersion, out.ModelSHA256 = report.Model.Version, report.Model.SHA256
	}
	out.TestPartitionSHA256 = report.PartitionExamplesSHA256["test"]

	blocked := evaluationMetadataReasons(report, manifest)
	blocked = append(blocked, evaluationCountReasons(report.Counts)...)
	metrics, metricReasons := evaluationMetrics(report)
	blocked = append(blocked, metricReasons...)
	points := report.OperatingPoints
	if !finitePtr(points.DegradedLogit) || !finitePtr(points.CriticalLogit) || *points.CriticalLogit < *points.DegradedLogit {
		blocked = append(blocked, "invalid_operating_points")
	}
	if len(blocked) > 0 {
		return block(blocked...)
	}
	out.Metrics = metrics

	var failed []string
	for _, spec := range ml05Gates {
		observed, _ := intervalValue(metrics[spec.metric], spec.bound)
		if !evalOp(observed, spec.op, spec.threshold) {
			failed = append(failed, "gate_failed:"+spec.id)
		}
	}
	if len(failed) > 0 {
		out.Verdict, out.Reasons = EvaluationFail, failed
		return out
	}
	// The report's own gate must agree with the controller's reading.
	if !embeddedGateAgrees(report, manifest) {
		return block("embedded_gate_inconsistent")
	}
	out.Verdict = EvaluationPass
	out.Summary = EvaluationSummary{
		EvaluationSHA256: out.EvaluationSHA256,
		PolicyVersion:    ML05PolicyVersion,
		PolicySHA256:     ML05PolicySHA256,
		HorizonHours:     report.HorizonHours,
		DegradedLogit:    *points.DegradedLogit,
		CriticalLogit:    *points.CriticalLogit,
	}
	return out
}

func evaluationMetadataReasons(report evaluationReportWire, manifest contracts.ModelManifestV1) []string {
	var reasons []string
	add := func(failed bool, reason string) {
		if failed {
			reasons = append(reasons, reason)
		}
	}
	add(report.SchemaVersion != EvaluationReportV1Version, "unsupported_report_schema")
	add(report.PolicySHA256 != ML05PolicySHA256, "policy_mismatch")
	add(report.PartitionManifestSHA256 != ML01PartitionManifestSHA256, "partition_manifest_mismatch")
	add(report.Partition != "test", "not_held_out_partition")
	add(report.HorizonHours != ML05HorizonHours, "horizon_mismatch")
	add(report.Evaluations != 1, "held_out_reuse_or_unrecorded")
	add(report.LabelStatus != "both_classes_present", "labels_unavailable")
	add(report.EvaluationError != "", "evaluation_error")
	add(report.Model == nil || report.Model.Version != manifest.ModelVersion || report.Model.SHA256 != manifest.ArtifactSHA256, "model_mismatch")
	add(!lowerHexSHA256Pattern.MatchString(report.PartitionExamplesSHA256["test"]), "test_partition_digest_missing")
	add(report.Bootstrap.Unit != "device" || report.Bootstrap.Replicates != 2000 || report.Bootstrap.Seed != 86 ||
		report.Bootstrap.Method != "percentile" || report.Bootstrap.Interval != 0.95, "bootstrap_procedure_mismatch")
	return reasons
}

func evaluationCountReasons(counts evaluationCountsWire) []string {
	checks := []struct {
		name string
		got  *int
		min  int
	}{
		{"test_positive_events", counts.TestPositiveEvents, 30},
		{"test_positive_windows", counts.TestPositiveWindows, 100},
		{"test_negative_windows", counts.TestNegativeWindows, 10000},
		{"test_devices", counts.TestDevices, 1000},
		{"validation_negative_windows", counts.ValidationNegativeWindows, 10000},
	}
	var reasons []string
	for _, check := range checks {
		switch {
		case check.got == nil:
			reasons = append(reasons, "missing_count:"+check.name)
		case *check.got < check.min:
			reasons = append(reasons, "insufficient:"+check.name)
		}
	}
	return reasons
}

// evaluationMetrics returns every metric an ML05 gate reads, or the reasons it
// cannot. A missing, non-finite or inconsistent interval blocks the report.
func evaluationMetrics(report evaluationReportWire) (map[string]MetricInterval, []string) {
	metrics := make(map[string]MetricInterval, len(ml05Gates))
	var reasons []string
	for _, spec := range ml05Gates {
		if _, done := metrics[spec.metric]; done {
			continue
		}
		interval, ok := report.Metrics[spec.metric]
		switch {
		case !ok || !finitePtr(interval.Point) || !finitePtr(interval.Lower) || !finitePtr(interval.Upper):
			reasons = append(reasons, "missing_metric:"+spec.metric)
		case *interval.Lower > *interval.Point || *interval.Point > *interval.Upper:
			reasons = append(reasons, "inconsistent_interval:"+spec.metric)
		case spec.metric == "roc_auc" && (*interval.Lower < 0 || *interval.Upper > 1):
			reasons = append(reasons, "inconsistent_interval:"+spec.metric)
		default:
			metrics[spec.metric] = MetricInterval{Point: *interval.Point, Lower: *interval.Lower, Upper: *interval.Upper}
		}
	}
	// Regression gates read these without an ML05 gate of their own.
	for _, name := range ComparisonMetrics {
		interval, ok := report.Metrics[name]
		if _, have := metrics[name]; have {
			continue
		}
		if !ok || !finitePtr(interval.Point) || !finitePtr(interval.Lower) || !finitePtr(interval.Upper) ||
			*interval.Lower > *interval.Point || *interval.Point > *interval.Upper {
			reasons = append(reasons, "missing_metric:"+name)
			continue
		}
		metrics[name] = MetricInterval{Point: *interval.Point, Lower: *interval.Lower, Upper: *interval.Upper}
	}
	return metrics, reasons
}

// ComparisonMetrics are the metrics a candidate is compared with the active
// model on, beyond those the ML05 gates read. Both come from the same report.
var ComparisonMetrics = []string{"average_precision"}

// embeddedGateAgrees checks that the report's own gate says pass and records
// each ML05 check exactly as the controller computed it.
func embeddedGateAgrees(report evaluationReportWire, manifest contracts.ModelManifestV1) bool {
	gate := report.Gate
	if gate.SchemaVersion != EvaluationGateV1Version || gate.PolicySHA256 != ML05PolicySHA256 ||
		gate.Status != "pass" || len(gate.BlockingReasons) != 0 {
		return false
	}
	if gate.Model != nil && (gate.Model.Version != manifest.ModelVersion || gate.Model.SHA256 != manifest.ArtifactSHA256) {
		return false
	}
	checks := make(map[string]evaluationCheck, len(gate.Checks))
	for _, check := range gate.Checks {
		if _, dup := checks[check.ID]; dup {
			return false
		}
		checks[check.ID] = check
	}
	if len(checks) != len(ml05Gates) {
		return false
	}
	for _, spec := range ml05Gates {
		interval := report.Metrics[spec.metric]
		observed, _ := intervalBound(interval, spec.bound)
		check, ok := checks[spec.id]
		if !ok || check.Status != "pass" || check.Kind != spec.kind || check.Metric != spec.metric ||
			check.Bound != spec.bound || check.Op != spec.op || !finitePtr(check.Threshold) ||
			*check.Threshold != spec.threshold || !finitePtr(check.Observed) || *check.Observed != observed {
			return false
		}
	}
	return true
}

func intervalValue(interval MetricInterval, bound string) (float64, bool) {
	switch bound {
	case "point":
		return interval.Point, true
	case "lower":
		return interval.Lower, true
	case "upper":
		return interval.Upper, true
	default:
		return 0, false
	}
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
