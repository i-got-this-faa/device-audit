package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// FED10 #115: held-out evaluation and promotion of a candidate model. See
// model-registry-v1.md.
const (
	ModelEvaluationSubmissionV1Version = "device-audit.model-evaluation-submission.v1"
	ModelEvaluationV1Version           = "device-audit.model-evaluation.v1"
	ModelPromotionRequestV1Version     = "device-audit.model-promotion-request.v1"
	ModelPromotionV1Version            = "device-audit.model-promotion.v1"
	// ModelEvaluationMaxBytesV1 bounds one evaluation report.
	ModelEvaluationMaxBytesV1 = 1 << 20
)

// ModelEvaluationVerdictV1 is the controller's own reading of a report.
// Blocked means the evidence cannot decide; it is not a failed model.
type ModelEvaluationVerdictV1 string

const (
	ModelEvaluationPass    ModelEvaluationVerdictV1 = "pass"
	ModelEvaluationFail    ModelEvaluationVerdictV1 = "fail"
	ModelEvaluationBlocked ModelEvaluationVerdictV1 = "blocked"
)

// ModelPromotionOutcomeV1 is the recorded result of one promotion decision.
type ModelPromotionOutcomeV1 string

const (
	// ModelPromotionPromoted means the candidate passed every gate and is active.
	ModelPromotionPromoted ModelPromotionOutcomeV1 = "promoted"
	// ModelPromotionRejected means the active model was left as it was.
	ModelPromotionRejected ModelPromotionOutcomeV1 = "rejected"
)

// ModelEvaluationSubmissionV1 carries one held-out evaluation report for a
// stored artifact. The model publisher signs it, so a console session alone
// cannot supply evidence. The report is stored byte for byte.
type ModelEvaluationSubmissionV1 struct {
	SchemaVersion  string `json:"schema_version"`
	ModelVersion   string `json:"model_version"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Report         []byte `json:"report"`
	SigningKeyID   string `json:"signing_key_id"`
	Signature      string `json:"signature"`
}

// ModelMetricV1 is one reported metric with its device-bootstrap interval.
type ModelMetricV1 struct {
	Point float64 `json:"point"`
	Lower float64 `json:"lower"`
	Upper float64 `json:"upper"`
}

// ModelEvaluationV1 is the stored evaluation of one artifact. A candidate has
// at most one: the held-out partition is scored once per candidate. Metrics is
// null when the report was too incomplete to read.
type ModelEvaluationV1 struct {
	SchemaVersion    string                   `json:"schema_version"`
	DeploymentID     string                   `json:"deployment_id"`
	ModelVersion     string                   `json:"model_version"`
	ArtifactSHA256   string                   `json:"artifact_sha256"`
	EvaluationSHA256 string                   `json:"evaluation_sha256"`
	PolicyVersion    string                   `json:"policy_version"`
	Verdict          ModelEvaluationVerdictV1 `json:"verdict"`
	Reasons          []string                 `json:"reasons"`
	Metrics          map[string]ModelMetricV1 `json:"metrics"`
	SubmittedAt      time.Time                `json:"submitted_at"`
	SubmittedBy      ModelActorV1             `json:"submitted_by"`
}

// ModelPromotionRequestV1 asks the controller to decide one candidate. The
// controller reads the stored evaluation; the request cannot supply a verdict.
type ModelPromotionRequestV1 struct {
	SchemaVersion    string `json:"schema_version"`
	ModelVersion     string `json:"model_version"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	EvaluationSHA256 string `json:"evaluation_sha256"`
}

// ModelRegressionCheckV1 records one comparison with the active model.
type ModelRegressionCheckV1 struct {
	GateID    string  `json:"gate_id"`
	Metric    string  `json:"metric"`
	Candidate float64 `json:"candidate"`
	Active    float64 `json:"active"`
	Status    string  `json:"status"`
}

// ModelBaselineV1 names the active model a candidate was compared with.
type ModelBaselineV1 struct {
	ModelVersion     string `json:"model_version"`
	ArtifactSHA256   string `json:"artifact_sha256"`
	EvaluationSHA256 string `json:"evaluation_sha256"`
}

// ModelPromotionV1 is the stored, immutable decision for one candidate.
// Baseline is null when no model was active. Reasons is empty only when the
// candidate was promoted.
type ModelPromotionV1 struct {
	SchemaVersion          string                   `json:"schema_version"`
	DeploymentID           string                   `json:"deployment_id"`
	ModelVersion           string                   `json:"model_version"`
	ArtifactSHA256         string                   `json:"artifact_sha256"`
	EvaluationSHA256       string                   `json:"evaluation_sha256"`
	PromotionPolicyVersion string                   `json:"promotion_policy_version"`
	Outcome                ModelPromotionOutcomeV1  `json:"outcome"`
	Reasons                []string                 `json:"reasons"`
	Baseline               *ModelBaselineV1         `json:"baseline"`
	Checks                 []ModelRegressionCheckV1 `json:"checks"`
	DecidedAt              time.Time                `json:"decided_at"`
	DecidedBy              ModelActorV1             `json:"decided_by"`
}

func (s *ModelEvaluationSubmissionV1) UnmarshalJSON(data []byte) error {
	type wire ModelEvaluationSubmissionV1
	return decodeEnvelopeJSON(data, (*wire)(s), []string{"schema_version", "model_version", "artifact_sha256", "report", "signing_key_id", "signature"})
}

func (r *ModelPromotionRequestV1) UnmarshalJSON(data []byte) error {
	type wire ModelPromotionRequestV1
	return decodeEnvelopeJSON(data, (*wire)(r), []string{"schema_version", "model_version", "artifact_sha256", "evaluation_sha256"})
}

// ReportSHA256 is the evaluation digest approvals and promotions cite.
func (s ModelEvaluationSubmissionV1) ReportSHA256() string {
	sum := sha256.Sum256(s.Report)
	return hex.EncodeToString(sum[:])
}

// SigningBytes binds the model, its digest and the exact report bytes.
func (s ModelEvaluationSubmissionV1) SigningBytes() []byte {
	return canonicalEnvelopeFields([]string{s.SchemaVersion, s.ModelVersion, s.ArtifactSHA256, s.ReportSHA256(), s.SigningKeyID})
}

// Verify admits a submission signed by the trusted publisher key. The
// signature is checked before the report is read.
func (s ModelEvaluationSubmissionV1) Verify(trustedKey ed25519.PublicKey) error {
	if s.SchemaVersion != ModelEvaluationSubmissionV1Version || !opaqueIDPattern.MatchString(s.ModelVersion) ||
		!fixedEnvelopeHex(s.ArtifactSHA256, sha256.Size) || !validEnvelopeKeyID(s.SigningKeyID) || len(s.Report) == 0 {
		return ModelRejectionInvalidRequest
	}
	if len(s.Report) > ModelEvaluationMaxBytesV1 {
		return ModelRejectionArtifactTooLarge
	}
	if validateEnvelopeSignature(s.Signature) != nil {
		return ModelRejectionInvalidSignature
	}
	if err := verifyEnvelopeSignature(trustedKey, s.SigningKeyID, s.Signature, s.SigningBytes()); err != nil {
		if err.Error() == EnvelopeRejectionInvalidSignature {
			return ModelRejectionInvalidSignature
		}
		return ModelRejectionKeyMismatch
	}
	return nil
}

func (r ModelPromotionRequestV1) Validate() error {
	if r.SchemaVersion != ModelPromotionRequestV1Version || !opaqueIDPattern.MatchString(r.ModelVersion) ||
		!fixedEnvelopeHex(r.ArtifactSHA256, sha256.Size) || !fixedEnvelopeHex(r.EvaluationSHA256, sha256.Size) {
		return ModelRejectionInvalidRequest
	}
	return nil
}
