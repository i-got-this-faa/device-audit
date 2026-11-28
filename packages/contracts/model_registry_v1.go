package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// FED07 #112: the controller's model artifact registry. See model-registry-v1.md.
const (
	ModelArtifactUploadV1Version   = "device-audit.model-artifact-upload.v1"
	ModelArtifactV1Version         = "device-audit.model-artifact.v1"
	ModelReferenceRequestV1Version = "device-audit.model-reference-request.v1"
	ModelReferencesV1Version       = "device-audit.model-references.v1"
	// ModelArtifactMaxBytesV1 is the ML05 #86 inference artifact budget.
	ModelArtifactMaxBytesV1 = 16 << 20
)

// ModelSlotV1 names one registry reference.
type ModelSlotV1 string

const (
	// ModelSlotActive is the model endpoints and controller inference load. It
	// may only name an approved artifact that declares the inference purpose.
	ModelSlotActive ModelSlotV1 = "active"
	// ModelSlotCandidate is the next model under evaluation. It needs no approval.
	ModelSlotCandidate ModelSlotV1 = "candidate"
)

// Registry refusals beyond the ModelRejection codes a manifest check returns.
const (
	ModelRejectionInvalidRequest    ModelRejection = "invalid_request"
	ModelRejectionArtifactTooLarge  ModelRejection = "artifact_too_large"
	ModelRejectionVersionConflict   ModelRejection = "version_conflict"
	ModelRejectionReferenceMismatch ModelRejection = "reference_mismatch"
	ModelRejectionNotApproved       ModelRejection = "not_approved"
	// ModelRejectionNotCandidate: only the model in the candidate slot can be promoted.
	ModelRejectionNotCandidate ModelRejection = "not_candidate"
)

// ModelArtifactUploadV1 carries one signed manifest and the exact artifact
// bytes, base64-encoded in JSON. SourceReference names where the artifact was
// produced, for example a training run; the registry does not resolve it.
type ModelArtifactUploadV1 struct {
	SchemaVersion   string          `json:"schema_version"`
	Manifest        ModelManifestV1 `json:"manifest"`
	Artifact        []byte          `json:"artifact"`
	SourceReference string          `json:"source_reference"`
}

// ModelActorV1 is the authenticated console session that made a change.
type ModelActorV1 struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// ModelApprovalV1 is a stored approval. Only a promotion creates one, and only
// from a passing evaluation; EvaluationSHA256 names that report.
type ModelApprovalV1 struct {
	EvaluationSHA256 string       `json:"evaluation_sha256"`
	PolicyVersion    string       `json:"policy_version"`
	ApprovedAt       time.Time    `json:"approved_at"`
	ApprovedBy       ModelActorV1 `json:"approved_by"`
}

// ModelArtifactV1 is one immutable registry entry. Everything but the manifest
// and source reference is controller-assigned. Approval is null until approved.
type ModelArtifactV1 struct {
	SchemaVersion    string           `json:"schema_version"`
	DeploymentID     string           `json:"deployment_id"`
	Manifest         ModelManifestV1  `json:"manifest"`
	ArtifactByteSize int              `json:"artifact_byte_size"`
	SourceReference  string           `json:"source_reference"`
	UploadedAt       time.Time        `json:"uploaded_at"`
	UploadedBy       ModelActorV1     `json:"uploaded_by"`
	Approval         *ModelApprovalV1 `json:"approval"`
}

// ModelReferenceRequestV1 points a slot at one stored artifact. The digest must
// match the stored version, so a request cannot name bytes it did not see.
type ModelReferenceRequestV1 struct {
	SchemaVersion  string `json:"schema_version"`
	ModelVersion   string `json:"model_version"`
	ArtifactSHA256 string `json:"artifact_sha256"`
}

// ModelReferenceV1 is one slot's current target.
type ModelReferenceV1 struct {
	ModelVersion   string       `json:"model_version"`
	ArtifactSHA256 string       `json:"artifact_sha256"`
	SetAt          time.Time    `json:"set_at"`
	SetBy          ModelActorV1 `json:"set_by"`
}

// ModelReferencesV1 is the registry's slots. A null slot names no model; it
// never falls back to another version.
type ModelReferencesV1 struct {
	SchemaVersion string            `json:"schema_version"`
	DeploymentID  string            `json:"deployment_id"`
	Active        *ModelReferenceV1 `json:"active"`
	Candidate     *ModelReferenceV1 `json:"candidate"`
}

func (u *ModelArtifactUploadV1) UnmarshalJSON(data []byte) error {
	type wire ModelArtifactUploadV1
	return decodeEnvelopeJSON(data, (*wire)(u), []string{"schema_version", "manifest", "artifact", "source_reference"})
}

func (r *ModelReferenceRequestV1) UnmarshalJSON(data []byte) error {
	type wire ModelReferenceRequestV1
	return decodeEnvelopeJSON(data, (*wire)(r), []string{"schema_version", "model_version", "artifact_sha256"})
}

// Verify admits an upload: the manifest must validate and verify against the
// configured publisher key, and the bytes must be within budget and match the
// signed digest. The manifest is authenticated before the artifact is hashed.
func (u ModelArtifactUploadV1) Verify(trustedKey ed25519.PublicKey) error {
	if u.SchemaVersion != ModelArtifactUploadV1Version || !opaqueIDPattern.MatchString(u.SourceReference) {
		return ModelRejectionInvalidRequest
	}
	if err := u.Manifest.Validate(); err != nil {
		return err
	}
	if err := u.Manifest.VerifySignature(trustedKey); err != nil {
		return err
	}
	if len(u.Artifact) == 0 {
		return ModelRejectionInvalidRequest
	}
	if len(u.Artifact) > ModelArtifactMaxBytesV1 {
		return ModelRejectionArtifactTooLarge
	}
	if sum := sha256.Sum256(u.Artifact); hex.EncodeToString(sum[:]) != u.Manifest.ArtifactSHA256 {
		return ModelRejectionDigestMismatch
	}
	return nil
}

func (r ModelReferenceRequestV1) Validate() error {
	if r.SchemaVersion != ModelReferenceRequestV1Version || !opaqueIDPattern.MatchString(r.ModelVersion) || !fixedEnvelopeHex(r.ArtifactSHA256, sha256.Size) {
		return ModelRejectionInvalidRequest
	}
	return nil
}

// Validate checks an actor taken from an authenticated session, with the
// bounds the console role bindings use.
func (a ModelActorV1) Validate() error {
	if strings.TrimSpace(a.Issuer) == "" || utf8.RuneCountInString(a.Issuer) > 2048 || strings.TrimSpace(a.Subject) == "" || utf8.RuneCountInString(a.Subject) > 255 {
		return fmt.Errorf("%w: invalid actor", ModelRejectionInvalidRequest)
	}
	return nil
}
