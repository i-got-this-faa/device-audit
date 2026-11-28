package contracts

import (
	"fmt"
	"time"
)

const (
	// AuditManifestPolicyV1 is the only manifest policy this controller signs.
	// It requires evidence the controller itself stored and re-verified, with
	// every reference expiring no earlier than the manifest.
	AuditManifestPolicyV1 = "device-audit.audit-manifest-policy.v1"
	// AuditManifestRequestV1Version versions AuditManifestRequestV1.
	AuditManifestRequestV1Version = "device-audit.audit-manifest-request.v1"
	// AuditManifestRecordV1Version versions AuditManifestRecordV1.
	AuditManifestRecordV1Version = "device-audit.audit-manifest-record.v1"
)

// AuditManifestRejection is the stable code for a refused manifest request.
// Evidence problems use the AuditEvidenceRejection codes.
type AuditManifestRejection string

func (r AuditManifestRejection) Error() string { return string(r) }

const (
	AuditManifestRejectionInvalidRequest AuditManifestRejection = "manifest_invalid_request"
	AuditManifestRejectionNotFound       AuditManifestRejection = "manifest_not_found"
	// Conflict: the manifest ID already names a different manifest.
	AuditManifestRejectionConflict AuditManifestRejection = "manifest_conflict"
	// Incompatible: an evidence record is not of a schema this policy accepts.
	AuditManifestRejectionIncompatible AuditManifestRejection = "manifest_incompatible_evidence"
	// OutlivesEvidence: the manifest would expire after some evidence's retention.
	AuditManifestRejectionOutlivesEvidence AuditManifestRejection = "manifest_outlives_evidence"
	// Unavailable: a stored manifest failed its integrity check.
	AuditManifestRejectionUnavailable AuditManifestRejection = "manifest_unavailable"
)

// AuditManifestRequestV1 asks the controller to sign a manifest over evidence
// it already stores (AUD01). The controller chooses the blinding nonce and
// commitment ID, the creation time and every reference digest; the caller names
// only the identity, the policy, the expiry and the evidence. The order of
// EvidenceIDs does not matter.
type AuditManifestRequestV1 struct {
	SchemaVersion string    `json:"schema_version"`
	ManifestID    string    `json:"manifest_id"`
	PolicyVersion string    `json:"policy_version"`
	ExpiresAt     time.Time `json:"expires_at"`
	EvidenceIDs   []string  `json:"evidence_ids"`
}

func (r *AuditManifestRequestV1) UnmarshalJSON(data []byte) error {
	type wire AuditManifestRequestV1
	return decodeEnvelopeJSON(data, (*wire)(r), []string{"schema_version", "manifest_id", "policy_version", "expires_at", "evidence_ids"})
}

// Validate checks the request's shape. now is the controller clock.
func (r AuditManifestRequestV1) Validate(now time.Time) error {
	if r.SchemaVersion != AuditManifestRequestV1Version || !opaqueIDPattern.MatchString(r.ManifestID) || r.PolicyVersion != AuditManifestPolicyV1 {
		return fmt.Errorf("invalid audit manifest request")
	}
	if len(r.EvidenceIDs) < 1 || len(r.EvidenceIDs) > 64 {
		return fmt.Errorf("a manifest references 1 to 64 evidence records")
	}
	seen := map[string]bool{}
	for _, id := range r.EvidenceIDs {
		if !opaqueIDPattern.MatchString(id) || seen[id] {
			return fmt.Errorf("evidence IDs must be opaque and unique")
		}
		seen[id] = true
	}
	if r.ExpiresAt.Nanosecond() != 0 || !r.ExpiresAt.After(now) || r.ExpiresAt.Sub(now) > 365*24*time.Hour {
		return fmt.Errorf("manifest must expire at a whole second, in the future, within 365 days")
	}
	return nil
}

// AuditManifestBasisV1 names what one manifest reference stands for: the stored
// evidence, its owner and the versions that produced it. The versions are read
// from the stored bytes and sources when the manifest is made, and the bytes
// are bound by the manifest's SHA-256, so they cannot differ from what is signed.
type AuditManifestBasisV1 struct {
	ReferenceID           string              `json:"reference_id"`
	Kind                  AuditEvidenceKindV1 `json:"kind"`
	DeviceID              string              `json:"device_id"`
	EvidenceSchemaVersion string              `json:"evidence_schema_version"`
	SHA256                string              `json:"sha256"`
	SizeBytes             uint32              `json:"size_bytes"`
	ModelVersion          *string             `json:"model_version"`
	ModelSHA256           *string             `json:"model_sha256"`
	MethodologyVersion    string              `json:"methodology_version"`
}

// AuditManifestRecordV1 is a stored signed manifest. The manifest holds the
// private blinding nonce, so reading the record needs the evidence-access role.
// Commitment is the only part eligible for a chain adapter.
type AuditManifestRecordV1 struct {
	SchemaVersion  string                 `json:"schema_version"`
	DeploymentID   string                 `json:"deployment_id"`
	ManifestID     string                 `json:"manifest_id"`
	Manifest       AuditManifestV1        `json:"manifest"`
	Commitment     AuditCommitmentV1      `json:"commitment"`
	ManifestSHA256 string                 `json:"manifest_sha256"`
	Basis          []AuditManifestBasisV1 `json:"basis"`
	CreatedBy      ModelActorV1           `json:"created_by"`
	CreatedAt      time.Time              `json:"created_at"`
}
