package contracts

import "time"

const (
	// AuditManifestVerificationV1Version versions AuditManifestVerificationV1.
	AuditManifestVerificationV1Version = "device-audit.audit-manifest-verification.v1"

	// AuditVerificationScopeV1 states what a verification establishes: the
	// integrity of the recorded bytes and the signatures over them. A valid
	// signature shows that a key signed these bytes, never that the endpoint
	// measured or reported truthfully.
	AuditVerificationScopeV1 = "integrity_only"
	// AuditTruthfulnessV1 is always this value: endpoint truthfulness is not
	// something verification can establish.
	AuditTruthfulnessV1 = "not_established"
)

// AuditReferenceStatusV1 is the outcome for one manifest reference.
type AuditReferenceStatusV1 string

const (
	// AuditReferenceVerified: bytes match the signed digest and size, the schema
	// and bound versions match, and any device signature verifies.
	AuditReferenceVerified AuditReferenceStatusV1 = "verified"
	// AuditReferenceEdited: the stored bytes no longer match the signed digest or size.
	AuditReferenceEdited AuditReferenceStatusV1 = "edited"
	// AuditReferenceMissing: no evidence record exists for the reference.
	AuditReferenceMissing AuditReferenceStatusV1 = "missing"
	// AuditReferenceExpired: the retention period ended, so the bytes were not examined.
	AuditReferenceExpired AuditReferenceStatusV1 = "expired"
	// AuditReferenceWrongVersion: the evidence is of a different schema, model or
	// methodology version than the manifest names.
	AuditReferenceWrongVersion AuditReferenceStatusV1 = "wrong_version"
	// AuditReferenceInvalidSignature: the device signature does not verify under
	// the enrolled key.
	AuditReferenceInvalidSignature AuditReferenceStatusV1 = "invalid_signature"
	// AuditReferenceUnknownSigner: no enrolled key matches the signing key ID.
	AuditReferenceUnknownSigner AuditReferenceStatusV1 = "unknown_signer"
	// AuditReferenceMalformed: the bytes match their digest but are not a valid
	// record of the named schema, or are not bound to their source.
	AuditReferenceMalformed AuditReferenceStatusV1 = "malformed"
)

// AuditReferenceCheckV1 is one reference's result. Reason is a stable short
// code that refines Status and holds no evidence content.
type AuditReferenceCheckV1 struct {
	ReferenceID   string                 `json:"reference_id"`
	SchemaVersion string                 `json:"schema_version"`
	Status        AuditReferenceStatusV1 `json:"status"`
	Reason        string                 `json:"reason"`
}

// AuditManifestVerificationV1 is a freshly computed verification of one stored
// manifest. Nothing in it is read from a stored result. EvidenceStatus uses the
// CT09 vocabulary (verified, invalid_signature, digest_mismatch,
// evidence_expired, evidence_missing); References, empty unless the manifest
// itself authenticated and is current, say which record each status comes from.
// AnchorState is always unverified, because no chain state is consulted.
type AuditManifestVerificationV1 struct {
	SchemaVersion  string                  `json:"schema_version"`
	DeploymentID   string                  `json:"deployment_id"`
	ManifestID     string                  `json:"manifest_id"`
	CommitmentID   string                  `json:"commitment_id"`
	CheckedAt      time.Time               `json:"checked_at"`
	EvidenceStatus string                  `json:"evidence_status"`
	AnchorState    string                  `json:"anchor_state"`
	Scope          string                  `json:"scope"`
	Truthfulness   string                  `json:"endpoint_truthfulness"`
	References     []AuditReferenceCheckV1 `json:"references"`
}
