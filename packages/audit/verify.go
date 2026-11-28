package audit

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// Evidence is one stored record as found, with nothing assumed about it. Found
// is false when no record exists for the reference.
type Evidence struct {
	Found           bool
	SchemaVersion   string
	RetentionEndsAt time.Time
	Content         []byte
}

// Binding is what was recorded about a reference when it was signed, used to
// catch evidence of another model or methodology version. Nil fields are not
// checked.
type Binding struct {
	ModelVersion       *string
	ModelSHA256        *string
	MethodologyVersion string
}

// VerifyInput is everything a verification needs. The verifier trusts only
// AuditKey and what it recomputes from Evidence; DeviceKey resolves an
// enrolled device key by device and signing key ID, and Assignment resolves
// the controller-signed assignment a diagnostic result answers.
type VerifyInput struct {
	Manifest   *contracts.AuditManifestV1
	Commitment contracts.AuditCommitmentV1
	AuditKey   ed25519.PublicKey
	Now        time.Time
	Evidence   map[string]Evidence
	Bindings   map[string]Binding
	DeviceKey  func(deviceID, signingKeyID string) (ed25519.PublicKey, bool)
	Assignment func(assignmentID string) (contracts.DiagnosticAssignmentV1, bool)
}

// VerifyManifest recomputes the manifest signature and commitment, every
// reference digest and size, the schema and bound versions, and each device
// signature, and returns distinct results for edited, missing, expired,
// wrong-version and badly signed evidence. It reads no stored verdict. The
// result establishes integrity only, never that an endpoint told the truth.
// Manifest-level failures follow CT09: a missing manifest, then an invalid
// signature, a commitment mismatch and expiry are decided before any reference.
func VerifyManifest(in VerifyInput) (contracts.AuditManifestVerificationV1, error) {
	out := contracts.AuditManifestVerificationV1{SchemaVersion: contracts.AuditManifestVerificationV1Version, CheckedAt: in.Now.UTC(),
		AnchorState: "unverified", Scope: contracts.AuditVerificationScopeV1, Truthfulness: contracts.AuditTruthfulnessV1,
		References: []contracts.AuditReferenceCheckV1{}}
	if in.Now.IsZero() {
		return out, fmt.Errorf("verifier clock required")
	}
	if err := in.Commitment.Validate(); err != nil {
		return out, err
	}
	out.CommitmentID = in.Commitment.CommitmentID
	if in.Manifest == nil {
		out.EvidenceStatus = "evidence_missing"
		return out, nil
	}
	m := in.Manifest
	if err := m.Validate(); err != nil {
		return out, err
	}
	out.DeploymentID, out.ManifestID = m.DeploymentID, m.ManifestID
	if m.VerifySignature(in.AuditKey) != nil {
		out.EvidenceStatus = "invalid_signature"
		return out, nil
	}
	expected, err := m.Commitment()
	if err != nil {
		return out, err
	}
	if expected != in.Commitment {
		out.EvidenceStatus = "digest_mismatch"
		return out, nil
	}
	created, _ := time.Parse(time.RFC3339, m.CreatedAt)
	if in.Now.Before(created) {
		return out, fmt.Errorf("manifest is from the future")
	}
	if expires, _ := time.Parse(time.RFC3339, m.ExpiresAt); !in.Now.Before(expires) {
		out.EvidenceStatus = "evidence_expired"
		return out, nil
	}
	var expired, missing, altered, unsigned bool
	for _, reference := range m.Evidence {
		check := verifyReference(in, reference)
		out.References = append(out.References, check)
		switch check.Status {
		case contracts.AuditReferenceExpired:
			expired = true
		case contracts.AuditReferenceMissing:
			missing = true
		case contracts.AuditReferenceEdited, contracts.AuditReferenceWrongVersion, contracts.AuditReferenceMalformed:
			altered = true
		case contracts.AuditReferenceInvalidSignature, contracts.AuditReferenceUnknownSigner:
			unsigned = true
		}
	}
	switch {
	case expired:
		out.EvidenceStatus = "evidence_expired"
	case missing:
		out.EvidenceStatus = "evidence_missing"
	case altered:
		out.EvidenceStatus = "digest_mismatch"
	case unsigned:
		out.EvidenceStatus = "invalid_signature"
	default:
		out.EvidenceStatus = "verified"
	}
	return out, nil
}

func verifyReference(in VerifyInput, reference contracts.AuditEvidenceReferenceV1) contracts.AuditReferenceCheckV1 {
	result := func(status contracts.AuditReferenceStatusV1, reason string) contracts.AuditReferenceCheckV1 {
		return contracts.AuditReferenceCheckV1{ReferenceID: reference.ReferenceID, SchemaVersion: reference.SchemaVersion, Status: status, Reason: reason}
	}
	evidence, found := in.Evidence[reference.ReferenceID]
	if !found || !evidence.Found {
		return result(contracts.AuditReferenceMissing, "no_record")
	}
	// Retention is judged before the bytes, as CT09 judges expiry before integrity.
	expiry, _ := time.Parse(time.RFC3339, reference.ExpiresAt)
	if !in.Now.Before(expiry) || !in.Now.Before(evidence.RetentionEndsAt) {
		return result(contracts.AuditReferenceExpired, "retention_ended")
	}
	if evidence.SchemaVersion != reference.SchemaVersion {
		return result(contracts.AuditReferenceWrongVersion, "stored_schema_differs")
	}
	sum := sha256.Sum256(evidence.Content)
	if hex.EncodeToString(sum[:]) != reference.SHA256 || uint64(len(evidence.Content)) != uint64(reference.SizeBytes) {
		return result(contracts.AuditReferenceEdited, "digest_or_size_differs")
	}
	var header struct {
		SchemaVersion string `json:"schema_version"`
	}
	if json.Unmarshal(evidence.Content, &header) != nil {
		return result(contracts.AuditReferenceMalformed, "not_json")
	}
	if header.SchemaVersion != reference.SchemaVersion {
		return result(contracts.AuditReferenceWrongVersion, "payload_schema_differs")
	}
	binding := in.Bindings[reference.ReferenceID]
	switch reference.SchemaVersion {
	case contracts.EvidenceEnvelopeV1Version:
		var envelope contracts.EvidenceEnvelopeV1
		if json.Unmarshal(evidence.Content, &envelope) != nil || envelope.Validate() != nil {
			return result(contracts.AuditReferenceMalformed, "invalid_envelope")
		}
		if binding.MethodologyVersion != "" && envelope.PayloadSchemaVersion != binding.MethodologyVersion {
			return result(contracts.AuditReferenceWrongVersion, "payload_version_differs")
		}
		return signedResult(in, result, envelope.DeviceID, envelope.SigningKeyID, envelope.VerifySignature)
	case contracts.DiagnosticResultV1Version:
		var diagnostic contracts.DiagnosticResultV1
		if json.Unmarshal(evidence.Content, &diagnostic) != nil || diagnostic.Validate() != nil {
			return result(contracts.AuditReferenceMalformed, "invalid_result")
		}
		if in.Assignment == nil {
			return result(contracts.AuditReferenceMalformed, "assignment_unresolvable")
		}
		assignment, ok := in.Assignment(diagnostic.AssignmentID)
		if !ok || diagnostic.CheckAssignment(assignment) != nil {
			return result(contracts.AuditReferenceMalformed, "assignment_mismatch")
		}
		if binding.MethodologyVersion != "" && assignment.ProbeID != binding.MethodologyVersion {
			return result(contracts.AuditReferenceWrongVersion, "probe_differs")
		}
		return signedResult(in, result, diagnostic.DeviceID, diagnostic.SigningKeyID, diagnostic.VerifySignature)
	case contracts.PredictionV2Version:
		var prediction contracts.PredictionV2
		if json.Unmarshal(evidence.Content, &prediction) != nil || prediction.Validate() != nil {
			return result(contracts.AuditReferenceMalformed, "invalid_prediction")
		}
		if binding.ModelVersion != nil && (prediction.Model == nil || prediction.Model.Version != *binding.ModelVersion ||
			(binding.ModelSHA256 != nil && prediction.Model.SHA256 != *binding.ModelSHA256)) {
			return result(contracts.AuditReferenceWrongVersion, "model_differs")
		}
		// The controller made this record; there is no device signature to check.
		return result(contracts.AuditReferenceVerified, "digest_and_shape_only")
	default:
		return result(contracts.AuditReferenceVerified, "digest_only")
	}
}

func signedResult(in VerifyInput, result func(contracts.AuditReferenceStatusV1, string) contracts.AuditReferenceCheckV1, deviceID, keyID string, verify func(ed25519.PublicKey) error) contracts.AuditReferenceCheckV1 {
	if in.DeviceKey == nil {
		return result(contracts.AuditReferenceUnknownSigner, "no_key_source")
	}
	key, ok := in.DeviceKey(deviceID, keyID)
	if !ok {
		return result(contracts.AuditReferenceUnknownSigner, "no_enrolled_key")
	}
	if verify(key) != nil {
		return result(contracts.AuditReferenceInvalidSignature, "signature_does_not_verify")
	}
	return result(contracts.AuditReferenceVerified, "digest_and_signature")
}
