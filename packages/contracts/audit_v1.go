package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

const (
	AuditManifestV1Version     = "device-audit.audit-manifest.v1"
	AuditCommitmentV1Version   = "device-audit.audit-commitment.v1"
	AuditReceiptV1Version      = "device-audit.audit-receipt.v1"
	AuditVerificationV1Version = "device-audit.audit-verification.v1"
)

type AuditEvidenceReferenceV1 struct {
	ReferenceID   string `json:"reference_id"`
	SchemaVersion string `json:"schema_version"`
	SHA256        string `json:"sha256"`
	SizeBytes     uint32 `json:"size_bytes"`
	ExpiresAt     string `json:"expires_at"`
}

// The entire signed manifest, including its blinding nonce, stays off-chain.
type AuditManifestV1 struct {
	SchemaVersion   string                     `json:"schema_version"`
	DeploymentID    string                     `json:"deployment_id"`
	ManifestID      string                     `json:"manifest_id"`
	CommitmentID    string                     `json:"commitment_id"`
	BlindingNonce   string                     `json:"blinding_nonce"`
	PolicyVersion   string                     `json:"policy_version"`
	ControllerKeyID string                     `json:"controller_key_id"`
	CreatedAt       string                     `json:"created_at"`
	ExpiresAt       string                     `json:"expires_at"`
	Evidence        []AuditEvidenceReferenceV1 `json:"evidence"`
	Signature       string                     `json:"signature"`
}

// Only these opaque fields may be sent to a future chain adapter.
type AuditCommitmentV1 struct {
	SchemaVersion    string `json:"schema_version"`
	CommitmentID     string `json:"commitment_id"`
	CommitmentSHA256 string `json:"commitment_sha256"`
}

// Receipts are off-chain adapter observations, not proofs of finality.
type AuditReceiptV1 struct {
	SchemaVersion        string  `json:"schema_version"`
	CommitmentID         string  `json:"commitment_id"`
	CommitmentSHA256     string  `json:"commitment_sha256"`
	AdapterID            string  `json:"adapter_id"`
	TransactionReference string  `json:"transaction_reference"`
	BlockReference       *string `json:"block_reference"`
	State                string  `json:"state"`
	ObservedAt           string  `json:"observed_at"`
	FinalizedAt          *string `json:"finalized_at"`
	Reason               *string `json:"reason"`
}

// Evidence integrity and independently established chain state are separate.
type AuditVerificationV1 struct {
	SchemaVersion  string `json:"schema_version"`
	CommitmentID   string `json:"commitment_id"`
	CheckedAt      string `json:"checked_at"`
	EvidenceStatus string `json:"evidence_status"`
	AnchorState    string `json:"anchor_state"`
}

func (e *AuditEvidenceReferenceV1) UnmarshalJSON(data []byte) error {
	type wire AuditEvidenceReferenceV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"reference_id", "schema_version", "sha256", "size_bytes", "expires_at"}); err != nil {
		return err
	}
	*e = AuditEvidenceReferenceV1(v)
	return nil
}

func (m *AuditManifestV1) UnmarshalJSON(data []byte) error {
	type wire AuditManifestV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "deployment_id", "manifest_id", "commitment_id", "blinding_nonce", "policy_version", "controller_key_id", "created_at", "expires_at", "evidence", "signature"}); err != nil {
		return err
	}
	*m = AuditManifestV1(v)
	return nil
}

func (c *AuditCommitmentV1) UnmarshalJSON(data []byte) error {
	type wire AuditCommitmentV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "commitment_id", "commitment_sha256"}); err != nil {
		return err
	}
	*c = AuditCommitmentV1(v)
	return nil
}

func (r *AuditReceiptV1) UnmarshalJSON(data []byte) error {
	type wire AuditReceiptV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "commitment_id", "commitment_sha256", "adapter_id", "transaction_reference", "block_reference", "state", "observed_at", "finalized_at", "reason"}, "block_reference", "finalized_at", "reason"); err != nil {
		return err
	}
	*r = AuditReceiptV1(v)
	return nil
}

func (v *AuditVerificationV1) UnmarshalJSON(data []byte) error {
	type wire AuditVerificationV1
	var decoded wire
	if err := decodeEnvelopeJSON(data, &decoded, []string{"schema_version", "commitment_id", "checked_at", "evidence_status", "anchor_state"}); err != nil {
		return err
	}
	*v = AuditVerificationV1(decoded)
	return nil
}

func (m AuditManifestV1) validateBody() error {
	if m.SchemaVersion != AuditManifestV1Version || !opaqueIDPattern.MatchString(m.DeploymentID) || !opaqueIDPattern.MatchString(m.ManifestID) || !fixedEnvelopeHex(m.CommitmentID, 32) || !fixedEnvelopeHex(m.BlindingNonce, 32) || !opaqueIDPattern.MatchString(m.PolicyVersion) || !validEnvelopeKeyID(m.ControllerKeyID) || len(m.Evidence) < 1 || len(m.Evidence) > 64 {
		return fmt.Errorf("invalid manifest identity or bounds")
	}
	created, err := parseEnvelopeTime(m.CreatedAt)
	if err != nil {
		return err
	}
	expires, err := parseEnvelopeTime(m.ExpiresAt)
	if err != nil {
		return err
	}
	if !expires.After(created) || expires.Sub(created) > 365*24*time.Hour {
		return fmt.Errorf("manifest lifetime outside (0,365 days]")
	}
	previous := ""
	for _, e := range m.Evidence {
		if !opaqueIDPattern.MatchString(e.ReferenceID) || e.ReferenceID <= previous || !fixedEnvelopeHex(e.SHA256, 32) || e.SizeBytes < 1 || e.SizeBytes > 10485760 {
			return fmt.Errorf("invalid, duplicate or unsorted evidence")
		}
		previous = e.ReferenceID
		switch e.SchemaVersion {
		case EvidenceEnvelopeV1Version, PredictionV2Version, LifecycleV2Version:
		default:
			return fmt.Errorf("unsupported evidence schema")
		}
		expiry, err := parseEnvelopeTime(e.ExpiresAt)
		if err != nil {
			return err
		}
		if !expiry.After(created) {
			return fmt.Errorf("evidence expires before manifest creation")
		}
	}
	return nil
}

func (m AuditManifestV1) Validate() error {
	if err := m.validateBody(); err != nil {
		return err
	}
	return validateEnvelopeSignature(m.Signature)
}

func (m AuditManifestV1) SigningBytes() ([]byte, error) {
	if err := m.validateBody(); err != nil {
		return nil, err
	}
	fields := []string{m.SchemaVersion, m.DeploymentID, m.ManifestID, m.CommitmentID, m.BlindingNonce, m.PolicyVersion, m.ControllerKeyID, m.CreatedAt, m.ExpiresAt, strconv.Itoa(len(m.Evidence))}
	for _, e := range m.Evidence {
		fields = append(fields, e.ReferenceID, e.SchemaVersion, e.SHA256, strconv.FormatUint(uint64(e.SizeBytes), 10), e.ExpiresAt)
	}
	return canonicalEnvelopeFields(fields), nil
}

func (m AuditManifestV1) VerifySignature(trustedAuditKey ed25519.PublicKey) error {
	message, err := m.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(trustedAuditKey, m.ControllerKeyID, m.Signature, message)
}

func (m AuditManifestV1) Commitment() (AuditCommitmentV1, error) {
	if err := m.Validate(); err != nil {
		return AuditCommitmentV1{}, err
	}
	message, err := m.SigningBytes()
	if err != nil {
		return AuditCommitmentV1{}, err
	}
	manifestHash, err := EnvelopeRequestSHA256V1(message, m.Signature)
	if err != nil {
		return AuditCommitmentV1{}, err
	}
	preimage := []byte("device-audit/audit-commitment/v1\x00")
	for _, field := range []string{m.CommitmentID, m.BlindingNonce, manifestHash} {
		raw, _ := hex.DecodeString(field)
		preimage = append(preimage, raw...)
	}
	digest := sha256.Sum256(preimage)
	return AuditCommitmentV1{SchemaVersion: AuditCommitmentV1Version, CommitmentID: m.CommitmentID, CommitmentSHA256: hex.EncodeToString(digest[:])}, nil
}

func (c AuditCommitmentV1) Validate() error {
	if c.SchemaVersion != AuditCommitmentV1Version || !fixedEnvelopeHex(c.CommitmentID, 32) || !fixedEnvelopeHex(c.CommitmentSHA256, 32) {
		return fmt.Errorf("public commitment requires only opaque 32-byte ID and digest")
	}
	return nil
}

func (r AuditReceiptV1) Validate() error {
	if r.SchemaVersion != AuditReceiptV1Version || !fixedEnvelopeHex(r.CommitmentID, 32) || !fixedEnvelopeHex(r.CommitmentSHA256, 32) || !opaqueIDPattern.MatchString(r.AdapterID) || !opaqueIDPattern.MatchString(r.TransactionReference) {
		return fmt.Errorf("invalid receipt binding")
	}
	observed, err := parseEnvelopeTime(r.ObservedAt)
	if err != nil {
		return err
	}
	if r.BlockReference != nil && !opaqueIDPattern.MatchString(*r.BlockReference) {
		return fmt.Errorf("invalid block reference")
	}
	switch r.State {
	case "pending":
		if r.FinalizedAt != nil || r.Reason != nil {
			return fmt.Errorf("pending receipt cannot claim finality or reversion")
		}
	case "finalized":
		if r.BlockReference == nil || r.FinalizedAt == nil || r.Reason != nil {
			return fmt.Errorf("finalized receipt requires block and finality time")
		}
		finalized, err := parseEnvelopeTime(*r.FinalizedAt)
		if err != nil {
			return err
		}
		if finalized.After(observed) {
			return fmt.Errorf("finality time after observation")
		}
	case "reverted":
		if r.FinalizedAt != nil || r.Reason == nil || (*r.Reason != "transaction_failed" && *r.Reason != "reorganized" && *r.Reason != "commitment_absent") {
			return fmt.Errorf("reverted receipt requires reason and no current finality")
		}
	default:
		return fmt.Errorf("invalid receipt state")
	}
	return nil
}

func (r AuditReceiptV1) CheckCommitment(c AuditCommitmentV1) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if r.CommitmentID != c.CommitmentID || r.CommitmentSHA256 != c.CommitmentSHA256 {
		return fmt.Errorf("receipt does not match commitment")
	}
	return nil
}

func (v AuditVerificationV1) Validate() error {
	if v.SchemaVersion != AuditVerificationV1Version || !fixedEnvelopeHex(v.CommitmentID, 32) {
		return fmt.Errorf("invalid verification binding")
	}
	if _, err := parseEnvelopeTime(v.CheckedAt); err != nil {
		return err
	}
	switch v.EvidenceStatus {
	case "verified", "evidence_missing", "evidence_expired", "digest_mismatch", "invalid_signature":
	default:
		return fmt.Errorf("invalid evidence status")
	}
	switch v.AnchorState {
	case "unverified", "pending", "finalized", "reverted":
	default:
		return fmt.Errorf("invalid anchor state")
	}
	return nil
}

// CheckAuditEvidenceV1 checks supplied off-chain bytes. It does not fetch data,
// authorize a deployment/key, parse referenced payloads or establish chain state.
func CheckAuditEvidenceV1(c AuditCommitmentV1, m *AuditManifestV1, evidence map[string][]byte, trustedAuditKey ed25519.PublicKey, now time.Time) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	if now.IsZero() {
		return "", fmt.Errorf("receiver clock required")
	}
	if m == nil {
		return "evidence_missing", nil
	}
	if err := m.Validate(); err != nil {
		return "", err
	}
	if err := m.VerifySignature(trustedAuditKey); err != nil {
		return "invalid_signature", nil
	}
	expected, err := m.Commitment()
	if err != nil {
		return "", err
	}
	if expected != c {
		return "digest_mismatch", nil
	}
	created, _ := parseEnvelopeTime(m.CreatedAt)
	if now.Before(created) {
		return "", fmt.Errorf("manifest is from the future")
	}
	expires, _ := parseEnvelopeTime(m.ExpiresAt)
	if !now.Before(expires) {
		return "evidence_expired", nil
	}
	for _, e := range m.Evidence {
		expiry, _ := parseEnvelopeTime(e.ExpiresAt)
		if !now.Before(expiry) {
			return "evidence_expired", nil
		}
	}
	for _, e := range m.Evidence {
		if _, ok := evidence[e.ReferenceID]; !ok {
			return "evidence_missing", nil
		}
	}
	for _, e := range m.Evidence {
		raw := evidence[e.ReferenceID]
		sum := sha256.Sum256(raw)
		if uint64(len(raw)) != uint64(e.SizeBytes) || hex.EncodeToString(sum[:]) != e.SHA256 {
			return "digest_mismatch", nil
		}
	}
	return "verified", nil
}
