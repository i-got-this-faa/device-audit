//go:build ignore

// Regenerate with go run packages/contracts/fixtures/audit/generate.go.
// Public test keys, IDs and nonces below must never be operational material.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	c "github.com/i-got-this-faa/device-audit/packages/contracts"
	"os"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func ptr[T any](v T) *T { return &v }
func readPayload(path, field string, index int) []byte {
	data, err := os.ReadFile(path)
	must(err)
	var collection struct {
		Vectors []map[string]json.RawMessage `json:"vectors"`
	}
	must(json.Unmarshal(data, &collection))
	var out bytes.Buffer
	must(json.Compact(&out, collection.Vectors[index][field]))
	return out.Bytes()
}

type vector struct {
	Name           string `json:"name"`
	Payload        any    `json:"payload"`
	Valid          bool   `json:"valid"`
	SchemaValid    bool   `json:"schema_valid"`
	SignatureValid bool   `json:"signature_valid"`
	CanonicalHex   string `json:"canonical_hex"`
}

func main() {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	key := ed25519.NewKeyFromSeed(seed)
	keyID, _ := c.SigningKeyIDV1(ed25519.PublicKey(key[32:]))
	m := c.AuditManifestV1{SchemaVersion: c.AuditManifestV1Version, DeploymentID: "deployment-a", ManifestID: "manifest-a", CommitmentID: strings.Repeat("c", 64), BlindingNonce: strings.Repeat("d", 64), PolicyVersion: "audit-policy.v1", ControllerKeyID: keyID, CreatedAt: "2026-10-19T12:00:00Z", ExpiresAt: "2026-10-20T12:00:00Z"}
	artifacts := map[string][]byte{"evidence-a": readPayload("packages/contracts/fixtures/envelopes/v1-vectors.json", "envelope", 1), "lifecycle-a": readPayload("packages/contracts/fixtures/lifecycle/v2-vectors.json", "lifecycle", 0)}
	for _, ref := range []string{"evidence-a", "lifecycle-a"} {
		raw := artifacts[ref]
		digest := sha256.Sum256(raw)
		version := c.EvidenceEnvelopeV1Version
		if ref == "lifecycle-a" {
			version = c.LifecycleV2Version
		}
		m.Evidence = append(m.Evidence, c.AuditEvidenceReferenceV1{ReferenceID: ref, SchemaVersion: version, SHA256: hex.EncodeToString(digest[:]), SizeBytes: uint32(len(raw)), ExpiresAt: "2026-10-19T18:00:00Z"})
	}
	message, err := m.SigningBytes()
	must(err)
	m.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	commitment, err := m.Commitment()
	must(err)
	var vectors []vector
	add := func(n string, p any, valid, schema, signature bool, canonical []byte) {
		vectors = append(vectors, vector{n, p, valid, schema, signature, hex.EncodeToString(canonical)})
	}
	add("signed_manifest", m, true, true, true, message)
	add("opaque_commitment", commitment, true, true, false, nil)
	bad := m
	bad.Signature = strings.Repeat("0", 128)
	add("invalid_manifest_signature", bad, true, true, false, nil)
	bad = m
	bad.Evidence = append([]c.AuditEvidenceReferenceV1{}, m.Evidence...)
	bad.Evidence[1] = bad.Evidence[0]
	add("duplicate_reference", bad, false, true, false, nil)
	bad = m
	bad.Evidence = []c.AuditEvidenceReferenceV1{m.Evidence[1], m.Evidence[0]}
	add("noncanonical_reference_order", bad, false, true, false, nil)
	bad = m
	bad.ExpiresAt = m.CreatedAt
	add("empty_manifest_lifetime", bad, false, true, false, nil)
	bad = m
	bad.Evidence = append([]c.AuditEvidenceReferenceV1{}, m.Evidence...)
	bad.Evidence[0].SchemaVersion = "device-audit.raw-logs.v1"
	add("unsupported_inline_log_schema", bad, false, false, false, nil)
	raw, _ := json.Marshal(commitment)
	for _, field := range []string{"device_id", "serial_number", "hostname", "raw_logs", "manifest_id", "blinding_nonce"} {
		var value map[string]any
		must(json.Unmarshal(raw, &value))
		value[field] = "sensitive-value"
		add("public_"+field, value, false, false, false, nil)
	}
	bc := commitment
	bc.CommitmentID = "LAPTOP-serial-123"
	add("raw_identifier_in_commitment_id", bc, false, false, false, nil)
	bc = commitment
	bc.CommitmentSHA256 = "raw log contents"
	add("raw_logs_in_commitment_digest", bc, false, false, false, nil)
	receipt := c.AuditReceiptV1{SchemaVersion: c.AuditReceiptV1Version, CommitmentID: commitment.CommitmentID, CommitmentSHA256: commitment.CommitmentSHA256, AdapterID: "unselected-adapter.v1", TransactionReference: "transaction-a", State: "pending", ObservedAt: "2026-10-19T12:05:00Z"}
	add("pending", receipt, true, true, false, nil)
	finalized := receipt
	finalized.State = "finalized"
	finalized.BlockReference = ptr("block-a")
	finalized.FinalizedAt = ptr("2026-10-19T12:04:00Z")
	add("finalized", finalized, true, true, false, nil)
	reverted := receipt
	reverted.State = "reverted"
	reverted.Reason = ptr("reorganized")
	reverted.ObservedAt = "2026-10-19T12:06:00Z"
	reverted.BlockReference = ptr("block-a")
	add("reverted_after_finality", reverted, true, true, false, nil)
	pendingBad := receipt
	pendingBad.FinalizedAt = finalized.FinalizedAt
	add("pending_claims_finality", pendingBad, false, false, false, nil)
	finalizedBad := finalized
	finalizedBad.FinalizedAt = ptr("2026-10-19T12:06:00Z")
	add("finality_after_observation", finalizedBad, false, true, false, nil)
	for _, status := range []string{"verified", "evidence_missing", "evidence_expired", "digest_mismatch", "invalid_signature"} {
		add(status+"_unverified_anchor", c.AuditVerificationV1{SchemaVersion: c.AuditVerificationV1Version, CommitmentID: commitment.CommitmentID, CheckedAt: "2026-10-19T12:05:00Z", EvidenceStatus: status, AnchorState: "unverified"}, true, true, false, nil)
	}
	for _, combination := range []struct{ name, evidence, anchor string }{
		{"finalized_with_missing_evidence", "evidence_missing", "finalized"},
		{"reverted_with_intact_evidence", "verified", "reverted"},
	} {
		add(combination.name, c.AuditVerificationV1{SchemaVersion: c.AuditVerificationV1Version, CommitmentID: commitment.CommitmentID, CheckedAt: "2026-10-19T12:06:00Z", EvidenceStatus: combination.evidence, AnchorState: combination.anchor}, true, true, false, nil)
	}
	checks := []map[string]string{
		{"name": "available", "manifest": "present", "bytes": "complete", "now": "2026-10-19T12:05:00Z", "status": "verified"},
		{"name": "missing_manifest", "manifest": "missing", "bytes": "complete", "now": "2026-10-19T12:05:00Z", "status": "evidence_missing"},
		{"name": "missing_artifact", "manifest": "present", "bytes": "missing", "now": "2026-10-19T12:05:00Z", "status": "evidence_missing"},
		{"name": "expired_artifact", "manifest": "present", "bytes": "complete", "now": "2026-10-19T18:00:00Z", "status": "evidence_expired"},
		{"name": "expired_manifest", "manifest": "present", "bytes": "complete", "now": "2026-10-20T12:00:00Z", "status": "evidence_expired"},
		{"name": "altered_artifact", "manifest": "present", "bytes": "altered", "now": "2026-10-19T12:05:00Z", "status": "digest_mismatch"},
		{"name": "invalid_signature", "manifest": "tampered_signature", "bytes": "complete", "now": "2026-10-19T12:05:00Z", "status": "invalid_signature"},
	}
	encoded := map[string]string{}
	for name, raw := range artifacts {
		encoded[name] = base64.StdEncoding.EncodeToString(raw)
	}
	out, err := json.MarshalIndent(map[string]any{"verification_key": hex.EncodeToString(key[32:]), "artifacts_base64": encoded, "checks": checks, "vectors": vectors}, "", "  ")
	must(err)
	must(os.WriteFile("packages/contracts/fixtures/audit/v1-vectors.json", append(out, '\n'), 0644))
}
