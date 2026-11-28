package audit

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ManifestSpec is everything a signed manifest holds. The commitment ID and
// blinding nonce must come from a cryptographic random generator, once per
// manifest; the builder only checks their shape.
type ManifestSpec struct {
	DeploymentID  string
	ManifestID    string
	CommitmentID  string
	BlindingNonce string
	PolicyVersion string
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Evidence      []contracts.AuditEvidenceReferenceV1
}

// BuildManifest returns the canonical signed manifest and its public
// commitment. Evidence is ordered by reference ID, so the same inputs in any
// order give the same signing bytes, signature (Ed25519 is deterministic) and
// commitment. Any change to an identity, time, reference, digest or version
// changes the signing bytes, so a signature for one manifest never verifies
// another. Whole-second UTC timestamps are required, not rounded.
func BuildManifest(spec ManifestSpec, key ed25519.PrivateKey) (contracts.AuditManifestV1, contracts.AuditCommitmentV1, error) {
	if len(key) != ed25519.PrivateKeySize {
		return contracts.AuditManifestV1{}, contracts.AuditCommitmentV1{}, fmt.Errorf("audit manifest signing key required")
	}
	keyID, err := contracts.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	if err != nil {
		return contracts.AuditManifestV1{}, contracts.AuditCommitmentV1{}, err
	}
	if spec.CreatedAt.Nanosecond() != 0 || spec.ExpiresAt.Nanosecond() != 0 {
		return contracts.AuditManifestV1{}, contracts.AuditCommitmentV1{}, fmt.Errorf("manifest times must be whole seconds")
	}
	evidence := append([]contracts.AuditEvidenceReferenceV1(nil), spec.Evidence...)
	sort.Slice(evidence, func(i, j int) bool { return evidence[i].ReferenceID < evidence[j].ReferenceID })
	m := contracts.AuditManifestV1{
		SchemaVersion: contracts.AuditManifestV1Version, DeploymentID: spec.DeploymentID, ManifestID: spec.ManifestID,
		CommitmentID: spec.CommitmentID, BlindingNonce: spec.BlindingNonce, PolicyVersion: spec.PolicyVersion,
		ControllerKeyID: keyID, CreatedAt: spec.CreatedAt.UTC().Format(time.RFC3339), ExpiresAt: spec.ExpiresAt.UTC().Format(time.RFC3339),
		Evidence: evidence,
	}
	message, err := m.SigningBytes()
	if err != nil {
		return contracts.AuditManifestV1{}, contracts.AuditCommitmentV1{}, err
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	commitment, err := m.Commitment()
	if err != nil {
		return contracts.AuditManifestV1{}, contracts.AuditCommitmentV1{}, err
	}
	return m, commitment, nil
}
