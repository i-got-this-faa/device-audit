package audit

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func testSpec() ManifestSpec {
	created := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	reference := func(id, schema, digest string, size uint32) contracts.AuditEvidenceReferenceV1 {
		return contracts.AuditEvidenceReferenceV1{ReferenceID: id, SchemaVersion: schema, SHA256: strings.Repeat(digest, 64), SizeBytes: size,
			ExpiresAt: created.Add(30 * 24 * time.Hour).Format(time.RFC3339)}
	}
	return ManifestSpec{
		DeploymentID: "deployment:audit", ManifestID: "manifest:1", CommitmentID: strings.Repeat("a1", 32), BlindingNonce: strings.Repeat("b2", 32),
		PolicyVersion: contracts.AuditManifestPolicyV1, CreatedAt: created, ExpiresAt: created.Add(7 * 24 * time.Hour),
		Evidence: []contracts.AuditEvidenceReferenceV1{
			reference("evidence:telemetry:1", contracts.EvidenceEnvelopeV1Version, "1", 900),
			reference("evidence:prediction:1", contracts.PredictionV2Version, "2", 400),
			reference("evidence:diagnostic:1", contracts.DiagnosticResultV1Version, "3", 700),
		},
	}
}

func TestBuildManifestIsCanonicalAndAnyChangeIsADifferentManifest(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	base, commitment, err := BuildManifest(testSpec(), key)
	if err != nil {
		t.Fatal(err)
	}
	if base.VerifySignature(pub) != nil || commitment.Validate() != nil || len(base.Evidence) != 3 ||
		base.Evidence[0].ReferenceID != "evidence:diagnostic:1" || base.Evidence[2].ReferenceID != "evidence:telemetry:1" {
		t.Fatalf("manifest is not sorted and signed: %+v", base)
	}
	baseBytes, _ := base.SigningBytes()

	// The same inputs in any order give identical canonical bytes, signature and digest.
	reordered := testSpec()
	reordered.Evidence[0], reordered.Evidence[2] = reordered.Evidence[2], reordered.Evidence[0]
	again, againCommitment, err := BuildManifest(reordered, key)
	if err != nil {
		t.Fatal(err)
	}
	againBytes, _ := again.SigningBytes()
	if !bytes.Equal(baseBytes, againBytes) || again.Signature != base.Signature || againCommitment != commitment {
		t.Fatal("equivalent inputs produced different manifests")
	}
	if testSpec().Evidence[0].ReferenceID != "evidence:telemetry:1" {
		t.Fatal("test spec is not stable")
	}

	// Every field that makes up the signed identity changes the digest and the signature.
	changes := map[string]func(*ManifestSpec){
		"deployment":    func(s *ManifestSpec) { s.DeploymentID = "deployment:other" },
		"manifest id":   func(s *ManifestSpec) { s.ManifestID = "manifest:2" },
		"commitment id": func(s *ManifestSpec) { s.CommitmentID = strings.Repeat("c3", 32) },
		"nonce":         func(s *ManifestSpec) { s.BlindingNonce = strings.Repeat("d4", 32) },
		"created":       func(s *ManifestSpec) { s.CreatedAt = s.CreatedAt.Add(time.Second) },
		"expiry":        func(s *ManifestSpec) { s.ExpiresAt = s.ExpiresAt.Add(time.Second) },
		"digest":        func(s *ManifestSpec) { s.Evidence[1].SHA256 = strings.Repeat("e", 64) },
		"size":          func(s *ManifestSpec) { s.Evidence[1].SizeBytes++ },
		"reference id":  func(s *ManifestSpec) { s.Evidence[1].ReferenceID = "evidence:prediction:2" },
		"schema":        func(s *ManifestSpec) { s.Evidence[1].SchemaVersion = contracts.LifecycleV2Version },
		"reference expiry": func(s *ManifestSpec) {
			s.Evidence[1].ExpiresAt = s.CreatedAt.Add(31 * 24 * time.Hour).Format(time.RFC3339)
		},
		"fewer references": func(s *ManifestSpec) { s.Evidence = s.Evidence[:2] },
	}
	for name, change := range changes {
		spec := testSpec()
		change(&spec)
		changed, changedCommitment, err := BuildManifest(spec, key)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if changedCommitment.CommitmentSHA256 == commitment.CommitmentSHA256 || changed.Signature == base.Signature {
			t.Fatalf("%s did not change the signed manifest", name)
		}
		// A signature for one manifest never verifies another's contents.
		spliced := changed
		spliced.Signature = base.Signature
		if spliced.VerifySignature(pub) == nil {
			t.Fatalf("%s: signature verified a different manifest", name)
		}
	}

	// The wrong key authenticates nothing.
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, ed25519.SeedSize))
	if base.VerifySignature(other.Public().(ed25519.PublicKey)) == nil {
		t.Fatal("manifest verified under another key")
	}
}

func TestBuildManifestRefusesIncompleteOrUnsupportedInput(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	refused := map[string]func(*ManifestSpec){
		"no evidence":     func(s *ManifestSpec) { s.Evidence = nil },
		"duplicate":       func(s *ManifestSpec) { s.Evidence[1].ReferenceID = s.Evidence[0].ReferenceID },
		"unknown schema":  func(s *ManifestSpec) { s.Evidence[0].SchemaVersion = "device-audit.unknown.v9" },
		"subsecond time":  func(s *ManifestSpec) { s.CreatedAt = s.CreatedAt.Add(time.Millisecond) },
		"bad nonce":       func(s *ManifestSpec) { s.BlindingNonce = "short" },
		"expiry reversed": func(s *ManifestSpec) { s.ExpiresAt = s.CreatedAt },
		"outlives refs":   func(s *ManifestSpec) { s.Evidence[0].ExpiresAt = s.CreatedAt.Format(time.RFC3339) },
		"zero size":       func(s *ManifestSpec) { s.Evidence[0].SizeBytes = 0 },
	}
	for name, change := range refused {
		spec := testSpec()
		change(&spec)
		if _, _, err := BuildManifest(spec, key); err == nil {
			t.Fatalf("%s was signed", name)
		}
	}
	if _, _, err := BuildManifest(testSpec(), nil); err == nil {
		t.Fatal("manifest signed without a key")
	}
}
