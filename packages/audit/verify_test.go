package audit

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type verifyFixture struct {
	manifest   contracts.AuditManifestV1
	commitment contracts.AuditCommitmentV1
	key        ed25519.PublicKey
	evidence   map[string]Evidence
	now        time.Time
}

func predictionBytes(t *testing.T, device, model string) []byte {
	t.Helper()
	probability, horizon := 0.4, uint32(168)
	data, err := json.Marshal(contracts.PredictionV2{SchemaVersion: contracts.PredictionV2Version, DeviceID: device,
		Model:       &contracts.ModelReferenceV2{Version: model, SHA256: strings.Repeat("a", 64)},
		Evidence:    &contracts.EvidenceV2{Digest: strings.Repeat("b", 64), TelemetrySchemaVersion: contracts.TelemetryV2Version},
		GeneratedAt: time.Date(2026, 11, 28, 11, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 11, 28, 13, 0, 0, 0, time.UTC),
		Health:    contracts.HealthV2{Status: "healthy", Probability: &probability, ProbabilityUnit: "probability", HorizonHours: &horizon},
		Forecasts: []contracts.FaultForecastV2{}}) //nolint
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func newVerifyFixture(t *testing.T) verifyFixture {
	t.Helper()
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	created := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	content := predictionBytes(t, "device:one", "model.v1")
	sum := sha256.Sum256(content)
	spec := ManifestSpec{DeploymentID: "deployment:audit", ManifestID: "manifest:v", CommitmentID: strings.Repeat("a1", 32), BlindingNonce: strings.Repeat("b2", 32),
		PolicyVersion: contracts.AuditManifestPolicyV1, CreatedAt: created, ExpiresAt: created.Add(7 * 24 * time.Hour),
		Evidence: []contracts.AuditEvidenceReferenceV1{{ReferenceID: "evidence:prediction:1", SchemaVersion: contracts.PredictionV2Version,
			SHA256: hex.EncodeToString(sum[:]), SizeBytes: uint32(len(content)), ExpiresAt: created.Add(30 * 24 * time.Hour).Format(time.RFC3339)}}}
	manifest, commitment, err := BuildManifest(spec, key)
	if err != nil {
		t.Fatal(err)
	}
	return verifyFixture{manifest: manifest, commitment: commitment, key: key.Public().(ed25519.PublicKey), now: created.Add(time.Hour),
		evidence: map[string]Evidence{"evidence:prediction:1": {Found: true, SchemaVersion: contracts.PredictionV2Version, RetentionEndsAt: created.Add(30 * 24 * time.Hour), Content: content}}}
}

func (f verifyFixture) input() VerifyInput {
	evidence := map[string]Evidence{}
	for id, e := range f.evidence {
		evidence[id] = e
	}
	manifest := f.manifest
	manifest.Evidence = append([]contracts.AuditEvidenceReferenceV1(nil), f.manifest.Evidence...)
	return VerifyInput{Manifest: &manifest, Commitment: f.commitment, AuditKey: f.key, Now: f.now, Evidence: evidence}
}

func TestVerifyManifestReportsDistinctOutcomesAndIntegrityOnly(t *testing.T) {
	f := newVerifyFixture(t)
	reference := "evidence:prediction:1"
	run := func(name string, input VerifyInput, wantStatus string, wantReference contracts.AuditReferenceStatusV1) contracts.AuditManifestVerificationV1 {
		t.Helper()
		report, err := VerifyManifest(input)
		if err != nil || report.EvidenceStatus != wantStatus || report.AnchorState != "unverified" ||
			report.Scope != contracts.AuditVerificationScopeV1 || report.Truthfulness != contracts.AuditTruthfulnessV1 {
			t.Fatalf("%s: %+v err=%v", name, report, err)
		}
		if wantReference != "" && (len(report.References) != 1 || report.References[0].Status != wantReference) {
			t.Fatalf("%s: references %+v want %s", name, report.References, wantReference)
		}
		return report
	}

	report := run("intact", f.input(), "verified", contracts.AuditReferenceVerified)
	if report.References[0].Reason != "digest_and_shape_only" {
		t.Fatalf("a record with no device signature claimed one: %+v", report.References[0])
	}

	edited := f.input()
	changed := append([]byte(nil), f.evidence[reference].Content...)
	changed[len(changed)-2] ^= 1
	e := edited.Evidence[reference]
	e.Content = changed
	edited.Evidence[reference] = e
	run("edited", edited, "digest_mismatch", contracts.AuditReferenceEdited)

	missing := f.input()
	delete(missing.Evidence, reference)
	run("missing", missing, "evidence_missing", contracts.AuditReferenceMissing)
	notFound := f.input()
	notFound.Evidence[reference] = Evidence{}
	run("not found", notFound, "evidence_missing", contracts.AuditReferenceMissing)

	expired := f.input()
	e = expired.Evidence[reference]
	e.RetentionEndsAt = f.now.Add(-time.Second)
	expired.Evidence[reference] = e
	run("retention ended", expired, "evidence_expired", contracts.AuditReferenceExpired)

	wrongSchema := f.input()
	e = wrongSchema.Evidence[reference]
	e.SchemaVersion = contracts.LifecycleV2Version
	wrongSchema.Evidence[reference] = e
	run("stored schema", wrongSchema, "digest_mismatch", contracts.AuditReferenceWrongVersion)

	// A record of another model version than the one signed over is a version error.
	model, sha := "model.v2", strings.Repeat("a", 64)
	wrongModel := f.input()
	wrongModel.Bindings = map[string]Binding{reference: {ModelVersion: &model, ModelSHA256: &sha}}
	run("model version", wrongModel, "digest_mismatch", contracts.AuditReferenceWrongVersion)
	model = "model.v1"
	wrongModel.Bindings = map[string]Binding{reference: {ModelVersion: &model, ModelSHA256: &sha}}
	run("bound model", wrongModel, "verified", contracts.AuditReferenceVerified)

	// A record that is not valid JSON of its schema is malformed, not edited.
	garbage := f.input()
	notJSON := []byte("not json at all")
	sum := sha256.Sum256(notJSON)
	garbage.Manifest.Evidence[0].SHA256 = hex.EncodeToString(sum[:])
	garbage.Manifest.Evidence[0].SizeBytes = uint32(len(notJSON))
	e = garbage.Evidence[reference]
	e.Content = notJSON
	garbage.Evidence[reference] = e
	// Re-sign so that only the evidence, not the manifest, is at fault.
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, ed25519.SeedSize))
	signing, _ := garbage.Manifest.SigningBytes()
	garbage.Manifest.Signature = hex.EncodeToString(ed25519.Sign(key, signing))
	garbage.Commitment, _ = garbage.Manifest.Commitment()
	run("malformed", garbage, "digest_mismatch", contracts.AuditReferenceMalformed)

	// Manifest-level failures come first and examine no reference.
	other := f.input()
	other.AuditKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{10}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if r := run("other key", other, "invalid_signature", ""); len(r.References) != 0 {
		t.Fatalf("references examined for an unauthenticated manifest: %+v", r.References)
	}
	wrongCommitment := f.input()
	wrongCommitment.Commitment.CommitmentSHA256 = strings.Repeat("0", 64)
	run("commitment", wrongCommitment, "digest_mismatch", "")
	late := f.input()
	late.Now = f.now.Add(8 * 24 * time.Hour)
	run("manifest expired", late, "evidence_expired", "")
	absent := f.input()
	absent.Manifest = nil
	run("no manifest", absent, "evidence_missing", "")
	early := f.input()
	early.Now = f.now.Add(-2 * time.Hour)
	if _, err := VerifyManifest(early); err == nil {
		t.Fatal("a manifest from the future was verified")
	}
	if _, err := VerifyManifest(VerifyInput{}); err == nil {
		t.Fatal("verified without a clock")
	}
}
