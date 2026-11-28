package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func TestAuditManifestsAreCanonicalSignedAndBoundToStoredEvidence(t *testing.T) {
	b := newForecastDiagnosticBed(t, "device:am-a")
	ctx := context.Background()
	const device = "device:am-a"
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x48}, ed25519.SeedSize))
	auditKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x49}, ed25519.SeedSize))
	auditPub := auditKey.Public().(ed25519.PublicKey)
	actor := contracts.ModelActorV1{Issuer: "https://id.example.test", Subject: "admin:am"}

	// Real evidence: a signed telemetry envelope, a prediction from a promoted
	// model and a device-signed diagnostic result that the forecast launched.
	asOf := b.startDay.AddDate(0, 0, 27).Add(20 * time.Minute)
	if delta := asOf.Sub(b.clock.Now()); delta > 0 {
		b.clock.Advance(delta)
	}
	recorded, err := b.repo.evaluateAndRecordDeviceHealth(ctx, b.cfg, device, asOf, makeSMARTMapReader(forecastDegradedSMART))
	if err != nil || recorded.Prediction == nil || recorded.Prediction.Model == nil {
		t.Fatalf("prediction setup: %+v err=%v", recorded, err)
	}
	launched, err := b.repo.TriggerForecastDiagnostics(ctx, device, diagKey, workflows.Actor(actor))
	if err != nil || len(launched.Decisions) != 1 {
		t.Fatalf("diagnostic setup: %+v err=%v", launched, err)
	}
	poll, err := b.repo.PollDiagnosticAssignments(ctx, device, time.Minute)
	if err != nil || len(poll.Assignments) != 1 {
		t.Fatalf("poll: %+v err=%v", poll, err)
	}
	runner := workflows.NewProbeRunner(func(context.Context, workflows.Request) ([]byte, error) {
		return []byte(`{"schema_version":"device-audit.probe-evidence.v1","health":"ok"}`), nil
	})
	result, err := workflows.ExecuteAssignedToResult(ctx, runner, poll.Assignments[0], diagKey.Public().(ed25519.PublicKey), b.devices[device].signing,
		b.repo.deploymentID, device, "boot:am:1", "ref:am:1", 30, b.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.SubmitDiagnosticResult(ctx, result); err != nil {
		t.Fatal(err)
	}
	longRetention := b.clock.Now().Add(60 * 24 * time.Hour)
	store := func(id string, kind contracts.AuditEvidenceKindV1, retention time.Time, fill func(*contracts.AuditEvidenceStoreRequestV1)) {
		t.Helper()
		request := contracts.AuditEvidenceStoreRequestV1{SchemaVersion: contracts.AuditEvidenceStoreV1Version, EvidenceID: id, Kind: kind, DeviceID: device, RetentionExpiresAt: retention}
		fill(&request)
		if _, _, err := b.repo.StoreAuditEvidence(ctx, request, actor); err != nil {
			t.Fatalf("store %s: %v", id, err)
		}
	}
	store("evidence:telemetry:29", contracts.AuditEvidenceTelemetry, longRetention, func(r *contracts.AuditEvidenceStoreRequestV1) { r.Sequence = 29 })
	store("evidence:prediction:1", contracts.AuditEvidencePrediction, longRetention, func(r *contracts.AuditEvidenceStoreRequestV1) { r.PredictionID = recorded.ID })
	store("evidence:diagnostic:1", contracts.AuditEvidenceDiagnostic, longRetention, func(r *contracts.AuditEvidenceStoreRequestV1) { r.AssignmentID = launched.Decisions[0].AssignmentID })
	store("evidence:telemetry:28", contracts.AuditEvidenceTelemetry, b.clock.Now().Add(24*time.Hour), func(r *contracts.AuditEvidenceStoreRequestV1) { r.Sequence = 28 })

	request := contracts.AuditManifestRequestV1{SchemaVersion: contracts.AuditManifestRequestV1Version, ManifestID: "manifest:am:1",
		PolicyVersion: contracts.AuditManifestPolicyV1, ExpiresAt: b.clock.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second),
		EvidenceIDs: []string{"evidence:telemetry:29", "evidence:diagnostic:1", "evidence:prediction:1"}}
	record, created, err := b.repo.CreateAuditManifest(ctx, request, auditKey, actor)
	if err != nil || !created {
		t.Fatalf("create manifest: created=%v err=%v", created, err)
	}
	m := record.Manifest
	if m.VerifySignature(auditPub) != nil || m.PolicyVersion != contracts.AuditManifestPolicyV1 || m.DeploymentID != b.repo.deploymentID || len(m.Evidence) != 3 ||
		m.Evidence[0].ReferenceID != "evidence:diagnostic:1" || m.Evidence[1].ReferenceID != "evidence:prediction:1" || m.Evidence[2].ReferenceID != "evidence:telemetry:29" ||
		m.Evidence[0].SchemaVersion != contracts.DiagnosticResultV1Version || m.Evidence[1].SchemaVersion != contracts.PredictionV2Version ||
		m.Evidence[2].SchemaVersion != contracts.EvidenceEnvelopeV1Version || record.CreatedBy != actor || record.Commitment.Validate() != nil {
		t.Fatalf("manifest: %+v", record)
	}
	if want, err := m.Commitment(); err != nil || want != record.Commitment {
		t.Fatalf("commitment does not follow from the manifest: %v", err)
	}

	// The basis names the model and methodology that produced each record.
	basis := map[string]contracts.AuditManifestBasisV1{}
	for _, item := range record.Basis {
		basis[item.ReferenceID] = item
	}
	prediction, diagnostic, telemetry := basis["evidence:prediction:1"], basis["evidence:diagnostic:1"], basis["evidence:telemetry:29"]
	if prediction.ModelVersion == nil || *prediction.ModelVersion != b.manifest.ModelVersion || prediction.ModelSHA256 == nil || *prediction.ModelSHA256 != b.manifest.ArtifactSHA256 ||
		prediction.MethodologyVersion != recorded.RulesVersion || prediction.Kind != contracts.AuditEvidencePrediction || prediction.DeviceID != device {
		t.Fatalf("prediction basis: %+v rules=%q", prediction, recorded.RulesVersion)
	}
	if diagnostic.MethodologyVersion != contracts.DiagnosticProbeStorageHealthV1 || diagnostic.ModelVersion != nil || diagnostic.ModelSHA256 != nil {
		t.Fatalf("diagnostic basis: %+v", diagnostic)
	}
	if telemetry.MethodologyVersion != contracts.TelemetryV2Version || telemetry.ModelVersion != nil {
		t.Fatalf("telemetry basis: %+v", telemetry)
	}

	// The retained bytes verify against the signed manifest.
	retained := map[string][]byte{}
	for _, reference := range m.Evidence {
		_, content, err := b.repo.AuditEvidenceContent(ctx, reference.ReferenceID, device)
		if err != nil {
			t.Fatal(err)
		}
		retained[reference.ReferenceID] = content
	}
	check := func(manifest *contracts.AuditManifestV1, commitment contracts.AuditCommitmentV1, bytesByID map[string][]byte, key ed25519.PublicKey) string {
		t.Helper()
		status, err := contracts.CheckAuditEvidenceV1(commitment, manifest, bytesByID, key, b.clock.Now())
		if err != nil {
			t.Fatal(err)
		}
		return status
	}
	if status := check(&m, record.Commitment, retained, auditPub); status != "verified" {
		t.Fatalf("retained evidence: %s", status)
	}
	altered := map[string][]byte{"evidence:diagnostic:1": retained["evidence:diagnostic:1"], "evidence:prediction:1": append([]byte(nil), retained["evidence:prediction:1"]...), "evidence:telemetry:29": retained["evidence:telemetry:29"]}
	altered["evidence:prediction:1"][0] ^= 0xff
	if status := check(&m, record.Commitment, altered, auditPub); status != "digest_mismatch" {
		t.Fatalf("altered evidence: %s", status)
	}
	if status := check(&m, record.Commitment, retained, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4a}, 32)).Public().(ed25519.PublicKey)); status != "invalid_signature" {
		t.Fatalf("another key: %s", status)
	}

	// The same request, in any evidence order and after a restart, is the same manifest.
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	reordered := request
	reordered.EvidenceIDs = []string{"evidence:prediction:1", "evidence:telemetry:29", "evidence:diagnostic:1"}
	b.clock.Advance(time.Hour)
	for _, repo := range []*PostgresRepository{b.repo, restarted} {
		again, created, err := repo.CreateAuditManifest(ctx, reordered, auditKey, actor)
		if err != nil || created {
			t.Fatalf("repeat: created=%v err=%v", created, err)
		}
		first, _ := m.SigningBytes()
		next, _ := again.Manifest.SigningBytes()
		if !bytes.Equal(first, next) || again.Manifest.Signature != m.Signature || again.Commitment != record.Commitment || again.ManifestSHA256 != record.ManifestSHA256 {
			t.Fatalf("repeat changed the manifest: %+v", again)
		}
	}

	// A different manifest ID over the same evidence is an independent commitment.
	second := request
	second.ManifestID = "manifest:am:2"
	other, created, err := b.repo.CreateAuditManifest(ctx, second, auditKey, actor)
	if err != nil || !created || other.Commitment.CommitmentID == record.Commitment.CommitmentID || other.Commitment.CommitmentSHA256 == record.Commitment.CommitmentSHA256 ||
		other.Manifest.BlindingNonce == m.BlindingNonce {
		t.Fatalf("second manifest: %+v created=%v err=%v", other, created, err)
	}

	// An altered reference, expiry or policy cannot reuse the first identity.
	conflicts := map[string]func(*contracts.AuditManifestRequestV1){
		"fewer references": func(r *contracts.AuditManifestRequestV1) { r.EvidenceIDs = r.EvidenceIDs[:2] },
		"other reference":  func(r *contracts.AuditManifestRequestV1) { r.EvidenceIDs[0] = "evidence:telemetry:28" },
		"later expiry":     func(r *contracts.AuditManifestRequestV1) { r.ExpiresAt = r.ExpiresAt.Add(time.Hour) },
	}
	for name, change := range conflicts {
		altered := request
		altered.EvidenceIDs = append([]string(nil), request.EvidenceIDs...)
		change(&altered)
		if _, _, err := b.repo.CreateAuditManifest(ctx, altered, auditKey, actor); !errors.Is(err, contracts.AuditManifestRejectionConflict) {
			t.Fatalf("%s reused the manifest identity: %v", name, err)
		}
	}
	stored, err := b.repo.AuditManifest(ctx, request.ManifestID)
	if err != nil || stored.ManifestSHA256 != record.ManifestSHA256 {
		t.Fatalf("manifest changed after refused requests: %+v err=%v", stored, err)
	}

	// Requests the policy cannot honour sign nothing.
	refusals := map[string]struct {
		change func(*contracts.AuditManifestRequestV1)
		want   error
	}{
		"unknown evidence":  {func(r *contracts.AuditManifestRequestV1) { r.EvidenceIDs = []string{"evidence:missing"} }, contracts.AuditEvidenceRejectionNotFound},
		"outlives evidence": {func(r *contracts.AuditManifestRequestV1) { r.EvidenceIDs = []string{"evidence:telemetry:28"} }, contracts.AuditManifestRejectionOutlivesEvidence},
		"other policy":      {func(r *contracts.AuditManifestRequestV1) { r.PolicyVersion = "device-audit.audit-manifest-policy.v0" }, contracts.AuditManifestRejectionInvalidRequest},
		"no evidence":       {func(r *contracts.AuditManifestRequestV1) { r.EvidenceIDs = nil }, contracts.AuditManifestRejectionInvalidRequest},
		"duplicate": {func(r *contracts.AuditManifestRequestV1) {
			r.EvidenceIDs = []string{"evidence:diagnostic:1", "evidence:diagnostic:1"}
		}, contracts.AuditManifestRejectionInvalidRequest},
		"past expiry": {func(r *contracts.AuditManifestRequestV1) {
			r.ExpiresAt = b.clock.Now().Add(-time.Hour).UTC().Truncate(time.Second)
		}, contracts.AuditManifestRejectionInvalidRequest},
		"subsecond expiry": {func(r *contracts.AuditManifestRequestV1) { r.ExpiresAt = r.ExpiresAt.Add(time.Millisecond) }, contracts.AuditManifestRejectionInvalidRequest},
	}
	for name, refusal := range refusals {
		bad := request
		bad.ManifestID = "manifest:am:refused:" + string(rune('a'+len(name)%20))
		bad.EvidenceIDs = append([]string(nil), request.EvidenceIDs...)
		refusal.change(&bad)
		if _, _, err := b.repo.CreateAuditManifest(ctx, bad, auditKey, actor); !errors.Is(err, refusal.want) {
			t.Fatalf("%s: %v want %v", name, err, refusal.want)
		}
	}
	var manifests int
	if err := b.db.QueryRow(`SELECT count(*) FROM audit_manifests`).Scan(&manifests); err != nil || manifests != 2 {
		t.Fatalf("refused requests stored manifests: %d err=%v", manifests, err)
	}
	// Evidence whose retention ended cannot be newly referenced; the manifest already made stays.
	b.clock.Advance(2 * 24 * time.Hour)
	expired := request
	expired.ManifestID, expired.ExpiresAt, expired.EvidenceIDs = "manifest:am:expired", b.clock.Now().Add(time.Hour).UTC().Truncate(time.Second), []string{"evidence:telemetry:28"}
	if _, _, err := b.repo.CreateAuditManifest(ctx, expired, auditKey, actor); !errors.Is(err, contracts.AuditEvidenceRejectionExpired) {
		t.Fatalf("expired evidence: %v", err)
	}
	if _, created, err := b.repo.CreateAuditManifest(ctx, request, auditKey, actor); err != nil || created {
		t.Fatalf("stored manifest after evidence expiry: created=%v err=%v", created, err)
	}

	// Stored manifests and their basis cannot be rewritten.
	for _, statement := range []string{`UPDATE audit_manifests SET policy_version='x'`, `DELETE FROM audit_manifests`,
		`UPDATE audit_manifest_evidence SET methodology_version='x'`, `DELETE FROM audit_manifest_evidence`} {
		if _, err := b.db.Exec(statement); err == nil {
			t.Fatalf("%s was allowed", statement)
		}
	}
	// A manifest damaged below the controller is refused, never served.
	for _, statement := range []string{`ALTER TABLE audit_manifests DISABLE TRIGGER audit_manifests_immutable`,
		`UPDATE audit_manifests SET manifest_sha256 = commitment_sha256 WHERE manifest_id='manifest:am:2'`} {
		if _, err := b.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.repo.AuditManifest(ctx, "manifest:am:2"); !errors.Is(err, contracts.AuditManifestRejectionUnavailable) {
		t.Fatalf("damaged manifest: %v", err)
	}
	if _, err := b.repo.AuditManifest(ctx, "manifest:missing"); !errors.Is(err, contracts.AuditManifestRejectionNotFound) {
		t.Fatalf("missing manifest: %v", err)
	}
}

func TestAuditManifestRoutesAuthorizeAndKeepTheNonceOutOfThePublicCommitment(t *testing.T) {
	b := newForecastDiagnosticBed(t, "device:am-route")
	ctx := context.Background()
	const device = "device:am-route"
	auditKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x4b}, ed25519.SeedSize))
	actor := contracts.ModelActorV1{Issuer: "https://id.example.test", Subject: "admin:am-route"}
	if _, _, err := b.repo.StoreAuditEvidence(ctx, contracts.AuditEvidenceStoreRequestV1{SchemaVersion: contracts.AuditEvidenceStoreV1Version, EvidenceID: "evidence:route:1",
		Kind: contracts.AuditEvidenceTelemetry, DeviceID: device, Sequence: 29, RetentionExpiresAt: b.clock.Now().Add(90 * 24 * time.Hour)}, actor); err != nil {
		t.Fatal(err)
	}
	service, err := NewAuditManifestService(b.repo, b.admin, auditKey)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, AuditManifests: service}).Handler()
	hz := httptest.NewRecorder()
	handler.ServeHTTP(hz, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var health map[string]any
	if json.Unmarshal(hz.Body.Bytes(), &health) != nil || health["audit_manifests"] != "configured" {
		t.Fatalf("healthz: %s", hz.Body.String())
	}
	admin, csrf := b.addSession(t, "admin:am-route", auth.RoleAdmin, 0)
	viewer, viewerCSRF := b.addSession(t, "viewer:am-route", auth.RoleViewer, 0)
	call := func(method, path string, body any, cookie, token string, want int) []byte {
		t.Helper()
		var raw []byte
		if body != nil {
			raw, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, path, bytes.NewReader(raw))
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: cookie})
		}
		if token != "" {
			r.Header.Set("Origin", "https://console.example.test")
			r.Header.Set("X-CSRF-Token", token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	request := contracts.AuditManifestRequestV1{SchemaVersion: contracts.AuditManifestRequestV1Version, ManifestID: "manifest:route:1", PolicyVersion: contracts.AuditManifestPolicyV1,
		ExpiresAt: b.clock.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second), EvidenceIDs: []string{"evidence:route:1"}}
	call(http.MethodPost, "/console/api/audit-manifests", request, "", "", http.StatusUnauthorized)
	call(http.MethodPost, "/console/api/audit-manifests", request, viewer, viewerCSRF, http.StatusForbidden)
	call(http.MethodPost, "/console/api/audit-manifests?x=1", request, admin, csrf, http.StatusBadRequest)
	call(http.MethodPost, "/console/api/audit-manifests", map[string]any{"schema_version": contracts.AuditManifestRequestV1Version, "evidence_bytes": "AAAA"}, admin, csrf, http.StatusBadRequest)
	missing := request
	missing.EvidenceIDs = []string{"evidence:missing"}
	call(http.MethodPost, "/console/api/audit-manifests", missing, admin, csrf, http.StatusNotFound)
	var record contracts.AuditManifestRecordV1
	if err := json.Unmarshal(call(http.MethodPost, "/console/api/audit-manifests", request, admin, csrf, http.StatusCreated), &record); err != nil || record.Manifest.BlindingNonce == "" {
		t.Fatalf("create over HTTP: %+v err=%v", record, err)
	}
	call(http.MethodPost, "/console/api/audit-manifests", request, admin, csrf, http.StatusOK)
	conflict := request
	conflict.ExpiresAt = conflict.ExpiresAt.Add(time.Hour)
	call(http.MethodPost, "/console/api/audit-manifests", conflict, admin, csrf, http.StatusConflict)

	call(http.MethodGet, "/console/api/audit-manifests/manifest:route:1", nil, viewer, "", http.StatusForbidden)
	call(http.MethodGet, "/console/api/audit-manifests/manifest:absent", nil, admin, "", http.StatusNotFound)
	var served contracts.AuditManifestRecordV1
	if err := json.Unmarshal(call(http.MethodGet, "/console/api/audit-manifests/manifest:route:1", nil, admin, "", http.StatusOK), &served); err != nil ||
		served.Manifest.Signature != record.Manifest.Signature || served.Commitment != record.Commitment {
		t.Fatalf("served manifest: %+v err=%v", served, err)
	}
	// The viewer-visible commitment is exactly the three public fields.
	public := call(http.MethodGet, "/console/api/audit-manifests/manifest:route:1/commitment", nil, viewer, "", http.StatusOK)
	var fields map[string]any
	if err := json.Unmarshal(public, &fields); err != nil || len(fields) != 3 || fields["commitment_id"] != record.Commitment.CommitmentID ||
		bytes.Contains(public, []byte(record.Manifest.BlindingNonce)) || bytes.Contains(public, []byte(device)) {
		t.Fatalf("public commitment: %s", public)
	}
	call(http.MethodGet, "/console/api/audit-manifests/manifest:route:1/commitment", nil, "", "", http.StatusUnauthorized)
}
