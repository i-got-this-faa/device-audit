package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func TestAuditEvidenceStoresExactSignedBytesWithScopeLimitsAndRetention(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x45}, ed25519.SeedSize))

	// A telemetry device with a recorded prediction, and a diagnostic device.
	telemetryDevice := "device:audit-t"
	keys := enrollTestDevice(t, b, telemetryDevice)
	diag := enrollMeshTestDevice(t, b, "device:audit-d")
	acceptTelemetrySample(t, b, telemetryDevice, keys, 2, b.clock.Now().Add(time.Minute), nil)
	recorded, err := b.repo.EvaluateAndRecordDeviceHealth(ctx, HealthConfig{PublisherKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey),
		EvaluationReports: EvaluationReportDir(t.TempDir())}, telemetryDevice, b.clock.Now())
	if err != nil || recorded.Prediction == nil {
		t.Fatalf("prediction setup: %+v err=%v", recorded, err)
	}
	noEvidence, err := b.repo.EvaluateAndRecordDeviceHealth(ctx, HealthConfig{PublisherKey: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey),
		EvaluationReports: EvaluationReportDir(t.TempDir())}, diag.id, b.clock.Now())
	if err != nil || noEvidence.Prediction != nil {
		t.Fatalf("no-evidence setup: %+v err=%v", noEvidence, err)
	}

	// One signed diagnostic result.
	if _, _, err := b.repo.CreateDiagnosticAssignment(ctx, workflows.AssignmentRequest{AssignmentID: "assign:audit", DeviceID: diag.id,
		ProbeID: contracts.DiagnosticProbeStorageHealthV1, Arguments: contracts.DiagnosticArgumentsV1{ComponentID: ptr("storage:disk-0")},
		Budget: contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 4096}, ExpiresInSeconds: 600}, diagKey, workflows.Actor{Issuer: "https://id.example.test", Subject: "admin:test"}); err != nil {
		t.Fatal(err)
	}
	poll, err := b.repo.PollDiagnosticAssignments(ctx, diag.id, time.Minute)
	if err != nil || len(poll.Assignments) != 1 {
		t.Fatalf("poll: %+v err=%v", poll, err)
	}
	runner := workflows.NewProbeRunner(func(context.Context, workflows.Request) ([]byte, error) {
		return []byte(`{"schema_version":"device-audit.probe-evidence.v1","health":"ok"}`), nil
	})
	result, err := workflows.ExecuteAssignedToResult(ctx, runner, poll.Assignments[0], diagKey.Public().(ed25519.PublicKey), diag.signing,
		b.repo.deploymentID, diag.id, "boot:audit:1", "ref:audit:1", 2, b.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.SubmitDiagnosticResult(ctx, result); err != nil {
		t.Fatal(err)
	}

	serve := func(repo *PostgresRepository) http.Handler {
		service, err := NewDeviceStateService(repo, b.admin)
		if err != nil {
			t.Fatal(err)
		}
		return NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service}).Handler()
	}
	handler := serve(b.repo)
	admin, csrf := b.addSession(t, "admin:audit", auth.RoleAdmin, 0)
	viewer, viewerCSRF := b.addSession(t, "viewer:audit", auth.RoleViewer, 0)
	call := func(h http.Handler, method, path string, body any, cookie, token string, want int) *httptest.ResponseRecorder {
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
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: %d want %d: %s", method, path, w.Code, want, w.Body.String())
		}
		return w
	}
	retention := b.clock.Now().Add(30 * 24 * time.Hour)
	telemetryRequest := contracts.AuditEvidenceStoreRequestV1{SchemaVersion: contracts.AuditEvidenceStoreV1Version, EvidenceID: "evidence:telemetry:1",
		Kind: contracts.AuditEvidenceTelemetry, DeviceID: telemetryDevice, Sequence: 2, RetentionExpiresAt: retention}
	predictionRequest := contracts.AuditEvidenceStoreRequestV1{SchemaVersion: contracts.AuditEvidenceStoreV1Version, EvidenceID: "evidence:prediction:1",
		Kind: contracts.AuditEvidencePrediction, DeviceID: telemetryDevice, PredictionID: recorded.ID, RetentionExpiresAt: retention}
	diagnosticRequest := contracts.AuditEvidenceStoreRequestV1{SchemaVersion: contracts.AuditEvidenceStoreV1Version, EvidenceID: "evidence:diagnostic:1",
		Kind: contracts.AuditEvidenceDiagnostic, DeviceID: diag.id, AssignmentID: "assign:audit", RetentionExpiresAt: retention}

	// Only a fresh administrator stores evidence.
	call(handler, http.MethodPost, "/console/api/audit-evidence", telemetryRequest, "", "", http.StatusUnauthorized)
	call(handler, http.MethodPost, "/console/api/audit-evidence", telemetryRequest, viewer, viewerCSRF, http.StatusForbidden)
	stored := map[string]contracts.AuditEvidenceV1{}
	for _, request := range []contracts.AuditEvidenceStoreRequestV1{telemetryRequest, predictionRequest, diagnosticRequest} {
		w := call(handler, http.MethodPost, "/console/api/audit-evidence", request, admin, csrf, http.StatusCreated)
		var meta contracts.AuditEvidenceV1
		if err := json.Unmarshal(w.Body.Bytes(), &meta); err != nil || meta.SHA256 == "" || meta.SizeBytes == 0 || meta.DeviceID != request.DeviceID ||
			meta.Kind != request.Kind || !meta.RetentionExpiresAt.Equal(retention.UTC().Truncate(time.Microsecond)) || meta.StoredBy.Subject != "admin:audit" {
			t.Fatalf("stored metadata: %+v err=%v", meta, err)
		}
		stored[request.EvidenceID] = meta
		// The identical request repeats without a second copy.
		call(handler, http.MethodPost, "/console/api/audit-evidence", request, admin, csrf, http.StatusOK)
	}

	// The bytes are the original signed objects, verifiable by the device's key.
	content := func(h http.Handler, id, query string, cookie string, want int) *httptest.ResponseRecorder {
		return call(h, http.MethodGet, "/console/api/audit-evidence/"+id+"/content"+query, nil, cookie, "", want)
	}
	telemetryBytes := content(handler, "evidence:telemetry:1", "", admin, http.StatusOK)
	var envelope contracts.EvidenceEnvelopeV1
	if err := json.Unmarshal(telemetryBytes.Body.Bytes(), &envelope); err != nil || envelope.VerifySignature(keys.signing.Public().(ed25519.PublicKey)) != nil ||
		envelope.Sequence != 2 || envelope.DeviceID != telemetryDevice {
		t.Fatalf("telemetry evidence is not the signed envelope: %v %s", err, telemetryBytes.Body.String())
	}
	sum := sha256.Sum256(telemetryBytes.Body.Bytes())
	digest, _ := hex.DecodeString(stored["evidence:telemetry:1"].SHA256)
	if hex.EncodeToString(sum[:]) != stored["evidence:telemetry:1"].SHA256 || uint32(telemetryBytes.Body.Len()) != stored["evidence:telemetry:1"].SizeBytes ||
		telemetryBytes.Header().Get("Repr-Digest") != "sha-256=:"+base64.StdEncoding.EncodeToString(digest)+":" {
		t.Fatalf("telemetry digest headers: %v", telemetryBytes.Header())
	}
	var prediction contracts.PredictionV2
	if err := json.Unmarshal(content(handler, "evidence:prediction:1", "", admin, http.StatusOK).Body.Bytes(), &prediction); err != nil ||
		prediction.DeviceID != telemetryDevice || prediction.Validate() != nil {
		t.Fatalf("prediction evidence: %+v err=%v", prediction, err)
	}
	var diagnostic contracts.DiagnosticResultV1
	if err := json.Unmarshal(content(handler, "evidence:diagnostic:1", "", admin, http.StatusOK).Body.Bytes(), &diagnostic); err != nil ||
		diagnostic.VerifySignature(diag.signing.Public().(ed25519.PublicKey)) != nil || diagnostic.AssignmentID != "assign:audit" {
		t.Fatalf("diagnostic evidence: %+v err=%v", diagnostic, err)
	}

	// A restart serves the same bytes; metadata needs only a viewer, bytes an administrator.
	restarted, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	again := serve(restarted)
	if got := content(again, "evidence:telemetry:1", "?device_id="+telemetryDevice, admin, http.StatusOK); !bytes.Equal(got.Body.Bytes(), telemetryBytes.Body.Bytes()) {
		t.Fatal("restart changed the stored bytes")
	}
	call(again, http.MethodGet, "/console/api/audit-evidence/evidence:telemetry:1", nil, viewer, "", http.StatusOK)
	content(again, "evidence:telemetry:1", "", viewer, http.StatusForbidden)
	content(again, "evidence:telemetry:1", "", "", http.StatusUnauthorized)

	// Wrong scope, unknown evidence and unknown parameters give explicit errors without bytes.
	for _, test := range []struct {
		id, query string
		status    int
		code      string
	}{
		{"evidence:telemetry:1", "?device_id=" + diag.id, http.StatusForbidden, "evidence_wrong_scope"},
		{"evidence:missing", "", http.StatusNotFound, "evidence_not_found"},
		{"evidence:telemetry:1", "?other=1", http.StatusBadRequest, "invalid_request"},
	} {
		w := content(again, test.id, test.query, admin, test.status)
		if strings.TrimSpace(w.Body.String()) != test.code || bytes.Contains(w.Body.Bytes(), []byte(telemetryDevice)) {
			t.Fatalf("%s %s: %q", test.id, test.query, w.Body.String())
		}
	}

	// Refusals store nothing.
	count := func() int {
		var n int
		if err := b.db.QueryRow(`SELECT count(*) FROM audit_evidence`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := count()
	refused := func(request contracts.AuditEvidenceStoreRequestV1, status int, code string) {
		t.Helper()
		w := call(handler, http.MethodPost, "/console/api/audit-evidence", request, admin, csrf, status)
		if strings.TrimSpace(w.Body.String()) != code {
			t.Fatalf("%s: %q want %q", request.EvidenceID, w.Body.String(), code)
		}
	}
	wrongDevice := telemetryRequest
	wrongDevice.EvidenceID, wrongDevice.DeviceID = "evidence:wrong-device", diag.id
	refused(wrongDevice, http.StatusNotFound, "evidence_source_not_found")
	missingSample := telemetryRequest
	missingSample.EvidenceID, missingSample.Sequence = "evidence:missing-sample", 99
	refused(missingSample, http.StatusNotFound, "evidence_source_not_found")
	noPrediction := predictionRequest
	noPrediction.EvidenceID, noPrediction.DeviceID, noPrediction.PredictionID = "evidence:no-prediction", diag.id, noEvidence.ID
	refused(noPrediction, http.StatusNotFound, "evidence_source_not_found")
	sameIDOtherSource := telemetryRequest
	sameIDOtherSource.Kind, sameIDOtherSource.Sequence, sameIDOtherSource.PredictionID = contracts.AuditEvidencePrediction, 0, recorded.ID
	refused(sameIDOtherSource, http.StatusConflict, "evidence_conflict")
	sameSourceOtherID := telemetryRequest
	sameSourceOtherID.EvidenceID = "evidence:telemetry:copy"
	refused(sameSourceOtherID, http.StatusConflict, "evidence_conflict")
	otherRetention := telemetryRequest
	otherRetention.RetentionExpiresAt = retention.Add(time.Hour)
	refused(otherRetention, http.StatusConflict, "evidence_conflict")
	pastRetention := telemetryRequest
	pastRetention.EvidenceID, pastRetention.RetentionExpiresAt = "evidence:past", b.clock.Now().Add(-time.Hour)
	refused(pastRetention, http.StatusBadRequest, "invalid_request")
	badKind := telemetryRequest
	badKind.EvidenceID, badKind.Kind = "evidence:bad-kind", "shell"
	refused(badKind, http.StatusBadRequest, "invalid_request")
	if count() != before {
		t.Fatalf("refused requests stored %d rows", count()-before)
	}

	// An object over the size limit is refused before anything is stored.
	small, err := NewPostgresRepository(ctx, b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	small.auditEvidenceMaxBytes = 64
	oversized := telemetryRequest
	oversized.EvidenceID = "evidence:oversized"
	if _, _, err := small.StoreAuditEvidence(ctx, oversized, contracts.ModelActorV1{Issuer: "https://id.example.test", Subject: "admin:audit"}); !errors.Is(err, contracts.AuditEvidenceRejectionTooLarge) {
		t.Fatalf("oversized write: %v", err)
	}
	if status, _ := auditEvidenceStatus(contracts.AuditEvidenceRejectionTooLarge); status != http.StatusRequestEntityTooLarge || count() != before {
		t.Fatalf("oversized write stored data or has status %d", status)
	}

	// The database refuses edits and deletes, and refuses a digest that does not match.
	for _, statement := range []string{`UPDATE audit_evidence SET retention_expires_at = retention_expires_at + interval '1 day'`, `DELETE FROM audit_evidence`} {
		if _, err := b.db.Exec(statement); err == nil {
			t.Fatalf("%s was allowed", statement)
		}
	}
	if _, err := b.db.Exec(`INSERT INTO audit_evidence (deployment_id, evidence_id, kind, schema_version, device_id, source_ref, content, sha256, stored_at, retention_expires_at, actor_issuer, actor_subject)
		VALUES ($1,'evidence:forged','telemetry','x',$2,'telemetry:77','\x7b7d',decode(repeat('00',32),'hex'),now(),now()+interval '1 day','i','s')`, b.repo.deploymentID, telemetryDevice); err == nil {
		t.Fatal("a digest that does not match the content was accepted")
	}

	// Bytes changed at rest are never served. The test database is isolated, so
	// the guards are removed here only to simulate corruption below the controller.
	var constraint string
	if err := b.db.QueryRow(`SELECT conname FROM pg_constraint WHERE conrelid='audit_evidence'::regclass AND pg_get_constraintdef(oid) LIKE '%sha256(content)%'`).Scan(&constraint); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{`ALTER TABLE audit_evidence DROP CONSTRAINT "` + constraint + `"`, `ALTER TABLE audit_evidence DISABLE TRIGGER audit_evidence_immutable`,
		`UPDATE audit_evidence SET content = '\x7b7d' WHERE evidence_id = 'evidence:prediction:1'`} {
		if _, err := b.db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	w := content(again, "evidence:prediction:1", "", admin, http.StatusInternalServerError)
	if strings.TrimSpace(w.Body.String()) != "evidence_unavailable" || bytes.Contains(w.Body.Bytes(), []byte("{}")) {
		t.Fatalf("corrupt evidence response %q", w.Body.String())
	}
	call(again, http.MethodGet, "/console/api/audit-evidence/evidence:prediction:1", nil, viewer, "", http.StatusInternalServerError)

	// After retention the bytes are no longer served, but the metadata remains.
	b.clock.Advance(31 * 24 * time.Hour)
	admin, _ = b.addSession(t, "admin:audit2", auth.RoleAdmin, 0)
	w = content(again, "evidence:telemetry:1", "", admin, http.StatusGone)
	if strings.TrimSpace(w.Body.String()) != "evidence_expired" || bytes.Contains(w.Body.Bytes(), []byte(telemetryDevice)) {
		t.Fatalf("expired body %q", w.Body.String())
	}
	call(again, http.MethodGet, "/console/api/audit-evidence/evidence:telemetry:1", nil, admin, "", http.StatusOK)
}

func ptr[T any](v T) *T { return &v }
