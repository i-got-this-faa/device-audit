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
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func TestDiagnosticAssignmentsSignDispatchCancelStatusAndRestart(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x44}, ed25519.SeedSize))
	diagPub := diagKey.Public().(ed25519.PublicKey)

	devA := enrollMeshTestDevice(t, b, "device:diag-a")
	devB := enrollMeshTestDevice(t, b, "device:diag-b")

	diagSvc, err := NewDiagnosticService(b.repo, b.admin, diagKey)
	if err != nil {
		t.Fatal(err)
	}
	api := NewAPI(Config{MaxDevices: 1, Auth: b.admin, Diagnostics: diagSvc})
	handler := api.Handler()
	meshSrv := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: b.repo, Now: b.clock.Now})

	freshAdmin, adminCSRF := b.addSession(t, "admin:diag", auth.RoleAdmin, 0)
	viewer, _ := b.addSession(t, "viewer:diag", auth.RoleViewer, 0)

	// /healthz reports diagnostics configured.
	hzW := httptest.NewRecorder()
	handler.ServeHTTP(hzW, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	var hz map[string]any
	if json.Unmarshal(hzW.Body.Bytes(), &hz) != nil || hz["diagnostics"] != "configured" {
		t.Fatalf("unexpected healthz: %s", hzW.Body.String())
	}

	callConsole := func(h http.Handler, method, target string, body any, cookie, csrf string, want int) []byte {
		t.Helper()
		var rBody []byte
		if body != nil {
			rBody, _ = json.Marshal(body)
		}
		r := httptest.NewRequest(method, target, bytes.NewReader(rBody))
		if body != nil {
			r.Header.Set("Content-Type", "application/json")
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: cookie})
		}
		if csrf != "" {
			r.Header.Set("Origin", "https://console.example.test")
			r.Header.Set("X-CSRF-Token", csrf)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: status=%d want %d: %s", method, target, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}

	postMesh := func(peer, path string, payload any, want int) []byte {
		t.Helper()
		var raw []byte
		if payload != nil {
			raw, _ = json.Marshal(payload)
		}
		r := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, peer))
		w := httptest.NewRecorder()
		meshSrv.Handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("mesh %s peer=%s: status=%d want %d: %s", path, peer, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}

	comp := "storage:disk-0"
	lookback := uint32(3600)
	maxEntries := uint32(64)
	req1 := workflows.AssignmentRequest{
		AssignmentID:     "assign:1",
		DeviceID:         devA.id,
		ProbeID:          contracts.DiagnosticProbeStorageHealthV1,
		Arguments:        contracts.DiagnosticArgumentsV1{ComponentID: &comp},
		Budget:           contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 4096},
		ExpiresInSeconds: 600,
	}
	req2 := workflows.AssignmentRequest{
		AssignmentID:     "assign:2",
		DeviceID:         devA.id,
		ProbeID:          contracts.DiagnosticProbeSystemErrorsV1,
		Arguments:        contracts.DiagnosticArgumentsV1{LookbackSeconds: &lookback, MaxEntries: &maxEntries},
		Budget:           contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 4096},
		ExpiresInSeconds: 600,
	}
	req3 := workflows.AssignmentRequest{
		AssignmentID:     "assign:pending-cancel",
		DeviceID:         devB.id,
		ProbeID:          contracts.DiagnosticProbeStorageHealthV1,
		Arguments:        contracts.DiagnosticArgumentsV1{ComponentID: &comp},
		Budget:           contracts.DiagnosticBudgetV1{WallSeconds: 15, MaxOutputBytes: 4096},
		ExpiresInSeconds: 300,
	}

	// Authorization & validation rejections.
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", req1, "", "", http.StatusUnauthorized)
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", req1, viewer, adminCSRF, http.StatusForbidden)
	badProbe := req1
	badProbe.AssignmentID = "assign:bad-probe"
	badProbe.ProbeID = "arbitrary_shell.v1"
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", badProbe, freshAdmin, adminCSRF, http.StatusBadRequest)
	unknownDev := req1
	unknownDev.AssignmentID = "assign:unknown-dev"
	unknownDev.DeviceID = "device:missing"
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", unknownDev, freshAdmin, adminCSRF, http.StatusNotFound)

	// Create 2 assignments for devA + 1 for devB, verify signature, monotonic sequence, idempotence & conflict.
	raw1 := callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", req1, freshAdmin, adminCSRF, http.StatusCreated)
	var rec1 workflows.AssignmentRecord
	if err := json.Unmarshal(raw1, &rec1); err != nil {
		t.Fatal(err)
	}
	if rec1.Status != workflows.StatusPending || rec1.AssignmentSequence != 1 || rec1.SignedAssignment.VerifySignature(diagPub) != nil {
		t.Fatalf("unexpected created assignment 1: %+v", rec1)
	}
	// Identical repeat returns 200 without new assignment/sequence; differing body conflicts with 409.
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", req1, freshAdmin, adminCSRF, http.StatusOK)
	conflict1 := req1
	conflict1.Budget.WallSeconds = 60
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", conflict1, freshAdmin, adminCSRF, http.StatusConflict)

	raw2 := callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", req2, freshAdmin, adminCSRF, http.StatusCreated)
	var rec2 workflows.AssignmentRecord
	if json.Unmarshal(raw2, &rec2) != nil || rec2.AssignmentSequence != 2 {
		t.Fatalf("expected sequence 2 for second devA assignment, got %+v", rec2)
	}
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments", req3, freshAdmin, adminCSRF, http.StatusCreated)

	// Cancel pending assignment BEFORE dispatch -> immediately terminal cancelled; devB poll never sees it.
	raw3Cancel := callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments/"+req3.AssignmentID+"/cancel", map[string]any{}, freshAdmin, adminCSRF, http.StatusOK)
	var rec3 workflows.AssignmentRecord
	if json.Unmarshal(raw3Cancel, &rec3) != nil || rec3.Status != workflows.StatusCancelled || !rec3.CancelRequested {
		t.Fatalf("pending cancel failed: %+v", rec3)
	}
	var pollB workflows.PollResponse
	if json.Unmarshal(postMesh(devB.peer, "/v1/diagnostics/poll", nil, http.StatusOK), &pollB) != nil || len(pollB.Assignments) != 0 {
		t.Fatalf("cancelled assignment dispatched to devB: %+v", pollB)
	}

	// DevA polls once -> leases assign:1; second duplicate poll must NOT re-lease assign:1 (assign:2 leased next).
	var pollA1 workflows.PollResponse
	if json.Unmarshal(postMesh(devA.peer, "/v1/diagnostics/poll", nil, http.StatusOK), &pollA1) != nil ||
		len(pollA1.Assignments) != 1 || pollA1.Assignments[0].AssignmentID != req1.AssignmentID {
		t.Fatalf("first poll devA unexpected: %+v", pollA1)
	}
	var pollA2 workflows.PollResponse
	if json.Unmarshal(postMesh(devA.peer, "/v1/diagnostics/poll", nil, http.StatusOK), &pollA2) != nil ||
		len(pollA2.Assignments) != 1 || pollA2.Assignments[0].AssignmentID != req2.AssignmentID {
		t.Fatalf("second poll devA unexpected: %+v", pollA2)
	}
	// Third poll receives zero new assignments and zero cancellations so far.
	var pollA3 workflows.PollResponse
	if json.Unmarshal(postMesh(devA.peer, "/v1/diagnostics/poll", nil, http.StatusOK), &pollA3) != nil ||
		len(pollA3.Assignments) != 0 || len(pollA3.CancelAssignmentIDs) != 0 {
		t.Fatalf("duplicate third poll should return empty: %+v", pollA3)
	}

	// Cancel leased assign:2 -> enters persistent cancel_requested; device poll sees cancel_assignment_ids.
	callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments/"+req2.AssignmentID+"/cancel", nil, freshAdmin, adminCSRF, http.StatusOK)
	var pollCancel workflows.PollResponse
	if json.Unmarshal(postMesh(devA.peer, "/v1/diagnostics/poll", nil, http.StatusOK), &pollCancel) != nil ||
		len(pollCancel.CancelAssignmentIDs) != 1 || pollCancel.CancelAssignmentIDs[0] != req2.AssignmentID {
		t.Fatalf("poll did not report cancel_requested for assign:2: %+v", pollCancel)
	}

	// Device A executes assign:1 cleanly and submits signed DiagnosticResultV1 (seq 2).
	runner := workflows.NewProbeRunner(func(_ context.Context, _ workflows.Request) ([]byte, error) {
		return []byte(`{"schema_version":"device-audit.probe-evidence.v1","health":"ok"}`), nil
	})
	res1, err := workflows.ExecuteAssignedToResult(ctx, runner, pollA1.Assignments[0], diagPub, devA.signing,
		b.repo.deploymentID, devA.id, "boot:diag:1", "ref:storage:1", 2, b.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	var receipt1 workflows.ResultReceipt
	if json.Unmarshal(postMesh(devA.peer, "/v1/diagnostics/results", res1, http.StatusCreated), &receipt1) != nil ||
		receipt1.Status != "accepted" || receipt1.State != "succeeded" || !receipt1.Created {
		t.Fatalf("submit result 1 unexpected: %+v", receipt1)
	}

	// Duplicate exact result submission returns 200 OK with created=false without a second terminal transition.
	var dupReceipt workflows.ResultReceipt
	if json.Unmarshal(postMesh(devA.peer, "/v1/diagnostics/results", res1, http.StatusOK), &dupReceipt) != nil || dupReceipt.Created {
		t.Fatalf("duplicate result created a new receipt: %+v", dupReceipt)
	}
	// Differing signed result for already-terminal assign:1 is 409 Conflict!
	res1Conflict, err := workflows.ExecuteAssignedToResult(ctx, runner, pollA1.Assignments[0], diagPub, devA.signing,
		b.repo.deploymentID, devA.id, "boot:diag:1", "ref:storage:other", 3, b.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	postMesh(devA.peer, "/v1/diagnostics/results", res1Conflict, http.StatusConflict)

	// Cancelling already-succeeded assign:1 leaves committed succeeded unchanged!
	rawCancelAfterSuccess := callConsole(handler, http.MethodPost, "/console/api/diagnostics/assignments/"+req1.AssignmentID+"/cancel", nil, freshAdmin, adminCSRF, http.StatusOK)
	var afterCancelSuccess workflows.AssignmentRecord
	if json.Unmarshal(rawCancelAfterSuccess, &afterCancelSuccess) != nil || afterCancelSuccess.Status != workflows.StatusSucceeded || len(afterCancelSuccess.Events) != 3 {
		t.Fatalf("cancel after success mutated terminal state: %+v", afterCancelSuccess)
	}

	// Reusing sequence 2 on telemetry fails as replay because diagnostic result consumed sequence 2!
	telBytes := meshTestTelemetry(t, devA.id, b.clock.Now())
	telSum := sha256.Sum256(telBytes)
	telReplay := contracts.EvidenceEnvelopeV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: b.repo.deploymentID, DeviceID: devA.id,
			SigningKeyID: devA.keyID, Sequence: 2, IssuedAt: b.clock.Now().Format(time.RFC3339), ExpiresAt: b.clock.Now().Add(time.Hour).Format(time.RFC3339),
		},
		PayloadSchemaVersion: contracts.TelemetryV2Version,
		PayloadBase64:        base64.StdEncoding.EncodeToString(telBytes),
		PayloadSHA256:        hex.EncodeToString(telSum[:]),
	}
	telSign, _ := telReplay.SigningBytes()
	telReplay.Signature = hex.EncodeToString(ed25519.Sign(devA.signing, telSign))
	if _, err := b.repo.AcceptEvidence(ctx, telReplay); err == nil {
		t.Fatal("telemetry reusing diagnostic sequence 2 was accepted")
	}

	// Controller restart preserves cancel_requested, signed assignment, terminal result, and paginated device list.
	db2, err := database.Open(ctx, b.url)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	repo2, err := NewPostgresRepository(ctx, db2, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	diagSvc2, err := NewDiagnosticService(repo2, b.admin, diagKey)
	if err != nil {
		t.Fatal(err)
	}
	handler2 := NewAPI(Config{MaxDevices: 1, Auth: b.admin, Diagnostics: diagSvc2}).Handler()

	// Wrong deployment scope rejected with 403/400.
	callConsole(handler2, http.MethodGet, "/console/api/diagnostics/assignments/"+req1.AssignmentID+"?deployment_id=deployment:other", nil, viewer, "", http.StatusForbidden)
	callConsole(handler2, http.MethodGet, "/console/api/diagnostics/assignments/"+req1.AssignmentID, nil, viewer, "", http.StatusBadRequest)

	rawGot2 := callConsole(handler2, http.MethodGet, "/console/api/diagnostics/assignments/"+req2.AssignmentID+"?deployment_id="+b.repo.deploymentID, nil, viewer, "", http.StatusOK)
	var got2 workflows.AssignmentRecord
	if json.Unmarshal(rawGot2, &got2) != nil || got2.Status != workflows.StatusCancelRequested || !got2.CancelRequested {
		t.Fatalf("cancel_requested lost across restart: %+v", got2)
	}

	// Paginate devA assignments across restart (limit=1 -> 2 pages).
	rawPage1 := callConsole(handler2, http.MethodGet, "/console/api/devices/"+devA.id+"/diagnostics/assignments?deployment_id="+b.repo.deploymentID+"&limit=1", nil, viewer, "", http.StatusOK)
	var page1 workflows.AssignmentListPage
	if json.Unmarshal(rawPage1, &page1) != nil || len(page1.Assignments) != 1 || page1.NextAfter == nil || page1.Assignments[0].AssignmentID != req1.AssignmentID {
		t.Fatalf("page 1 unexpected: %+v", page1)
	}
	rawPage2 := callConsole(handler2, http.MethodGet, "/console/api/devices/"+devA.id+"/diagnostics/assignments?deployment_id="+b.repo.deploymentID+"&limit=1&after="+*page1.NextAfter, nil, viewer, "", http.StatusOK)
	var page2 workflows.AssignmentListPage
	if json.Unmarshal(rawPage2, &page2) != nil || len(page2.Assignments) != 1 || page2.NextAfter != nil || page2.Assignments[0].AssignmentID != req2.AssignmentID {
		t.Fatalf("page 2 unexpected: %+v", page2)
	}
}

func TestDiagnosticAssignmentsExpiredLeasesRevocationAndDatabaseGuards(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, ed25519.SeedSize))
	diagPub := diagKey.Public().(ed25519.PublicKey)

	devLease := enrollMeshTestDevice(t, b, "device:diag-lease")
	devRev := enrollMeshTestDevice(t, b, "device:diag-rev")
	actor := workflows.Actor{Issuer: "https://id.example.test", Subject: "admin:diag"}
	comp := "storage:disk-0"

	// 1. Expired lease transitions once to expired; subsequent poll, cancel, or late result creates no second transition.
	leaseReq := workflows.AssignmentRequest{
		AssignmentID: "assign:lease-exp", DeviceID: devLease.id, ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &comp},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 4096}, ExpiresInSeconds: 600,
	}
	createdRec, created, err := b.repo.CreateDiagnosticAssignment(ctx, leaseReq, diagKey, actor)
	if err != nil || !created {
		t.Fatalf("create lease assignment failed: created=%v err=%v", created, err)
	}
	poll, err := b.repo.PollDiagnosticAssignments(ctx, devLease.id, 30*time.Second)
	if err != nil || len(poll.Assignments) != 1 {
		t.Fatalf("poll failed: %+v err=%v", poll, err)
	}
	// Advance past 30s lease -> DiagnosticAssignment sweeps it cleanly to terminal expired ONCE.
	b.clock.Advance(31 * time.Second)
	expRec, err := b.repo.DiagnosticAssignment(ctx, leaseReq.AssignmentID)
	if err != nil || expRec.Status != workflows.StatusExpired || len(expRec.Events) != 3 {
		t.Fatalf("expired lease not finalized: %+v err=%v", expRec, err)
	}
	// Poll again and try Cancel after expiry -> no re-dispatch, still 3 events.
	pollAfter, err := b.repo.PollDiagnosticAssignments(ctx, devLease.id, 30*time.Second)
	if err != nil || len(pollAfter.Assignments) != 0 {
		t.Fatalf("expired assignment re-dispatched: %+v err=%v", pollAfter, err)
	}
	cancelAfterExp, err := b.repo.CancelDiagnosticAssignment(ctx, leaseReq.AssignmentID, actor)
	if err != nil || cancelAfterExp.Status != workflows.StatusExpired || len(cancelAfterExp.Events) != 3 {
		t.Fatalf("cancel after lease expiry created extra transition: %+v err=%v", cancelAfterExp, err)
	}
	// Late result after expired lease fails closed as terminal conflict.
	runner := workflows.NewProbeRunner(func(_ context.Context, _ workflows.Request) ([]byte, error) {
		return []byte(`{"ok":true}`), nil
	})
	lateResult, err := workflows.ExecuteAssignedToResult(ctx, runner, createdRec.SignedAssignment, diagPub, devLease.signing,
		b.repo.deploymentID, devLease.id, "boot:late", "ref:late:1", 2, func() time.Time { return createdRec.IssuedAt })
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.SubmitDiagnosticResult(ctx, lateResult); !errors.Is(err, workflows.ErrAssignmentTerminal) {
		t.Fatalf("expected ErrAssignmentTerminal after lease expiry, got %v", err)
	}

	// 2. Pending assignment whose target device gets revoked -> poll refuses dispatch; Create after revocation refused.
	revReq := workflows.AssignmentRequest{
		AssignmentID: "assign:rev-pending", DeviceID: devRev.id, ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &comp},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 15, MaxOutputBytes: 4096}, ExpiresInSeconds: 600,
	}
	if _, _, err := b.repo.CreateDiagnosticAssignment(ctx, revReq, diagKey, actor); err != nil {
		t.Fatal(err)
	}
	// Lease a second assignment on devRev BEFORE revocation, then revoke devRev -> SubmitDiagnosticResult refuses!
	revLeasedReq := revReq
	revLeasedReq.AssignmentID = "assign:rev-leased"
	revLeased, _, err := b.repo.CreateDiagnosticAssignment(ctx, revLeasedReq, diagKey, actor)
	if err != nil {
		t.Fatal(err)
	}
	if pollRev, err := b.repo.PollDiagnosticAssignments(ctx, devRev.id, time.Minute); err != nil || len(pollRev.Assignments) != 1 {
		t.Fatalf("pre-revoke poll failed: %+v err=%v", pollRev, err)
	}
	if _, _, err := b.repo.RevokeDevice(ctx, contracts.DeviceRevocationRequestV1{
		SchemaVersion: contracts.DeviceRevocationRequestV1Version, DeviceID: devRev.id, ReasonReference: "incident:revoked",
	}, "https://id.example.test", "admin:diag"); err != nil {
		t.Fatal(err)
	}
	// Dispatch to revoked device fails; new assignment on revoked device fails.
	if _, err := b.repo.PollDiagnosticAssignments(ctx, devRev.id, time.Minute); !errors.Is(err, workflows.ErrAssignmentDeviceRevoked) {
		t.Fatalf("expected ErrAssignmentDeviceRevoked on poll, got %v", err)
	}
	revNew := revReq
	revNew.AssignmentID = "assign:after-revoke"
	if _, _, err := b.repo.CreateDiagnosticAssignment(ctx, revNew, diagKey, actor); !errors.Is(err, workflows.ErrAssignmentDeviceRevoked) {
		t.Fatalf("expected ErrAssignmentDeviceRevoked on create, got %v", err)
	}
	revRes, err := workflows.ExecuteAssignedToResult(ctx, runner, revLeased.SignedAssignment, diagPub, devRev.signing,
		b.repo.deploymentID, devRev.id, "boot:rev", "ref:rev:1", 2, b.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.SubmitDiagnosticResult(ctx, revRes); !errors.Is(err, workflows.ErrAssignmentDeviceRevoked) {
		t.Fatalf("expected ErrAssignmentDeviceRevoked on result submit, got %v", err)
	}

	// 3. Direct SQL triggers block invalid transitions, result spoofing, and deletions/mutations.
	for name, stmt := range map[string]string{
		"delete assignment":        `DELETE FROM diagnostic_assignments`,
		"reopen expired in SQL":    fmt.Sprintf(`UPDATE diagnostic_assignments SET status='pending', terminal_at=NULL, terminal_reason=NULL WHERE assignment_id='%s'`, leaseReq.AssignmentID),
		"mutate probe in SQL":      fmt.Sprintf(`UPDATE diagnostic_assignments SET probe_id='system_errors.v1' WHERE assignment_id='%s'`, revReq.AssignmentID),
		"dispatch revoked in SQL":  fmt.Sprintf(`UPDATE diagnostic_assignments SET status='leased', delivery_count=1, first_dispatched_at=now(), last_dispatched_at=now(), lease_expires_at=expires_at WHERE assignment_id='%s'`, revReq.AssignmentID),
		"delete assignment events": `DELETE FROM diagnostic_assignment_events`,
		"insert bad result":        fmt.Sprintf(`INSERT INTO diagnostic_results SELECT deployment_id, assignment_id, device_id, controller_key_id, 2, assignment_sha256, assignment_sha256, 'boot:x', NULL, issued_at, issued_at, expires_at, 'cancelled', 'cancel_requested', '[]'::jsonb, '{}'::jsonb, issued_at FROM diagnostic_assignments WHERE assignment_id='%s'`, leaseReq.AssignmentID),
	} {
		if _, err := b.db.Exec(stmt); err == nil {
			t.Fatalf("database allowed %s", name)
		}
	}
	if expRec.Result != nil {
		t.Fatalf("unexpected result on expired lease: %+v", expRec.Result)
	}
}

func TestDiagnosticAssignmentsConcurrentPollAndResult(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	diagKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x66}, ed25519.SeedSize))
	diagPub := diagKey.Public().(ed25519.PublicKey)

	dev := enrollMeshTestDevice(t, b, "device:diag-conc")
	actor := workflows.Actor{Issuer: "https://id.example.test", Subject: "admin:conc"}
	comp := "storage:disk-0"
	req := workflows.AssignmentRequest{
		AssignmentID: "assign:conc:1", DeviceID: dev.id, ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &comp},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 20, MaxOutputBytes: 4096}, ExpiresInSeconds: 600,
	}
	created, _, err := b.repo.CreateDiagnosticAssignment(ctx, req, diagKey, actor)
	if err != nil {
		t.Fatal(err)
	}

	const workers = 8
	var leased atomic.Int32
	var pollErrs atomic.Int32
	var wg sync.WaitGroup
	startPoll := make(chan struct{})
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startPoll
			resp, err := b.repo.PollDiagnosticAssignments(ctx, dev.id, time.Minute)
			if err != nil {
				pollErrs.Add(1)
				return
			}
			leased.Add(int32(len(resp.Assignments)))
		}()
	}
	close(startPoll)
	wg.Wait()
	if pollErrs.Load() != 0 || leased.Load() != 1 {
		t.Fatalf("concurrent poll leased=%d errs=%d want 1/0", leased.Load(), pollErrs.Load())
	}

	// 8 concurrent identical submissions -> 1 created, 7 idempotent repeats, 0 errors.
	runner := workflows.NewProbeRunner(func(_ context.Context, _ workflows.Request) ([]byte, error) {
		return []byte(`{"health":"ok"}`), nil
	})
	res, err := workflows.ExecuteAssignedToResult(ctx, runner, created.SignedAssignment, diagPub, dev.signing,
		b.repo.deploymentID, dev.id, "boot:conc", "ref:conc:1", 2, b.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	var resCreated atomic.Int32
	var resErrs atomic.Int32
	var wg2 sync.WaitGroup
	startRes := make(chan struct{})
	for range workers {
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			<-startRes
			_, c, err := b.repo.SubmitDiagnosticResult(ctx, res)
			if err != nil {
				resErrs.Add(1)
				return
			}
			if c {
				resCreated.Add(1)
			}
		}()
	}
	close(startRes)
	wg2.Wait()
	if resErrs.Load() != 0 || resCreated.Load() != 1 {
		t.Fatalf("concurrent identical results created=%d errs=%d want 1/0", resCreated.Load(), resErrs.Load())
	}

	// Second assignment: 8 concurrent conflicting results -> 1 winner, 7 ErrAssignmentConflict.
	req2 := req
	req2.AssignmentID = "assign:conc:2"
	created2, _, err := b.repo.CreateDiagnosticAssignment(ctx, req2, diagKey, actor)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := b.repo.PollDiagnosticAssignments(ctx, dev.id, time.Minute); err != nil || len(p.Assignments) != 1 {
		t.Fatalf("poll 2 failed: %v", err)
	}
	var win atomic.Int32
	var conflicts atomic.Int32
	var otherErrs atomic.Int32
	var wg3 sync.WaitGroup
	startConflict := make(chan struct{})
	for i := range workers {
		rConf, err := workflows.ExecuteAssignedToResult(ctx, runner, created2.SignedAssignment, diagPub, dev.signing,
			b.repo.deploymentID, dev.id, fmt.Sprintf("boot:%d", i), fmt.Sprintf("ref:%d", i), uint64(3+i), b.clock.Now)
		if err != nil {
			t.Fatal(err)
		}
		wg3.Add(1)
		go func(r contracts.DiagnosticResultV1) {
			defer wg3.Done()
			<-startConflict
			_, c, err := b.repo.SubmitDiagnosticResult(ctx, r)
			switch {
			case err == nil && c:
				win.Add(1)
			case errors.Is(err, workflows.ErrAssignmentConflict):
				conflicts.Add(1)
			default:
				otherErrs.Add(1)
			}
		}(rConf)
	}
	close(startConflict)
	wg3.Wait()
	if win.Load() != 1 || conflicts.Load() != workers-1 || otherErrs.Load() != 0 {
		t.Fatalf("concurrent conflicting results win=%d conflicts=%d other=%d", win.Load(), conflicts.Load(), otherErrs.Load())
	}
}
