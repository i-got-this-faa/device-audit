package controller

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// SEC09 #90: revocation authority, its audit record and its ordering against
// ingestion, at the console and mesh HTTP boundaries with real PostgreSQL.

func revocationRequest(device, reason string) contracts.DeviceRevocationRequestV1 {
	return contracts.DeviceRevocationRequestV1{SchemaVersion: contracts.DeviceRevocationRequestV1Version, DeviceID: device, ReasonReference: reason}
}

func revocationEvents(t *testing.T, db *sql.DB, device string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM device_revocation_events WHERE device_id=$1`, device).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func requireAdmitted(t *testing.T, repo *PostgresRepository, d meshTestDevice, want bool) {
	t.Helper()
	_, err := repo.NetworkPeerBinding(context.Background(), d.peer)
	if (err == nil) != want {
		t.Fatalf("tunnel admission for %s=%v, want %v", d.id, err == nil, want)
	}
}

// pausingClock blocks its first caller, which holds the device row lock when it
// reads the clock, until the test releases it.
type pausingClock struct {
	once     sync.Once
	locked   chan struct{}
	released chan struct{}
	now      func() time.Time
}

func newPausingClock(now func() time.Time) *pausingClock {
	return &pausingClock{locked: make(chan struct{}), released: make(chan struct{}), now: now}
}

func (c *pausingClock) Now() time.Time {
	c.once.Do(func() {
		close(c.locked)
		<-c.released
	})
	return c.now()
}

func waitForLockedQuery(t *testing.T, db *sql.DB, prefix string) {
	t.Helper()
	waitRepositoryCondition(t, func(ctx context.Context) (bool, error) {
		var waiting bool
		err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
			WHERE datname=current_database() AND query LIKE $1 AND wait_event_type='Lock')`, prefix+"%").Scan(&waiting)
		return waiting, err
	})
}

func TestRevocationHTTPAuthorizationAndAuditRecord(t *testing.T) {
	b := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, b, "device:revoke-http")
	service, err := NewRevocationService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, Revocation: service}).Handler()
	viewer, viewerCSRF := b.addSession(t, "viewer:test", auth.RoleViewer, 0)
	oldAdmin, oldCSRF := b.addSession(t, "admin:old", auth.RoleAdmin, 6*time.Minute)
	encoded, _ := json.Marshal(revocationRequest(device.id, "incident:42"))
	path := "/console/api/devices/" + device.id + "/revocation"
	const origin = "https://console.example.test"
	call := func(target, body, session, csrf, origin string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
		r.Header.Set("Accept", "application/json")
		r.Header.Set("Content-Type", "application/json")
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("POST %s: %d want %d: %s", target, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}

	// Unauthorized callers are denied before the repository is reached.
	call(path, string(encoded), "", "", "", http.StatusUnauthorized)
	call(path, string(encoded), viewer, viewerCSRF, origin, http.StatusForbidden)
	call(path, string(encoded), oldAdmin, oldCSRF, origin, http.StatusForbidden)
	call(path, string(encoded), b.session, "wrong", origin, http.StatusForbidden)
	call(path, string(encoded), b.session, b.csrf, "https://attacker.example", http.StatusForbidden)
	for _, bad := range []struct{ target, body string }{
		{strings.Replace(path, device.id, "device:other", 1), string(encoded)},
		{path + "?force=true", string(encoded)},
		{path, string(encoded) + "{}"},
		{path, strings.Replace(string(encoded), `"reason_reference":`, `"actor_subject":"admin:forged","reason_reference":`, 1)},
		{path, strings.Replace(string(encoded), "incident:42", "stolen laptop", 1)},
		{path, strings.Repeat(" ", 16<<10) + string(encoded)},
	} {
		call(bad.target, bad.body, b.session, b.csrf, origin, http.StatusBadRequest)
	}
	unknown, _ := json.Marshal(revocationRequest("device:unknown", "incident:42"))
	call("/console/api/devices/device:unknown/revocation", string(unknown), b.session, b.csrf, origin, http.StatusNotFound)
	if revocationEvents(t, b.db, device.id) != 0 {
		t.Fatal("denied request left a revocation record")
	}
	requireAdmitted(t, b.repo, device, true)

	var record contracts.DeviceRevocationV1
	if err := json.Unmarshal(call(path, string(encoded), b.session, b.csrf, origin, http.StatusCreated), &record); err != nil {
		t.Fatal(err)
	}
	enrolled, err := b.repo.Device(context.Background(), device.id)
	if err != nil {
		t.Fatal(err)
	}
	if err := record.Validate(); err != nil || record.ActorSubject != "admin:test" || record.ActorIssuer != "https://id.example.test" ||
		record.ReasonReference != "incident:42" || record.EnrollmentSHA256 != enrolled.RequestSHA256 ||
		!record.RevokedAt.Equal(b.clock.Now()) || enrolled.RevokedAt == nil || !enrolled.RevokedAt.Equal(record.RevokedAt) {
		t.Fatalf("revocation provenance: %+v device=%+v err=%v", record, enrolled, err)
	}
	requireAdmitted(t, b.repo, device, false)

	// A repeat returns the original record and writes no second event.
	b.clock.Advance(time.Minute)
	again, _ := json.Marshal(revocationRequest(device.id, "incident:43"))
	var repeated contracts.DeviceRevocationV1
	if err := json.Unmarshal(call(path, string(again), b.session, b.csrf, origin, http.StatusOK), &repeated); err != nil {
		t.Fatal(err)
	}
	if repeated != record || revocationEvents(t, b.db, device.id) != 1 {
		t.Fatalf("repeat changed the record: %+v want %+v", repeated, record)
	}
}

func TestRevocationRejectsFreshAndEstablishedPeersAcrossRestart(t *testing.T) {
	b := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, b, "device:revoke-restart")
	node := &meshTestNode{}
	server := newMeshTestServer(t, MeshConfig{Node: node, Repository: b.repo, Now: b.clock.Now})
	status, ack := serveMeshEvidence(t, server, device.peer, meshReplayEvidence(t, b, device, 2))
	requireAcceptedAcknowledgement(t, status, ack, 2)

	record, created, err := b.repo.RevokeDevice(context.Background(), revocationRequest(device.id, "incident:restart"), "https://id.example.test", "admin:test")
	if err != nil || !created {
		t.Fatalf("revoke: created=%v err=%v", created, err)
	}
	requireRevoked := func(repo *PostgresRepository, server *http.Server, node *meshTestNode, sequence uint64) {
		t.Helper()
		// A fresh tunnel is refused by the same lookup the Tailcat AllowClient uses.
		requireAdmitted(t, repo, device, false)
		// An established tunnel's next request is rejected and the tunnel dropped.
		status, ack := serveMeshEvidence(t, server, device.peer, meshReplayEvidence(t, b, device, sequence))
		if status != http.StatusForbidden || ack != nil || !node.disconnected {
			t.Fatalf("established peer status=%d ack=%+v disconnected=%v", status, ack, node.disconnected)
		}
		// Ingestion rechecks under its lock even if a caller skipped admission.
		requireRepositoryRejection(t, evidenceErr(repo.AcceptEvidence(context.Background(), meshReplayEvidence(t, b, device, sequence))), contracts.EnvelopeRejectionRevokedKey)
	}
	requireRevoked(b.repo, server, node, 3)

	// Restart: a new pool, repository and handler hold no process state.
	b.db.Close()
	db, err := database.Open(context.Background(), b.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo, err := NewPostgresRepository(context.Background(), db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	b.db, b.repo = db, repo
	restartedNode := &meshTestNode{}
	requireRevoked(repo, newMeshTestServer(t, MeshConfig{Node: restartedNode, Repository: repo, Now: b.clock.Now}), restartedNode, 4)
	requireMeshDeviceState(t, b, device, 2, 2)

	stored, created, err := repo.RevokeDevice(context.Background(), revocationRequest(device.id, "incident:other"), "https://id.example.test", "admin:other")
	if err != nil || created || stored != record || revocationEvents(t, db, device.id) != 1 {
		t.Fatalf("restarted record=%+v created=%v err=%v; want %+v", stored, created, err, record)
	}
}

// A sample that reaches ingestion while a revocation holds the device row waits
// behind it and is then rejected; it is never admitted after the revocation.
func TestRevocationRejectsSampleQueuedBehindIt(t *testing.T) {
	b := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, b, "device:queued-sample")
	server := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: b.repo, Now: b.clock.Now})
	clock := newPausingClock(b.clock.Now)
	revoker, err := NewPostgresRepository(context.Background(), b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	revoked := make(chan error, 1)
	go func() {
		_, _, err := revoker.RevokeDevice(context.Background(), revocationRequest(device.id, "incident:race"), "https://id.example.test", "admin:test")
		revoked <- err
	}()
	<-clock.locked
	// The revocation is uncommitted, so the peer still passes tunnel admission.
	envelope := meshReplayEvidence(t, b, device, 2)
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- recordMeshEvidence(server, device.peer, envelope) }()
	waitForLockedQuery(t, b.db, "SELECT public_key")
	close(clock.released)
	if err := <-revoked; err != nil {
		t.Fatal(err)
	}
	w := <-response
	ack := meshAcknowledgement(t, w, envelope)
	if w.Code != http.StatusConflict || ack == nil || ack.Status != "rejected" || *ack.RejectionReason != contracts.EnvelopeRejectionRevokedKey {
		t.Fatalf("queued sample status=%d ack=%+v, want signed revoked_key", w.Code, ack)
	}
	requireMeshDeviceState(t, b, device, contracts.EnrollmentSequenceV1)
}

// A revocation that arrives while a sample holds the device row waits for it.
// The sample is admitted before revoked_at and nothing is admitted after.
func TestRevocationWaitsForInFlightSample(t *testing.T) {
	b := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, b, "device:in-flight")
	clock := newPausingClock(b.clock.Now)
	ingest, err := NewPostgresRepository(context.Background(), b.db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	server := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: ingest, Now: b.clock.Now})
	envelope := meshReplayEvidence(t, b, device, 2)
	response := make(chan *httptest.ResponseRecorder, 1)
	go func() { response <- recordMeshEvidence(server, device.peer, envelope) }()
	<-clock.locked
	type outcome struct {
		record  contracts.DeviceRevocationV1
		created bool
		err     error
	}
	revoked := make(chan outcome, 1)
	go func() {
		record, created, err := b.repo.RevokeDevice(context.Background(), revocationRequest(device.id, "incident:race"), "https://id.example.test", "admin:test")
		revoked <- outcome{record, created, err}
	}()
	waitForLockedQuery(t, b.db, "SELECT request_sha256")
	close(clock.released)
	w := <-response
	requireAcceptedAcknowledgement(t, w.Code, meshAcknowledgement(t, w, envelope), 2)
	result := <-revoked
	if result.err != nil || !result.created {
		t.Fatalf("revocation behind sample: %+v", result)
	}
	stored, err := b.repo.Evidence(context.Background(), device.id, 2)
	if err != nil || stored.ReceivedAt.After(result.record.RevokedAt) {
		t.Fatalf("sample received %v after revocation %v: %v", stored.ReceivedAt, result.record.RevokedAt, err)
	}
	status, ack := serveMeshEvidence(t, server, device.peer, meshReplayEvidence(t, b, device, 3))
	if status != http.StatusForbidden || ack != nil {
		t.Fatalf("post-revocation sample status=%d ack=%+v", status, ack)
	}
	requireMeshDeviceState(t, b, device, 2, 2)
}

func TestRevocationConcurrentAdministratorsRecordOnce(t *testing.T) {
	b := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, b, "device:concurrent-revoke")
	other, err := database.Open(context.Background(), b.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.Close() })
	second, err := NewPostgresRepository(context.Background(), other, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	const writers = 8
	records := make([]contracts.DeviceRevocationV1, writers)
	created := make([]bool, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		repo := []*PostgresRepository{b.repo, second}[i%2]
		wg.Go(func() {
			<-start
			var err error
			records[i], created[i], err = repo.RevokeDevice(context.Background(), revocationRequest(device.id, "incident:concurrent"), "https://id.example.test", fmt.Sprintf("admin:%d", i))
			if err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	wg.Wait()
	winners := 0
	for i := range writers {
		if created[i] {
			winners++
		}
		if records[i] != records[0] {
			t.Fatalf("writers saw different records: %+v %+v", records[i], records[0])
		}
	}
	if winners != 1 || revocationEvents(t, b.db, device.id) != 1 {
		t.Fatalf("created=%d events=%d, want one revocation", winners, revocationEvents(t, b.db, device.id))
	}
}

func TestRevocationRollbackUnrecordedAndUnavailableStore(t *testing.T) {
	b := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, b, "device:revoke-rollback")
	request := revocationRequest(device.id, "incident:rollback")
	ctx := context.Background()
	for _, invalid := range []struct {
		request         contracts.DeviceRevocationRequestV1
		issuer, subject string
	}{
		{revocationRequest(device.id, "free text"), "https://id.example.test", "admin:test"},
		{request, "https://id.example.test", " "},
		{request, "https://id.example.test", strings.Repeat("a", 256)},
	} {
		if _, _, err := b.repo.RevokeDevice(ctx, invalid.request, invalid.issuer, invalid.subject); !errors.Is(err, ErrRevocationInvalid) {
			t.Fatalf("invalid revocation %+v: %v", invalid, err)
		}
	}
	// A deferred trigger fails at COMMIT, after both writes succeeded.
	if _, err := b.db.Exec(`CREATE FUNCTION reject_revocation_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected commit failure'; END $$;
		CREATE CONSTRAINT TRIGGER reject_revocation_commit AFTER INSERT ON device_revocation_events DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_revocation_commit()`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.RevokeDevice(ctx, request, "https://id.example.test", "admin:test"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("failed commit reported: %v", err)
	}
	requireAdmitted(t, b.repo, device, true)
	if revocationEvents(t, b.db, device.id) != 0 {
		t.Fatal("rolled-back revocation left a record")
	}
	if _, err := b.db.Exec(`DROP TRIGGER reject_revocation_commit ON device_revocation_events`); err != nil {
		t.Fatal(err)
	}
	if _, created, err := b.repo.RevokeDevice(ctx, request, "https://id.example.test", "admin:test"); err != nil || !created {
		t.Fatalf("revoke after rollback: created=%v err=%v", created, err)
	}

	if _, _, err := b.repo.RevokeDevice(ctx, revocationRequest("device:unknown", "incident:x"), "https://id.example.test", "admin:test"); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown device: %v", err)
	}

	// A device revoked by hand has no actor to report; none is invented.
	manual := enrollMeshTestDevice(t, b, "device:manual-revoke")
	if _, err := b.db.Exec(`UPDATE device_enrollments SET revoked_at=now() WHERE device_id=$1`, manual.id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.repo.RevokeDevice(ctx, revocationRequest(manual.id, "incident:manual"), "https://id.example.test", "admin:test"); !errors.Is(err, ErrRevocationUnrecorded) {
		t.Fatalf("unrecorded revocation: %v", err)
	}

	open := enrollMeshTestDevice(t, b, "device:closed-store")
	b.db.Close()
	if _, _, err := b.repo.RevokeDevice(ctx, revocationRequest(open.id, "incident:outage"), "https://id.example.test", "admin:test"); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("closed store: %v", err)
	}
}
