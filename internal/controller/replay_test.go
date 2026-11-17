package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// SEC08 #89: replay rejection and acknowledgements at the mesh HTTP boundary,
// backed by real PostgreSQL. The repository tests cover the same rules below HTTP.

func meshReplayEvidence(t *testing.T, bed *enrollmentTestBed, d meshTestDevice, sequence uint64) contracts.EvidenceEnvelopeV1 {
	t.Helper()
	issued := bed.clock.Now()
	e := contracts.EvidenceEnvelopeV1{EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: bed.repo.deploymentID, DeviceID: d.id, SigningKeyID: d.keyID, Sequence: sequence, IssuedAt: issued.Format(time.RFC3339), ExpiresAt: issued.Add(time.Hour).Format(time.RFC3339)}, PayloadSchemaVersion: contracts.TelemetryV2Version}
	setMeshTestPayload(&e, meshTestTelemetry(t, d.id, issued))
	signMeshTestEvidence(t, &e, d.signing)
	return e
}

func requireMeshDeviceState(t *testing.T, bed *enrollmentTestBed, d meshTestDevice, mark uint64, sequences ...uint64) {
	t.Helper()
	var got uint64
	if err := bed.db.QueryRow(`SELECT last_sequence FROM device_enrollments WHERE device_id=$1`, d.id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	rows, err := bed.db.Query(`SELECT sequence FROM device_evidence WHERE device_id=$1 ORDER BY sequence`, d.id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var stored []uint64
	for rows.Next() {
		var sequence uint64
		if err := rows.Scan(&sequence); err != nil {
			t.Fatal(err)
		}
		stored = append(stored, sequence)
	}
	if got != mark || len(stored) != len(sequences) {
		t.Fatalf("durable state: mark=%d samples=%v; want mark=%d samples=%v", got, stored, mark, sequences)
	}
	for i := range stored {
		if stored[i] != sequences[i] {
			t.Fatalf("durable samples=%v want %v", stored, sequences)
		}
	}
}

func requireReplayAcknowledgement(t *testing.T, status int, ack *contracts.AcknowledgementV1, mark uint64) {
	t.Helper()
	if status != http.StatusConflict || ack == nil || ack.Status != "rejected" || *ack.RejectionReason != contracts.EnvelopeRejectionReplay || ack.LastSequence == nil || *ack.LastSequence != mark {
		t.Fatalf("replay status=%d acknowledgement=%+v, want signed replay at mark %d", status, ack, mark)
	}
	if err := ack.Validate(); err != nil {
		t.Fatalf("replay acknowledgement violates CT04: %v", err)
	}
}

func requireAcceptedAcknowledgement(t *testing.T, status int, ack *contracts.AcknowledgementV1, sequence uint64) {
	t.Helper()
	if status != http.StatusOK || ack == nil || ack.Status != "accepted" || *ack.LastSequence != sequence {
		t.Fatalf("status=%d acknowledgement=%+v, want accepted sequence %d", status, ack, sequence)
	}
}

func TestMeshConcurrentDuplicatesAcceptOnce(t *testing.T) {
	bed := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, bed, "device:concurrent")
	server := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: bed.repo, Now: bed.clock.Now})
	envelope := meshReplayEvidence(t, bed, device, 7)

	const copies = 16
	responses := make([]*httptest.ResponseRecorder, copies)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range copies {
		wg.Go(func() {
			<-start
			responses[i] = recordMeshEvidence(server, device.peer, envelope)
		})
	}
	close(start)
	wg.Wait()

	var accepted []*contracts.AcknowledgementV1
	for _, w := range responses {
		ack := meshAcknowledgement(t, w, envelope)
		if ack != nil && ack.Status == "accepted" {
			requireAcceptedAcknowledgement(t, w.Code, ack, envelope.Sequence)
			accepted = append(accepted, ack)
			continue
		}
		// Every duplicate learns the committed mark, never a second acceptance.
		requireReplayAcknowledgement(t, w.Code, ack, envelope.Sequence)
	}
	if len(accepted) != 1 {
		t.Fatalf("accepted %d concurrent copies, want 1", len(accepted))
	}
	requireMeshDeviceState(t, bed, device, envelope.Sequence, envelope.Sequence)
	// The accepted receipt names the committed row's receive time.
	stored, err := bed.repo.Evidence(context.Background(), device.id, envelope.Sequence)
	if err != nil || stored.ReceivedAt.UTC().Format(time.RFC3339) != accepted[0].ReceivedAt {
		t.Fatalf("stored receipt=%v acknowledged=%s err=%v", stored.ReceivedAt, accepted[0].ReceivedAt, err)
	}
}

func TestMeshSequencePolicySurvivesControllerRestart(t *testing.T) {
	bed := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, bed, "device:restart")
	server := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: bed.repo, Now: bed.clock.Now})
	send := func(s *http.Server, sequence uint64) (int, *contracts.AcknowledgementV1) {
		return serveMeshEvidence(t, s, device.peer, meshReplayEvidence(t, bed, device, sequence))
	}

	status, ack := send(server, 5)
	requireAcceptedAcknowledgement(t, status, ack, 5)
	status, ack = send(server, 3) // Out of order: gaps below the mark are consumed.
	requireReplayAcknowledgement(t, status, ack, 5)

	// Restart: a new connection pool, repository and handler hold no process
	// state from the first controller. Only PostgreSQL carries the mark.
	bed.db.Close()
	db, err := database.Open(context.Background(), bed.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo, err := NewPostgresRepository(context.Background(), db, RepositoryConfig{DeploymentID: bed.repo.deploymentID, Now: bed.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	bed.db, bed.repo = db, repo
	restarted := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: repo, Now: bed.clock.Now})

	for _, sequence := range []uint64{5, 4, 2} {
		status, ack = send(restarted, sequence)
		requireReplayAcknowledgement(t, status, ack, 5)
	}
	status, ack = send(restarted, 7)
	requireAcceptedAcknowledgement(t, status, ack, 7)
	status, ack = send(restarted, 6)
	requireReplayAcknowledgement(t, status, ack, 7)
	requireMeshDeviceState(t, bed, device, 7, 5, 7)
}

func TestMeshInjectedCommitFailureIsNeverAcknowledged(t *testing.T) {
	bed := newEnrollmentTestBed(t)
	device := enrollMeshTestDevice(t, bed, "device:commit-failure")
	server := newMeshTestServer(t, MeshConfig{Node: &meshTestNode{}, Repository: bed.repo, Now: bed.clock.Now})
	envelope := meshReplayEvidence(t, bed, device, 2)
	// A deferred constraint trigger fails at COMMIT, after every write succeeded.
	if _, err := bed.db.Exec(`CREATE FUNCTION fail_commit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected commit failure'; END $$;
		CREATE CONSTRAINT TRIGGER fail_commit AFTER INSERT ON device_evidence
		DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_commit()`); err != nil {
		t.Fatal(err)
	}
	status, ack := serveMeshEvidence(t, server, device.peer, envelope)
	if status != http.StatusServiceUnavailable || ack != nil {
		t.Fatalf("failed commit status=%d acknowledgement=%+v", status, ack)
	}
	requireMeshDeviceState(t, bed, device, contracts.EnrollmentSequenceV1)

	if _, err := bed.db.Exec(`DROP TRIGGER fail_commit ON device_evidence`); err != nil {
		t.Fatal(err)
	}
	// The endpoint retained the envelope; the rolled-back sequence is still usable.
	status, ack = serveMeshEvidence(t, server, device.peer, envelope)
	requireAcceptedAcknowledgement(t, status, ack, envelope.Sequence)
	requireMeshDeviceState(t, bed, device, envelope.Sequence, envelope.Sequence)
}
