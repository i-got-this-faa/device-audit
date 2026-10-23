package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const (
	repositoryTestTimeout                   = 10 * time.Second
	repositoryTestPollInterval              = 10 * time.Millisecond
	repositoryFixtureSeedHex                = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
	repositoryFixturePath                   = "../../packages/contracts/fixtures/envelopes/v1-vectors.json"
	repositoryFixtureAuthorizationReference = "authorization:fixture"
	repositoryFixtureEvidenceRequestSHA256  = "0887d62032237d1975aacc3e4e1865b14bcbda46537be3af86c3941bbec70aea"
	repositoryConcurrentEnrollments         = 8
)

// Public RFC 8032 test seed, also used by the shared envelope fixtures.
func repositoryFixtureKey() ed25519.PrivateKey {
	seed, _ := hex.DecodeString(repositoryFixtureSeedHex)
	return ed25519.NewKeyFromSeed(seed)
}

func repositoryEnvelopes(t *testing.T) (contracts.EnrollmentEnvelopeV1, contracts.EvidenceEnvelopeV1) {
	t.Helper()
	data, err := os.ReadFile(repositoryFixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var catalogue struct {
		Vectors []struct {
			Name     string
			Envelope json.RawMessage
		}
	}
	if err := json.Unmarshal(data, &catalogue); err != nil {
		t.Fatal(err)
	}
	var enrollment contracts.EnrollmentEnvelopeV1
	var evidence contracts.EvidenceEnvelopeV1
	for _, vector := range catalogue.Vectors {
		switch vector.Name {
		case "valid enrollment":
			if err := json.Unmarshal(vector.Envelope, &enrollment); err != nil {
				t.Fatal(err)
			}
		case "valid offline evidence with nullable metric":
			if err := json.Unmarshal(vector.Envelope, &evidence); err != nil {
				t.Fatal(err)
			}
		}
	}
	if enrollment.DeviceID == "" || evidence.DeviceID == "" {
		t.Fatal("shared envelope fixtures are missing")
	}
	return enrollment, evidence
}

func openRepositoryTestDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	adminURL := *parsed
	adminURL.Path = "/postgres"
	admin, err := database.Open(context.Background(), adminURL.String())
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("device_repository_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		admin.Close()
		t.Fatal(err)
	}
	parsed.Path = "/" + name
	db, err := database.Open(context.Background(), parsed.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=$1`, name)
		if _, err := admin.Exec(`DROP DATABASE "` + name + `"`); err != nil {
			t.Errorf("drop isolated repository database: %v", err)
		}
		admin.Close()
	})
	if _, err := database.Migrate(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return db, parsed.String()
}

func repositoryFixtureTime(t *testing.T) time.Time {
	t.Helper()
	enrollment, _ := repositoryEnvelopes(t)
	now, err := time.Parse(time.RFC3339, enrollment.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func fixtureRepository(t *testing.T, db *sql.DB) *PostgresRepository {
	t.Helper()
	enrollment, _ := repositoryEnvelopes(t)
	now := repositoryFixtureTime(t)
	repo, err := NewPostgresRepository(context.Background(), db, RepositoryConfig{
		DeploymentID: enrollment.DeploymentID, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

func signRepositoryEnrollment(t *testing.T, envelope *contracts.EnrollmentEnvelopeV1) {
	t.Helper()
	message, err := envelope.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(repositoryFixtureKey(), message))
}

func signRepositoryEvidence(t *testing.T, envelope *contracts.EvidenceEnvelopeV1) {
	t.Helper()
	message, err := envelope.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signature = hex.EncodeToString(ed25519.Sign(repositoryFixtureKey(), message))
}

func enrollRepositoryFixture(t *testing.T, repo *PostgresRepository) contracts.EnrollmentEnvelopeV1 {
	t.Helper()
	envelope, _ := repositoryEnvelopes(t)
	challenge, err := repo.CreateEnrollmentChallenge(context.Background(), envelope.DeviceID, repositoryFixtureKey().Public().(ed25519.PublicKey), repositoryFixtureAuthorizationReference)
	if err != nil {
		t.Fatal(err)
	}
	envelope.ChallengeID = challenge.ID
	signRepositoryEnrollment(t, &envelope)
	if err := repo.Enroll(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func requireRepositoryRejection(t *testing.T, err error, reason string) *RepositoryRejection {
	t.Helper()
	var rejection *RepositoryRejection
	if !errors.As(err, &rejection) || rejection.Reason != reason {
		t.Fatalf("rejection=%v, want %s", err, reason)
	}
	return rejection
}

func requireRepositoryState(t *testing.T, db *sql.DB, sequence uint64, samples int) {
	t.Helper()
	var mark uint64
	var count int
	enrollment, _ := repositoryEnvelopes(t)
	if err := db.QueryRow(`SELECT last_sequence FROM device_enrollments WHERE device_id=$1`, enrollment.DeviceID).Scan(&mark); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM device_evidence`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if mark != sequence || count != samples {
		t.Fatalf("durable state: mark=%d samples=%d; want mark=%d samples=%d", mark, count, sequence, samples)
	}
}

func TestRepositoryPreservesSignedProvenanceAndSequenceOnReopen(t *testing.T) {
	db, databaseURL := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrollment := enrollRepositoryFixture(t, repo)
	_, evidence := repositoryEnvelopes(t)
	ctx := context.Background()
	if err := repo.AcceptEvidence(ctx, evidence); err != nil {
		t.Fatal(err)
	}
	db.Close()
	reopened, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	repo = fixtureRepository(t, reopened)
	device, err := repo.Device(ctx, enrollment.DeviceID)
	if err != nil || device.LastSequence != contracts.FirstEvidenceSequenceV1 || !reflect.DeepEqual(device.Envelope, enrollment) || !device.EnrolledAt.Equal(repositoryFixtureTime(t)) {
		t.Fatalf("reopened identity=%+v err=%v", device, err)
	}
	stored, err := repo.Evidence(ctx, evidence.DeviceID, evidence.Sequence)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.StdEncoding.DecodeString(evidence.PayloadBase64)
	if !bytes.Equal(stored.PayloadBytes, payload) || !reflect.DeepEqual(stored.Envelope, evidence) ||
		stored.RequestSHA256 != repositoryFixtureEvidenceRequestSHA256 ||
		!stored.ReceivedAt.Equal(repositoryFixtureTime(t)) || !stored.CollectedAt.Equal(repositoryFixtureTime(t).Add(-contracts.EvidenceMaxLifetimeV1)) {
		t.Fatalf("stored provenance differs: %+v", stored)
	}
	if err := stored.Envelope.VerifySignature(repositoryFixtureKey().Public().(ed25519.PublicKey)); err != nil {
		t.Fatalf("stored envelope no longer verifies: %v", err)
	}
	var telemetry contracts.TelemetryV2
	if err := json.Unmarshal(stored.PayloadBytes, &telemetry); err != nil {
		t.Fatal(err)
	}
	if telemetry.Metrics.GPUUtilization.Value != nil || telemetry.Metrics.GPUUtilization.Unit != "percent" || telemetry.Metrics.GPUUtilization.MissingReason != "sensor_unavailable" {
		t.Fatalf("nullable metric lost: %+v", telemetry.Metrics.GPUUtilization)
	}
	rejection := requireRepositoryRejection(t, repo.AcceptEvidence(ctx, evidence), contracts.EnvelopeRejectionReplay)
	if rejection.LastSequence == nil || *rejection.LastSequence != contracts.FirstEvidenceSequenceV1 {
		t.Fatalf("replay lacks committed mark: %+v", rejection)
	}
	// Retention of sample bodies must never control replay protection.
	if _, err := reopened.Exec(`DELETE FROM device_evidence`); err != nil {
		t.Fatal(err)
	}
	requireRepositoryRejection(t, repo.AcceptEvidence(ctx, evidence), contracts.EnvelopeRejectionReplay)
	const sequenceGap = 100
	for _, sequence := range []uint64{sequenceGap, contracts.MaxEnvelopeSequence} {
		evidence.Sequence = sequence
		signRepositoryEvidence(t, &evidence)
		if err := repo.AcceptEvidence(ctx, evidence); err != nil {
			t.Fatal(err)
		}
	}
	requireRepositoryState(t, reopened, contracts.MaxEnvelopeSequence, 2)
	requireRepositoryRejection(t, repo.AcceptEvidence(ctx, evidence), contracts.EnvelopeRejectionReplay)
	evidence.Sequence++
	requireRepositoryRejection(t, repo.AcceptEvidence(ctx, evidence), contracts.EnvelopeRejectionInvalidPayload)
}

func TestRepositoryExactPayloadWhitespace(t *testing.T) {
	db, _ := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrollRepositoryFixture(t, repo)
	_, evidence := repositoryEnvelopes(t)
	payload, _ := base64.StdEncoding.DecodeString(evidence.PayloadBase64)
	var indented bytes.Buffer
	if err := json.Indent(&indented, payload, "", "  "); err != nil {
		t.Fatal(err)
	}
	changed := append(indented.Bytes(), '\n')
	digest := sha256.Sum256(changed)
	evidence.PayloadBase64, evidence.PayloadSHA256 = base64.StdEncoding.EncodeToString(changed), hex.EncodeToString(digest[:])
	signRepositoryEvidence(t, &evidence)
	if err := repo.AcceptEvidence(context.Background(), evidence); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.Evidence(context.Background(), evidence.DeviceID, evidence.Sequence)
	if err != nil || !bytes.Equal(stored.PayloadBytes, changed) {
		t.Fatalf("exact signed bytes were normalized: err=%v", err)
	}
}

func TestRepositoryEnrollmentAtomicityAndConflicts(t *testing.T) {
	db, _ := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	ctx := context.Background()
	enrollment, _ := repositoryEnvelopes(t)
	challenge, err := repo.CreateEnrollmentChallenge(ctx, enrollment.DeviceID, repositoryFixtureKey().Public().(ed25519.PublicKey), repositoryFixtureAuthorizationReference)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.ChallengeID = challenge.ID
	signRepositoryEnrollment(t, &enrollment)
	// Fail after identity insertion, while consuming its challenge.
	if _, err := db.Exec(`CREATE FUNCTION reject_consumption() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected challenge write failure'; END $$;
		CREATE TRIGGER reject_consumption BEFORE UPDATE ON enrollment_challenges FOR EACH ROW EXECUTE FUNCTION reject_consumption()`); err != nil {
		t.Fatal(err)
	}
	if err := repo.Enroll(ctx, enrollment); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("injected enrollment failure=%v", err)
	}
	if _, err := repo.Device(ctx, enrollment.DeviceID); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("rolled back enrollment survived: %v", err)
	}
	var consumed *time.Time
	if err := db.QueryRow(`SELECT consumed_at FROM enrollment_challenges WHERE id=$1`, challenge.ID).Scan(&consumed); err != nil || consumed != nil {
		t.Fatalf("failed enrollment consumed challenge: %v %v", consumed, err)
	}
	if _, err := db.Exec(`DROP TRIGGER reject_consumption ON enrollment_challenges`); err != nil {
		t.Fatal(err)
	}
	if err := repo.Enroll(ctx, enrollment); err != nil {
		t.Fatal(err)
	}
	requireRepositoryRejection(t, repo.Enroll(ctx, enrollment), contracts.EnvelopeRejectionChallengeReused)
	for _, deviceID := range []string{enrollment.DeviceID, "asset:another"} {
		challenge, err := repo.CreateEnrollmentChallenge(ctx, deviceID, repositoryFixtureKey().Public().(ed25519.PublicKey), repositoryFixtureAuthorizationReference)
		if err != nil {
			t.Fatal(err)
		}
		conflict := enrollment
		conflict.DeviceID, conflict.ChallengeID = deviceID, challenge.ID
		signRepositoryEnrollment(t, &conflict)
		requireRepositoryRejection(t, repo.Enroll(ctx, conflict), contracts.EnvelopeRejectionEnrollmentConflict)
		if err := db.QueryRow(`SELECT consumed_at FROM enrollment_challenges WHERE id=$1`, challenge.ID).Scan(&consumed); err != nil || consumed != nil {
			t.Fatalf("conflict consumed challenge: %v %v", consumed, err)
		}
	}
	requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
}

func TestRepositoryRejectsUntrustedOrStaleInput(t *testing.T) {
	db, _ := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrollRepositoryFixture(t, repo)
	_, evidence := repositoryEnvelopes(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		reason string
		change func(*contracts.EvidenceEnvelopeV1)
	}{
		{"deployment", contracts.EnvelopeRejectionDeploymentMismatch, func(e *contracts.EvidenceEnvelopeV1) { e.DeploymentID = "deployment:other" }},
		{"signature", contracts.EnvelopeRejectionInvalidSignature, func(e *contracts.EvidenceEnvelopeV1) { e.Signature = strings.Repeat("00", ed25519.SignatureSize) }},
		{"digest", contracts.EnvelopeRejectionInvalidPayload, func(e *contracts.EvidenceEnvelopeV1) { e.PayloadSHA256 = strings.Repeat("00", sha256.Size) }},
		{contracts.EnvelopeRejectionExpired, contracts.EnvelopeRejectionExpired, func(e *contracts.EvidenceEnvelopeV1) {
			now := repositoryFixtureTime(t)
			e.IssuedAt = now.Add(-contracts.EvidenceMaxLifetimeV1).Format(time.RFC3339)
			e.ExpiresAt = now.Format(time.RFC3339)
			signRepositoryEvidence(t, e)
		}},
		{"future", contracts.EnvelopeRejectionFutureTimestamp, func(e *contracts.EvidenceEnvelopeV1) {
			issued := repositoryFixtureTime(t).Add(contracts.EnvelopeMaxFutureSkewV1 + time.Second)
			e.IssuedAt = issued.Format(time.RFC3339)
			e.ExpiresAt = issued.Add(contracts.EvidenceMaxLifetimeV1).Format(time.RFC3339)
			signRepositoryEvidence(t, e)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := evidence
			tc.change(&changed)
			requireRepositoryRejection(t, repo.AcceptEvidence(ctx, changed), tc.reason)
			requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
		})
	}
	if _, err := db.Exec(`UPDATE device_enrollments SET revoked_at=now()`); err != nil {
		t.Fatal(err)
	}
	requireRepositoryRejection(t, repo.AcceptEvidence(ctx, evidence), contracts.EnvelopeRejectionRevokedKey)
	requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
	if _, err := NewPostgresRepository(ctx, db, RepositoryConfig{DeploymentID: "deployment:other"}); err == nil {
		t.Fatal("database accepted another configured deployment")
	}
	db.Close()
	if _, err := repo.Device(ctx, evidence.DeviceID); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unavailable read=%v", err)
	}
	if err := repo.AcceptEvidence(ctx, evidence); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("unavailable write=%v", err)
	}
}

func TestRepositoryEvidenceRollbackAtBothWriteBoundaries(t *testing.T) {
	for _, deferred := range []bool{false, true} {
		t.Run(fmt.Sprintf("deferred=%v", deferred), func(t *testing.T) {
			db, _ := openRepositoryTestDB(t)
			repo := fixtureRepository(t, db)
			enrollRepositoryFixture(t, repo)
			_, evidence := repositoryEnvelopes(t)
			trigger := `CREATE TRIGGER fail_write BEFORE UPDATE ON device_enrollments FOR EACH ROW EXECUTE FUNCTION fail_write()`
			if deferred {
				trigger = `CREATE CONSTRAINT TRIGGER fail_write AFTER UPDATE ON device_enrollments DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION fail_write()`
			}
			if _, err := db.Exec(`CREATE FUNCTION fail_write() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN RAISE EXCEPTION 'injected evidence write failure'; END $$;` + trigger); err != nil {
				t.Fatal(err)
			}
			if err := repo.AcceptEvidence(context.Background(), evidence); !errors.Is(err, ErrRepositoryUnavailable) {
				t.Fatalf("injected transaction failure=%v", err)
			}
			requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
			if _, err := db.Exec(`DROP TRIGGER fail_write ON device_enrollments`); err != nil {
				t.Fatal(err)
			}
			if err := repo.AcceptEvidence(context.Background(), evidence); err != nil {
				t.Fatalf("rolled back sequence became unusable: %v", err)
			}
			requireRepositoryState(t, db, evidence.Sequence, 1)
		})
	}
}

func TestRepositoryConcurrentIndependentWriters(t *testing.T) {
	db, databaseURL := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrollRepositoryFixture(t, repo)
	_, evidence := repositoryEnvelopes(t)
	const writers = 16
	start := make(chan struct{})
	results := make(chan error, writers)
	var wg sync.WaitGroup
	for range writers {
		independent, err := database.Open(context.Background(), databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { independent.Close() })
		writer := fixtureRepository(t, independent)
		wg.Go(func() {
			<-start
			results <- writer.AcceptEvidence(context.Background(), evidence)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			requireRepositoryRejection(t, err, contracts.EnvelopeRejectionReplay)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d concurrent duplicates, want 1", accepted)
	}
	requireRepositoryState(t, db, evidence.Sequence, 1)
	// Race distinct higher sequences. Any serial order is valid; the maximum
	// must win and no accepted sample may exist beyond the final mark.
	results = make(chan error, writers)
	start = make(chan struct{})
	for i := range writers {
		next := evidence
		next.Sequence = evidence.Sequence + 1 + uint64(i)
		signRepositoryEvidence(t, &next)
		wg.Go(func() {
			<-start
			results <- repo.AcceptEvidence(context.Background(), next)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			requireRepositoryRejection(t, err, contracts.EnvelopeRejectionReplay)
		}
	}
	device, err := repo.Device(context.Background(), evidence.DeviceID)
	if err != nil || device.LastSequence != uint64(writers)+evidence.Sequence {
		t.Fatalf("concurrent high-water mark=%d err=%v", device.LastSequence, err)
	}
	if _, err := repo.Evidence(context.Background(), evidence.DeviceID, uint64(writers)+evidence.Sequence); err != nil {
		t.Fatalf("maximum committed mark has no sample: %v", err)
	}
}

func TestRepositoryChallengeBindingAndExpiry(t *testing.T) {
	db, _ := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrollment, _ := repositoryEnvelopes(t)
	ctx := context.Background()
	challenge, err := repo.CreateEnrollmentChallenge(ctx, enrollment.DeviceID, repositoryFixtureKey().Public().(ed25519.PublicKey), repositoryFixtureAuthorizationReference)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.ChallengeID = challenge.ID
	enrollment.DeviceID = "asset:unauthorized"
	signRepositoryEnrollment(t, &enrollment)
	requireRepositoryRejection(t, repo.Enroll(ctx, enrollment), contracts.EnvelopeRejectionBootstrapInvalid)
	enrollment.DeviceID = challenge.DeviceID
	signRepositoryEnrollment(t, &enrollment)
	repo.now = func() time.Time { return challenge.ExpiresAt }
	requireRepositoryRejection(t, repo.Enroll(ctx, enrollment), contracts.EnvelopeRejectionChallengeExpired)
	var consumed bool
	if err := db.QueryRow(`SELECT consumed_at IS NOT NULL FROM enrollment_challenges WHERE id=$1`, challenge.ID).Scan(&consumed); err != nil || consumed {
		t.Fatalf("denied enrollment consumed challenge: %v %v", consumed, err)
	}
	if _, err := repo.Device(ctx, challenge.DeviceID); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("denied enrollment created identity: %v", err)
	}
}

func TestRepositoryConcurrentEnrollmentConsumesChallengeOnce(t *testing.T) {
	db, _ := openRepositoryTestDB(t)
	repo := fixtureRepository(t, db)
	enrollment, _ := repositoryEnvelopes(t)
	challenge, err := repo.CreateEnrollmentChallenge(context.Background(), enrollment.DeviceID, repositoryFixtureKey().Public().(ed25519.PublicKey), repositoryFixtureAuthorizationReference)
	if err != nil {
		t.Fatal(err)
	}
	enrollment.ChallengeID = challenge.ID
	signRepositoryEnrollment(t, &enrollment)
	start := make(chan struct{})
	results := make(chan error, repositoryConcurrentEnrollments)
	var wg sync.WaitGroup
	for range repositoryConcurrentEnrollments {
		wg.Go(func() {
			<-start
			results <- repo.Enroll(context.Background(), enrollment)
		})
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			requireRepositoryRejection(t, err, contracts.EnvelopeRejectionChallengeReused)
		}
	}
	if accepted != 1 {
		t.Fatalf("challenge admitted %d enrollments, want 1", accepted)
	}
	requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
}

func TestRepositoryWaitingWriterCancellationAndExpiry(t *testing.T) {
	for _, cancelWriter := range []bool{false, true} {
		t.Run(fmt.Sprintf("cancel=%v", cancelWriter), func(t *testing.T) {
			db, _ := openRepositoryTestDB(t)
			repo := fixtureRepository(t, db)
			enrollRepositoryFixture(t, repo)
			_, evidence := repositoryEnvelopes(t)
			var clock atomic.Int64
			clock.Store(repositoryFixtureTime(t).Unix())
			repo.now = func() time.Time { return time.Unix(clock.Load(), 0) }
			blocker, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if _, err := blocker.Exec(`SELECT 1 FROM device_enrollments FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), repositoryTestTimeout)
			defer cancel()
			result := make(chan error, 1)
			go func() { result <- repo.AcceptEvidence(ctx, evidence) }()
			waitRepositoryCondition(t, func(ctx context.Context) (bool, error) {
				var waiting bool
				err := db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM pg_stat_activity
					WHERE datname=current_database() AND query LIKE 'SELECT public_key%'
					AND wait_event_type='Lock')`).Scan(&waiting)
				return waiting, err
			})
			if cancelWriter {
				cancel()
			} else {
				clock.Store(repositoryFixtureTime(t).Add(contracts.EvidenceMaxLifetimeV1).Unix())
				if err := blocker.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-result:
				if cancelWriter {
					if !errors.Is(err, ErrRepositoryUnavailable) || !errors.Is(err, context.Canceled) {
						t.Fatalf("waiting writer ignored cancellation: %v", err)
					}
				} else {
					requireRepositoryRejection(t, err, contracts.EnvelopeRejectionExpired)
				}
			case <-time.After(repositoryTestTimeout):
				t.Fatal("waiting writer did not finish")
			}
			requireRepositoryState(t, db, contracts.EnrollmentSequenceV1, 0)
		})
	}
}
