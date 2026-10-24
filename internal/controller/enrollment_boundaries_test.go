package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	c "github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestEnrollmentChallengeBindingAndConcurrentStart(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:challenge")
	keys := newEnrollmentKeys(t)
	start := c.EnrollmentStartV1{SchemaVersion: c.EnrollmentStartV1Version, DeploymentID: token.DeploymentID, DeviceID: token.DeviceID, PublicKey: hex.EncodeToString(keys.signing.Public().(ed25519.PublicKey)), NetworkPublicKey: hex.EncodeToString(keys.networkPublic[:])}
	type outcome struct {
		status int
		data   []byte
		err    error
	}
	results := make(chan outcome, 8)
	gate := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-gate
			status, data, err := enrollmentPost(b.server.Client(), b.server.URL+"/v1/enrollment/challenges", start, map[string]string{"Authorization": "Bearer " + token.Token})
			results <- outcome{status, data, err}
		}()
	}
	close(gate)
	wg.Wait()
	close(results)
	var canonical []byte
	for result := range results {
		if result.err != nil || result.status != http.StatusOK {
			t.Fatalf("concurrent start status=%d err=%v", result.status, result.err)
		}
		if canonical == nil {
			canonical = result.data
		} else if !bytes.Equal(canonical, result.data) {
			t.Fatal("one token created different concurrent challenges")
		}
	}
	var challenge c.EnrollmentChallengeV1
	if err := json.Unmarshal(canonical, &challenge); err != nil {
		t.Fatal(err)
	}
	other := newEnrollmentKeys(t)
	start.NetworkPublicKey = hex.EncodeToString(other.networkPublic[:])
	status, _, err := enrollmentPost(b.server.Client(), b.server.URL+"/v1/enrollment/challenges", start, map[string]string{"Authorization": "Bearer " + token.Token})
	if err != nil || status != http.StatusForbidden {
		t.Fatalf("challenge rebound to another key: %d %v", status, err)
	}
	assertBootstrapUnconsumed(t, b, token.DeviceID)
	b.submit(t, token, admissionForChallenge(t, b.clock, challenge, keys), http.StatusCreated)
}

func TestEnrollmentRejectsMalformedBoundedBodiesAndQueries(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:wire")
	keys := newEnrollmentKeys(t)
	start := c.EnrollmentStartV1{SchemaVersion: c.EnrollmentStartV1Version, DeploymentID: token.DeploymentID, DeviceID: token.DeviceID, PublicKey: hex.EncodeToString(keys.signing.Public().(ed25519.PublicKey)), NetworkPublicKey: hex.EncodeToString(keys.networkPublic[:])}
	valid, _ := json.Marshal(start)
	for _, test := range []struct{ name, body, query, contentType string }{
		{"duplicate", strings.Replace(string(valid), `"device_id":`, `"device_id":"device:other","device_id":`, 1), "", "application/json"},
		{"case alias", strings.Replace(string(valid), `"device_id"`, `"Device_ID"`, 1), "", "application/json"},
		{"trailing", string(valid) + "{}", "", "application/json"},
		{"oversize", strings.Repeat(" ", maxEnrollmentBodyBytes) + string(valid), "", "application/json"},
		{"query", string(valid), "?token=must-not-be-read", "application/json"},
		{"empty query", string(valid), "?", "application/json"},
		{"content type", string(valid), "", "text/plain"},
		{"null", strings.Replace(string(valid), `"device_id":"device:wire"`, `"device_id":null`, 1), "", "application/json"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodPost, b.server.URL+"/v1/enrollment/challenges"+test.query, strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Authorization", "Bearer "+token.Token)
			response, err := b.server.Client().Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest {
				data, _ := io.ReadAll(response.Body)
				t.Fatalf("malformed body status=%d %s", response.StatusCode, data)
			}
		})
	}
	assertBootstrapUnconsumed(t, b, token.DeviceID)
	var challenges int
	if err := b.db.QueryRow(`SELECT count(*) FROM enrollment_challenges`).Scan(&challenges); err != nil || challenges != 0 {
		t.Fatalf("malformed request created challenge: %d %v", challenges, err)
	}
	b.clock.Advance(c.EnrollmentMaxLifetimeV1)
	status, _, err := enrollmentPost(b.server.Client(), b.server.URL+"/v1/enrollment/challenges", start, map[string]string{"Authorization": "Bearer " + token.Token})
	if err != nil || status != http.StatusForbidden {
		t.Fatalf("expired bootstrap created challenge: %d %v", status, err)
	}
}

func TestEnrollmentChallengeCreationRollbackAndStorageOutage(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:start-rollback")
	keys := newEnrollmentKeys(t)
	start := c.EnrollmentStartV1{SchemaVersion: c.EnrollmentStartV1Version, DeploymentID: token.DeploymentID, DeviceID: token.DeviceID, PublicKey: hex.EncodeToString(keys.signing.Public().(ed25519.PublicKey)), NetworkPublicKey: hex.EncodeToString(keys.networkPublic[:])}
	if _, err := b.db.Exec(`CREATE FUNCTION reject_network_challenge() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected challenge failure'; END $$;
		CREATE TRIGGER reject_network_challenge BEFORE INSERT ON enrollment_network_challenges FOR EACH ROW EXECUTE FUNCTION reject_network_challenge()`); err != nil {
		t.Fatal(err)
	}
	status, _, err := enrollmentPost(b.server.Client(), b.server.URL+"/v1/enrollment/challenges", start, map[string]string{"Authorization": "Bearer " + token.Token})
	if err != nil || status != http.StatusServiceUnavailable {
		t.Fatalf("challenge failure status=%d %v", status, err)
	}
	var count int
	if err := b.db.QueryRow(`SELECT count(*) FROM enrollment_challenges`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("partial challenge survived: %d %v", count, err)
	}
	assertBootstrapUnconsumed(t, b, token.DeviceID)
	if _, err := b.db.Exec(`DROP TRIGGER reject_network_challenge ON enrollment_network_challenges`); err != nil {
		t.Fatal(err)
	}
	request := admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys)
	if err := b.db.Close(); err != nil {
		t.Fatal(err)
	}
	b.submit(t, token, request, http.StatusServiceUnavailable)
}

func TestEnrollmentWaitingWriterChecksExpiryAndCancellation(t *testing.T) {
	for _, cancelWriter := range []bool{false, true} {
		t.Run(map[bool]string{false: "expiry", true: "cancellation"}[cancelWriter], func(t *testing.T) {
			b := newEnrollmentTestBed(t)
			token := b.issue(t, "device:wait")
			keys := newEnrollmentKeys(t)
			request := admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys)
			blocker, err := b.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback()
			if _, err := blocker.Exec(`SELECT 1 FROM enrollment_challenges FOR UPDATE`); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), repositoryTestTimeout)
			defer cancel()
			result := make(chan error, 1)
			go func() { _, err := b.repo.AdmitEnrollment(ctx, token.Token, request); result <- err }()
			waitRepositoryCondition(t, func(ctx context.Context) (bool, error) {
				var waiting bool
				err := b.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'SELECT device_id, signing_key_id%' AND wait_event_type='Lock')`).Scan(&waiting)
				return waiting, err
			})
			if cancelWriter {
				cancel()
			} else {
				b.clock.Advance(c.EnrollmentMaxLifetimeV1)
				if err := blocker.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-result:
				if cancelWriter {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("cancellation ignored: %v", err)
					}
				} else {
					requireRepositoryRejection(t, err, c.EnvelopeRejectionChallengeExpired)
				}
			case <-time.After(repositoryTestTimeout):
				t.Fatal("blocked admission did not finish")
			}
			assertBootstrapUnconsumed(t, b, token.DeviceID)
			if cancelWriter {
				if err := blocker.Rollback(); err != nil {
					t.Fatal(err)
				}
				b.submit(t, token, request, http.StatusCreated)
			}
		})
	}
}

func TestEnrollmentEnvelopeExpiryDuringNetworkKeyConflictWait(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:unique-wait")
	keys := newEnrollmentKeys(t)
	request := admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys)
	request.Enrollment.ExpiresAt = b.clock.Now().Add(time.Second).Format(time.RFC3339)
	signAdmission(t, &request, keys.signing)
	// A separate signing-only device lets an uncommitted binding hold the unique
	// network-key slot without locking this request's enrollment challenge.
	other := b.issue(t, "device:other-pending")
	otherKeys := newEnrollmentKeys(t)
	otherRequest := admissionForChallenge(t, b.clock, b.challenge(t, other, otherKeys), otherKeys)
	if err := b.repo.Enroll(context.Background(), otherRequest.Enrollment); err != nil {
		t.Fatal(err)
	}
	blocker, err := b.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback()
	if _, err := blocker.Exec(`INSERT INTO device_network_bindings (deployment_id,device_id,network_public_key,request_sha256) VALUES ($1,$2,$3,$4)`, other.DeploymentID, other.DeviceID, keys.networkPublic[:], make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), repositoryTestTimeout)
	defer cancel()
	go func() { _, err := b.repo.AdmitEnrollment(ctx, token.Token, request); result <- err }()
	waitRepositoryCondition(t, func(ctx context.Context) (bool, error) {
		var waiting bool
		err := b.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND query LIKE 'INSERT INTO device_network_bindings%' AND wait_event_type='Lock')`).Scan(&waiting)
		return waiting, err
	})
	b.clock.Advance(time.Second)
	if err := blocker.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		requireRepositoryRejection(t, err, c.EnvelopeRejectionExpired)
	case <-time.After(repositoryTestTimeout):
		t.Fatal("unique-key waiter did not finish")
	}
	assertBootstrapUnconsumed(t, b, token.DeviceID)
}
