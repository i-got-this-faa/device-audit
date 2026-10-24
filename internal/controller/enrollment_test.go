package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	c "github.com/i-got-this-faa/device-audit/packages/contracts"
	"golang.org/x/crypto/nacl/box"
)

type enrollmentClock struct{ seconds atomic.Int64 }

func (c *enrollmentClock) Now() time.Time { return time.Unix(c.seconds.Load(), 0).UTC() }
func (c *enrollmentClock) Advance(duration time.Duration) {
	c.seconds.Add(int64(duration / time.Second))
}

type enrollmentTestBed struct {
	db        *sql.DB
	url       string
	repo      *PostgresRepository
	clock     *enrollmentClock
	authStore *auth.PostgresStore
	admin     *auth.Service
	server    *httptest.Server
	handler   http.Handler
	session   string
	csrf      string
	logs      *bytes.Buffer
}

func newEnrollmentTestBed(t *testing.T) *enrollmentTestBed {
	t.Helper()
	db, url := openRepositoryTestDB(t)
	clock := &enrollmentClock{}
	clock.seconds.Store(time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC).Unix())
	repo, err := NewPostgresRepository(context.Background(), db, RepositoryConfig{DeploymentID: "deployment:enrollment-test", Now: clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	store := auth.NewPostgresStore(db)
	logs := &bytes.Buffer{}
	admin, err := auth.NewService(auth.Config{Issuer: "https://id.example.test", PublicOrigin: "https://console.example.test", Store: store, Provider: auth.NewOIDCProvider("https://id.example.test", "test-client", "test-only", "https://console.example.test/auth/callback", nil), Now: clock.Now, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewEnrollmentService(repo, admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: admin, Enrollment: service}).Handler()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	bed := &enrollmentTestBed{db: db, url: url, repo: repo, clock: clock, authStore: store, admin: admin, server: server, handler: handler, logs: logs}
	bed.session, bed.csrf = bed.addSession(t, "admin:test", auth.RoleAdmin, 0)
	return bed
}

func (b *enrollmentTestBed) addSession(t *testing.T, subject string, role auth.Role, age time.Duration) (string, string) {
	t.Helper()
	if err := b.admin.EnsureBinding(context.Background(), subject, role); err != nil {
		t.Fatal(err)
	}
	var secret, csrf [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(csrf[:]); err != nil {
		t.Fatal(err)
	}
	id, csrfToken := hex.EncodeToString(secret[:]), hex.EncodeToString(csrf[:])
	digest := sha256.Sum256([]byte(id))
	now := b.clock.Now()
	if err := b.authStore.CreateSession(context.Background(), auth.Session{IDDigest: digest[:], CSRFToken: csrfToken, Issuer: "https://id.example.test", Subject: subject, Role: role, CreatedAt: now, AuthenticatedAt: now.Add(-age), LastSeenAt: now, IdleExpiresAt: now.Add(15 * time.Minute), AbsoluteExpiresAt: now.Add(8 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return id, csrfToken
}

func enrollmentPost(client *http.Client, target string, body any, headers map[string]string) (int, []byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 32<<10))
	if response.Header.Get("Cache-Control") != "no-store" {
		return response.StatusCode, data, fmt.Errorf("enrollment response can be cached")
	}
	return response.StatusCode, data, err
}

func (b *enrollmentTestBed) adminHeaders() map[string]string {
	return map[string]string{"Cookie": "__Host-device-audit-session=" + b.session, "Origin": "https://console.example.test", "X-CSRF-Token": b.csrf}
}

func (b *enrollmentTestBed) issue(t *testing.T, device string) c.BootstrapTokenV1 {
	t.Helper()
	status, data, err := enrollmentPost(b.server.Client(), b.server.URL+"/admin/bootstrap-tokens", c.BootstrapTokenRequestV1{SchemaVersion: c.BootstrapTokenRequestV1Version, DeviceID: device}, b.adminHeaders())
	if err != nil || status != http.StatusCreated {
		t.Fatalf("token issuance status=%d err=%v", status, err)
	}
	var token c.BootstrapTokenV1
	if err := json.Unmarshal(data, &token); err != nil {
		t.Fatal(err)
	}
	if err := token.Validate(); err != nil {
		t.Fatal(err)
	}
	return token
}

type enrollmentKeys struct {
	signing                       ed25519.PrivateKey
	networkPublic, networkPrivate *[32]byte
}

func newEnrollmentKeys(t *testing.T) enrollmentKeys {
	t.Helper()
	_, signing, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return enrollmentKeys{signing: signing, networkPublic: public, networkPrivate: private}
}

func (b *enrollmentTestBed) challenge(t *testing.T, token c.BootstrapTokenV1, keys enrollmentKeys) c.EnrollmentChallengeV1 {
	t.Helper()
	start := c.EnrollmentStartV1{SchemaVersion: c.EnrollmentStartV1Version, DeploymentID: token.DeploymentID, DeviceID: token.DeviceID, PublicKey: hex.EncodeToString(keys.signing.Public().(ed25519.PublicKey)), NetworkPublicKey: hex.EncodeToString(keys.networkPublic[:])}
	status, data, err := enrollmentPost(b.server.Client(), b.server.URL+"/v1/enrollment/challenges", start, map[string]string{"Authorization": "Bearer " + token.Token})
	if err != nil || status != http.StatusOK {
		t.Fatalf("challenge status=%d err=%v", status, err)
	}
	var challenge c.EnrollmentChallengeV1
	if err := json.Unmarshal(data, &challenge); err != nil {
		t.Fatal(err)
	}
	if err := challenge.Validate(); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func admissionForChallenge(t *testing.T, clock *enrollmentClock, challenge c.EnrollmentChallengeV1, keys enrollmentKeys) c.EnrollmentAdmissionV1 {
	t.Helper()
	sealed, err := base64.StdEncoding.DecodeString(challenge.NetworkChallenge)
	if err != nil {
		t.Fatal(err)
	}
	proof, ok := box.OpenAnonymous(nil, sealed, keys.networkPublic, keys.networkPrivate)
	if !ok || len(proof) != c.BootstrapSecretBytes {
		t.Fatal("network challenge did not decrypt with the endpoint key")
	}
	request := c.EnrollmentAdmissionV1{SchemaVersion: c.EnrollmentAdmissionV1Version, Enrollment: c.EnrollmentEnvelopeV1{EnvelopeHeaderV1: c.EnvelopeHeaderV1{SchemaVersion: c.EnrollmentV1Version, DeploymentID: challenge.DeploymentID, DeviceID: challenge.DeviceID, SigningKeyID: challenge.SigningKeyID, Sequence: 1, IssuedAt: clock.Now().Format(time.RFC3339), ExpiresAt: challenge.ExpiresAt}, PublicKey: hex.EncodeToString(keys.signing.Public().(ed25519.PublicKey)), ChallengeID: challenge.ChallengeID}, NetworkPublicKey: challenge.NetworkPublicKey, NetworkProof: hex.EncodeToString(proof)}
	signAdmission(t, &request, keys.signing)
	return request
}

func signAdmission(t *testing.T, request *c.EnrollmentAdmissionV1, key ed25519.PrivateKey) {
	t.Helper()
	inner, err := request.Enrollment.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.Enrollment.Signature = hex.EncodeToString(ed25519.Sign(key, inner))
	outer, err := request.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = hex.EncodeToString(ed25519.Sign(key, outer))
}

func (b *enrollmentTestBed) submit(t *testing.T, token c.BootstrapTokenV1, request c.EnrollmentAdmissionV1, want int) []byte {
	t.Helper()
	status, data, err := enrollmentPost(b.server.Client(), b.server.URL+"/v1/enrollment", request, map[string]string{"Authorization": "Bearer " + token.Token})
	if err != nil || status != want {
		t.Fatalf("admission status=%d want=%d err=%v response=%s", status, want, err, data)
	}
	return data
}

func assertBootstrapUnconsumed(t *testing.T, b *enrollmentTestBed, device string) {
	t.Helper()
	var tokens, challenges, identities, networks int
	err := b.db.QueryRow(`SELECT
		(SELECT count(*) FROM bootstrap_tokens WHERE device_id=$1 AND consumed_at IS NOT NULL),
		(SELECT count(*) FROM enrollment_challenges WHERE device_id=$1 AND consumed_at IS NOT NULL),
		(SELECT count(*) FROM device_enrollments WHERE device_id=$1),
		(SELECT count(*) FROM device_network_bindings WHERE device_id=$1)`, device).Scan(&tokens, &challenges, &identities, &networks)
	if err != nil {
		t.Fatal(err)
	}
	if tokens != 0 || challenges != 0 || identities != 0 || networks != 0 {
		t.Fatalf("partial admission: tokens=%d challenges=%d identities=%d networks=%d", tokens, challenges, identities, networks)
	}
}

func TestEnrollmentTLSRoundTripAndRestart(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:round-trip")
	keys := newEnrollmentKeys(t)
	challenge := b.challenge(t, token, keys)
	repeated := b.challenge(t, token, keys)
	if repeated != challenge {
		t.Fatal("same bootstrap start created a different challenge")
	}
	assertBootstrapUnconsumed(t, b, token.DeviceID)
	var digest []byte
	var issuer, subject string
	if err := b.db.QueryRow(`SELECT token_sha256,issued_by_issuer,issued_by_subject FROM bootstrap_tokens`).Scan(&digest, &issuer, &subject); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256([]byte(token.Token))
	if !bytes.Equal(digest, expected[:]) || bytes.Equal(digest, []byte(token.Token)) || issuer != "https://id.example.test" || subject != "admin:test" {
		t.Fatal("bootstrap credential digest or issuer provenance incorrect")
	}
	sealed, _ := base64.StdEncoding.DecodeString(challenge.NetworkChallenge)
	other := newEnrollmentKeys(t)
	if _, ok := box.OpenAnonymous(nil, sealed, other.networkPublic, other.networkPrivate); ok {
		t.Fatal("another network private key opened the challenge")
	}
	request := admissionForChallenge(t, b.clock, challenge, keys)
	data := b.submit(t, token, request, http.StatusCreated)
	var accepted c.EnrollmentAcceptedV1
	if err := json.Unmarshal(data, &accepted); err != nil {
		t.Fatal(err)
	}
	if err := accepted.Validate(); err != nil {
		t.Fatal(err)
	}
	if accepted.DeviceID != request.Enrollment.DeviceID || accepted.NetworkPublicKey != request.NetworkPublicKey || accepted.SigningKeyID != request.Enrollment.SigningKeyID {
		t.Fatal("acceptance lost identity binding")
	}
	reopened, err := database.Open(context.Background(), b.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	repo, err := NewPostgresRepository(context.Background(), reopened, RepositoryConfig{DeploymentID: token.DeploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := repo.NetworkBinding(context.Background(), token.DeviceID)
	canonical, _ := request.SigningBytes()
	fingerprint, _ := c.EnvelopeRequestSHA256V1(canonical, request.Signature)
	if err != nil || stored.DeviceID != request.Enrollment.DeviceID || stored.SigningKeyID != request.Enrollment.SigningKeyID || stored.NetworkPublicKey != request.NetworkPublicKey || stored.RequestSHA256 != fingerprint {
		t.Fatalf("network binding did not survive reopen: %v", err)
	}
	device, err := repo.Device(context.Background(), token.DeviceID)
	if err != nil || device.LastSequence != 1 {
		t.Fatalf("initial sequence not durable: %v", err)
	}
	if err := device.Envelope.VerifySignature(keys.signing.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	var persistedBinding, persistedChallenge string
	if err := b.db.QueryRow(`SELECT row_to_json(n)::text FROM device_network_bindings n WHERE device_id=$1`, token.DeviceID).Scan(&persistedBinding); err != nil {
		t.Fatal(err)
	}
	if err := b.db.QueryRow(`SELECT row_to_json(n)::text FROM enrollment_network_challenges n WHERE challenge_id=$1`, challenge.ChallengeID).Scan(&persistedChallenge); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persistedBinding, request.NetworkProof) || strings.Contains(persistedChallenge, request.NetworkProof) || strings.Contains(persistedBinding, token.Token) || strings.Contains(persistedChallenge, token.Token) {
		t.Fatal("plaintext credential or network proof persisted")
	}
	if _, err := repo.AdmitEnrollment(context.Background(), token.Token, request); err == nil {
		t.Fatal("reopened repository redeemed consumed token")
	}
	b.submit(t, token, request, http.StatusForbidden)
	if strings.Contains(b.logs.String(), token.Token) || strings.Contains(b.logs.String(), request.NetworkProof) {
		t.Fatal("credential or network proof entered logs")
	}
}

func TestEnrollmentTokenIssuanceAuthorization(t *testing.T) {
	b := newEnrollmentTestBed(t)
	viewer, viewerCSRF := b.addSession(t, "viewer:test", auth.RoleViewer, 0)
	stale, staleCSRF := b.addSession(t, "admin:stale", auth.RoleAdmin, 5*time.Minute+time.Second)
	for _, test := range []struct {
		name, session, csrf, origin string
		want                        int
	}{
		{"anonymous", "", "", "", http.StatusUnauthorized},
		{"viewer", viewer, viewerCSRF, "https://console.example.test", http.StatusForbidden},
		{"missing csrf", b.session, "", "https://console.example.test", http.StatusForbidden},
		{"foreign origin", b.session, b.csrf, "https://attacker.example.test", http.StatusForbidden},
		{"stale authentication", stale, staleCSRF, "https://console.example.test", http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			status, _, err := enrollmentPost(b.server.Client(), b.server.URL+"/admin/bootstrap-tokens", c.BootstrapTokenRequestV1{SchemaVersion: c.BootstrapTokenRequestV1Version, DeviceID: "device:denied"}, map[string]string{"Cookie": "__Host-device-audit-session=" + test.session, "Origin": test.origin, "X-CSRF-Token": test.csrf, "X-Forwarded-User": "admin:test"})
			if err != nil || status != test.want {
				t.Fatalf("status=%d want=%d err=%v", status, test.want, err)
			}
		})
	}
	var count int
	if err := b.db.QueryRow(`SELECT count(*) FROM bootstrap_tokens`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("denied issuer created tokens: %d %v", count, err)
	}
	plain := httptest.NewServer(b.handler)
	t.Cleanup(plain.Close)
	status, data, err := enrollmentPost(plain.Client(), plain.URL+"/admin/bootstrap-tokens", c.BootstrapTokenRequestV1{SchemaVersion: c.BootstrapTokenRequestV1Version, DeviceID: "device:plaintext"}, b.adminHeaders())
	if err != nil || status != http.StatusForbidden || !bytes.Contains(data, []byte("tls_required")) {
		t.Fatalf("plaintext issuance status=%d err=%v", status, err)
	}
	// Proxy headers cannot turn a plaintext request into an authenticated TLS one.
	status, data, err = enrollmentPost(plain.Client(), plain.URL+"/v1/enrollment/challenges", map[string]string{}, map[string]string{"X-Forwarded-Proto": "https", "Forwarded": "proto=https", "Authorization": "Bearer " + strings.Repeat("ab", 32)})
	if err != nil || status != http.StatusForbidden || !bytes.Contains(data, []byte("tls_required")) {
		t.Fatalf("forwarded TLS bypass status=%d err=%v", status, err)
	}
}

func TestEnrollmentRejectsInvalidProofsAndExpiryWithoutAdmission(t *testing.T) {
	for _, name := range []string{"outer signature", "inner signature", "signing key", "network proof", "network key", "device", "deployment", "challenge", "token", "expired token", "expired envelope"} {
		t.Run(name, func(t *testing.T) {
			b := newEnrollmentTestBed(t)
			token := b.issue(t, "device:invalid")
			keys := newEnrollmentKeys(t)
			challenge := b.challenge(t, token, keys)
			request := admissionForChallenge(t, b.clock, challenge, keys)
			switch name {
			case "outer signature":
				request.Signature = strings.Repeat("00", 64)
			case "inner signature":
				request.Enrollment.Signature = strings.Repeat("00", 64)
				message, err := request.SigningBytes()
				if err != nil {
					t.Fatal(err)
				}
				request.Signature = hex.EncodeToString(ed25519.Sign(keys.signing, message))
			case "signing key":
				other := newEnrollmentKeys(t)
				public := other.signing.Public().(ed25519.PublicKey)
				request.Enrollment.PublicKey = hex.EncodeToString(public)
				request.Enrollment.SigningKeyID, _ = c.SigningKeyIDV1(public)
				signAdmission(t, &request, other.signing)
			case "network proof":
				request.NetworkProof = strings.Repeat("00", 32)
				signAdmission(t, &request, keys.signing)
			case "network key":
				other := newEnrollmentKeys(t)
				request.NetworkPublicKey = hex.EncodeToString(other.networkPublic[:])
				signAdmission(t, &request, keys.signing)
			case "device":
				request.Enrollment.DeviceID = "device:other"
				signAdmission(t, &request, keys.signing)
			case "deployment":
				request.Enrollment.DeploymentID = "deployment:other"
				signAdmission(t, &request, keys.signing)
			case "challenge":
				request.Enrollment.ChallengeID = strings.Repeat("ab", 32)
				signAdmission(t, &request, keys.signing)
			case "token":
				token.Token = strings.Repeat("ab", 32)
			case "expired token":
				b.clock.Advance(c.EnrollmentMaxLifetimeV1)
			case "expired envelope":
				request.Enrollment.ExpiresAt = b.clock.Now().Add(time.Second).Format(time.RFC3339)
				signAdmission(t, &request, keys.signing)
				b.clock.Advance(time.Second)
			}
			b.submit(t, token, request, http.StatusForbidden)
			assertBootstrapUnconsumed(t, b, token.DeviceID)
		})
	}
}

func TestEnrollmentRollbackAtEveryAdmissionWrite(t *testing.T) {
	for _, test := range []struct {
		table, event string
		deferred     bool
	}{
		{"device_enrollments", "INSERT", false},
		{"enrollment_challenges", "UPDATE", false},
		{"device_network_bindings", "INSERT", false},
		{"bootstrap_tokens", "UPDATE", false},
		{"device_network_bindings", "INSERT", true},
	} {
		t.Run(fmt.Sprintf("%s-%v", test.table, test.deferred), func(t *testing.T) {
			b := newEnrollmentTestBed(t)
			token := b.issue(t, "device:rollback")
			keys := newEnrollmentKeys(t)
			request := admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys)
			if _, err := b.db.Exec(`CREATE FUNCTION reject_admission() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected admission failure'; END $$`); err != nil {
				t.Fatal(err)
			}
			statement := fmt.Sprintf(`CREATE TRIGGER reject_admission BEFORE %s ON %s FOR EACH ROW EXECUTE FUNCTION reject_admission()`, test.event, test.table)
			if test.deferred {
				statement = fmt.Sprintf(`CREATE CONSTRAINT TRIGGER reject_admission AFTER %s ON %s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_admission()`, test.event, test.table)
			}
			if _, err := b.db.Exec(statement); err != nil {
				t.Fatal(err)
			}
			data := b.submit(t, token, request, http.StatusServiceUnavailable)
			if bytes.Contains(data, []byte("injected")) {
				t.Fatal("database exception leaked to client")
			}
			assertBootstrapUnconsumed(t, b, token.DeviceID)
			if _, err := b.db.Exec(fmt.Sprintf(`DROP TRIGGER reject_admission ON %s`, test.table)); err != nil {
				t.Fatal(err)
			}
			b.submit(t, token, request, http.StatusCreated)
		})
	}
}

func TestEnrollmentConcurrentRedemptionAcrossRepositories(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:concurrent")
	keys := newEnrollmentKeys(t)
	request := admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys)
	db, err := database.Open(context.Background(), b.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	repo, err := NewPostgresRepository(context.Background(), db, RepositoryConfig{DeploymentID: token.DeploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewEnrollmentService(repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	second := httptest.NewTLSServer(NewAPI(Config{MaxDevices: 1, Enrollment: service}).Handler())
	t.Cleanup(second.Close)
	servers := []*httptest.Server{b.server, second}
	type outcome struct {
		status int
		err    error
	}
	results := make(chan outcome, 12)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			server := servers[i%len(servers)]
			status, _, err := enrollmentPost(server.Client(), server.URL+"/v1/enrollment", request, map[string]string{"Authorization": "Bearer " + token.Token})
			results <- outcome{status, err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	accepted := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.status == http.StatusCreated {
			accepted++
		} else if result.status != http.StatusForbidden {
			t.Fatalf("duplicate status=%d", result.status)
		}
	}
	if accepted != 1 {
		t.Fatalf("concurrent copies admitted %d times", accepted)
	}
	var tokens, challenges, identities, networks int
	if err := b.db.QueryRow(`SELECT (SELECT count(*) FROM bootstrap_tokens WHERE consumed_at IS NOT NULL),(SELECT count(*) FROM enrollment_challenges WHERE consumed_at IS NOT NULL),(SELECT count(*) FROM device_enrollments),(SELECT count(*) FROM device_network_bindings)`).Scan(&tokens, &challenges, &identities, &networks); err != nil {
		t.Fatal(err)
	}
	if tokens != 1 || challenges != 1 || identities != 1 || networks != 1 {
		t.Fatalf("incomplete concurrent commit: %d %d %d %d", tokens, challenges, identities, networks)
	}
}

func TestEnrollmentRejectsKeyAndDeviceConflictsAtomically(t *testing.T) {
	for _, name := range []string{"signing key", "network key", "device"} {
		t.Run(name, func(t *testing.T) {
			b := newEnrollmentTestBed(t)
			first := b.issue(t, "device:first")
			keys := newEnrollmentKeys(t)
			b.submit(t, first, admissionForChallenge(t, b.clock, b.challenge(t, first, keys), keys), http.StatusCreated)
			device := "device:second"
			secondKeys := newEnrollmentKeys(t)
			switch name {
			case "signing key":
				secondKeys.signing = keys.signing
			case "network key":
				secondKeys.networkPublic, secondKeys.networkPrivate = keys.networkPublic, keys.networkPrivate
			case "device":
				device = first.DeviceID
			}
			second := b.issue(t, device)
			request := admissionForChallenge(t, b.clock, b.challenge(t, second, secondKeys), secondKeys)
			b.submit(t, second, request, http.StatusConflict)
			var consumed int
			if err := b.db.QueryRow(`SELECT count(*) FROM bootstrap_tokens WHERE device_id=$1 AND consumed_at IS NULL`, device).Scan(&consumed); err != nil || consumed != 1 {
				t.Fatalf("conflicting request consumed token: %d %v", consumed, err)
			}
			var networks, identities int
			if err := b.db.QueryRow(`SELECT (SELECT count(*) FROM device_network_bindings),(SELECT count(*) FROM device_enrollments)`).Scan(&networks, &identities); err != nil || networks != 1 || identities != 1 {
				t.Fatalf("conflict left partial identity: %d %d %v", networks, identities, err)
			}
		})
	}
}
