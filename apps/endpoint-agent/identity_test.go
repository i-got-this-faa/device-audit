package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"golang.org/x/crypto/nacl/box"
)

func testStore(t *testing.T) (*identityStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	s, err := openIdentityStore(path, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	return s, path
}

func testToken() contracts.BootstrapTokenV1 {
	return contracts.BootstrapTokenV1{SchemaVersion: contracts.BootstrapTokenV1Version, DeploymentID: "deployment:test", DeviceID: "device:test", Token: strings.Repeat("ab", 32), ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Truncate(time.Second).Format(time.RFC3339)}
}

func testChallenge(t *testing.T, start contracts.EnrollmentStartV1) contracts.EnrollmentChallengeV1 {
	t.Helper()
	public, err := contracts.NetworkPublicKeyV1(start.NetworkPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.SealAnonymous(nil, bytes.Repeat([]byte{7}, 32), &public, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := hex.DecodeString(start.PublicKey)
	id, _ := contracts.SigningKeyIDV1(ed25519.PublicKey(key))
	return contracts.EnrollmentChallengeV1{SchemaVersion: contracts.EnrollmentChallengeV1Version, DeploymentID: start.DeploymentID, DeviceID: start.DeviceID, SigningKeyID: id, NetworkPublicKey: start.NetworkPublicKey, ChallengeID: strings.Repeat("cd", 32), NetworkChallenge: base64.StdEncoding.EncodeToString(sealed), ExpiresAt: time.Now().UTC().Add(4 * time.Minute).Truncate(time.Second).Format(time.RFC3339)}
}

func testAccepted(start contracts.EnrollmentStartV1) contracts.EnrollmentAcceptedV1 {
	key, _ := hex.DecodeString(start.PublicKey)
	id, _ := contracts.SigningKeyIDV1(ed25519.PublicKey(key))
	return contracts.EnrollmentAcceptedV1{SchemaVersion: contracts.EnrollmentAcceptedV1Version, DeploymentID: start.DeploymentID, DeviceID: start.DeviceID, SigningKeyID: id, NetworkPublicKey: start.NetworkPublicKey, LastSequence: 1}
}

// This TLS peer checks real canonical signatures and network possession. It is
// a protocol fixture, not a PostgreSQL admission or deployed-controller proof.
func TestEnrollmentAndProcessRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	s, err := openIdentityStore(path, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if s != nil {
			s.close()
		}
	}()
	var start contracts.EnrollmentStartV1
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testToken().Token {
			t.Error("missing bootstrap authorization")
			w.WriteHeader(403)
			return
		}
		switch r.URL.Path {
		case "/v1/enrollment/challenges":
			if json.NewDecoder(r.Body).Decode(&start) != nil || start.Validate() != nil {
				t.Error("invalid enrollment start")
				w.WriteHeader(400)
				return
			}
			json.NewEncoder(w).Encode(testChallenge(t, start))
		case "/v1/enrollment":
			var admission contracts.EnrollmentAdmissionV1
			key, _ := hex.DecodeString(start.PublicKey)
			if json.NewDecoder(r.Body).Decode(&admission) != nil || admission.VerifySignature(ed25519.PublicKey(key)) != nil || admission.NetworkProof != strings.Repeat("07", 32) {
				t.Error("invalid possession proof")
				w.WriteHeader(403)
				return
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(testAccepted(start))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	client, origin, err := enrollmentClient(server.URL, caFile)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	accepted, err := enroll(context.Background(), s, client, origin, testToken())
	if err != nil {
		t.Fatal(err)
	}
	before, err := s.read(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.read(sequenceFile); err != nil {
		t.Fatal("admission saved without sequence state")
	}
	i, err := s.load(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if !strings.Contains(fmt.Sprintf(format, i), "redacted") {
			t.Fatal("identity formatting was not redacted")
		}
	}
	s.close()
	s = nil
	command := identityStatusProcess(path)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fresh process could not reuse identity: %v", err)
	}
	var got contracts.EnrollmentAcceptedV1
	if json.Unmarshal(out, &got) != nil || got != accepted {
		t.Fatal("fresh process did not report the same bound public identity")
	}
	if bytes.Contains(out, []byte(hex.EncodeToString(i.signing.Seed()))) || bytes.Contains(out, []byte(hex.EncodeToString(i.network.Bytes()))) {
		t.Fatal("private material in process output")
	}
	s, err = openIdentityStore(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enroll(context.Background(), s, client, origin, testToken()); err != nil {
		t.Fatal(err)
	}
	after, err := s.read(keyFile)
	if err != nil || !bytes.Equal(before, after) || requests.Load() != 2 {
		t.Fatal("restart changed identity or re-enrolled admitted keys")
	}
}

func identityStatusProcess(path string) *exec.Cmd {
	command := exec.Command(os.Args[0], "-test.run=^TestIdentityProcess$")
	command.Env = append(os.Environ(), "DEVICE_AUDIT_TEST_IDENTITY_DIR="+path)
	return command
}

func TestIdentityProcess(t *testing.T) {
	path := os.Getenv("DEVICE_AUDIT_TEST_IDENTITY_DIR")
	if path == "" {
		return
	}
	os.Args = []string{os.Args[0], "--identity-status", "--state-dir", path}
	main()
	os.Exit(0)
}

func TestIdentityStorageFailsClosed(t *testing.T) {
	for _, damage := range []string{"truncated", "bitflip", "missing", "directory", "scope-only", "oversize"} {
		t.Run(damage, func(t *testing.T) {
			s, _ := testStore(t)
			i, err := s.load(true)
			if err != nil {
				t.Fatal(err)
			}
			if damage == "scope-only" {
				if s.root.Remove(keyFile) != nil {
					t.Fatal("remove key fixture")
				}
				if s.write("scope.json", []byte("{}")) != nil {
					t.Fatal("write scope fixture")
				}
			} else {
				data, _ := s.read(keyFile)
				if damage == "missing" || damage == "directory" {
					s.root.Remove(keyFile)
					if damage == "directory" {
						s.root.Mkdir(keyFile, 0700)
					}
				} else {
					if damage == "truncated" {
						data = data[:3]
					}
					if damage == "bitflip" {
						data[len(data)/2] ^= 1
					}
					if damage == "oversize" {
						data = make([]byte, 16385)
					}
					if err := s.root.WriteFile(keyFile, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				// A missing key beside a committed receipt must never reprovision.
				if damage == "missing" {
					receipt, _ := json.Marshal(testAccepted(i.start("deployment:test", "device:test")))
					if s.write(receiptFile, receipt) != nil {
						t.Fatal("write receipt fixture")
					}
				}
			}
			if _, err := s.load(false); err == nil {
				t.Fatal("damaged identity loaded")
			}
			if _, err := enroll(context.Background(), s, http.DefaultClient, "https://unreachable.invalid", testToken()); err == nil {
				t.Fatal("damaged identity replaced")
			}
		})
	}
}

func TestChallengeScopeAndPossession(t *testing.T) {
	i, err := newIdentity()
	if err != nil {
		t.Fatal(err)
	}
	start := i.start("deployment:test", "device:test")
	for _, damage := range []string{"device", "deployment", "signing", "network", "expired", "late", "sealed"} {
		t.Run(damage, func(t *testing.T) {
			challenge := testChallenge(t, start)
			switch damage {
			case "device":
				challenge.DeviceID = "another-device"
			case "deployment":
				challenge.DeploymentID = "another-deployment"
			case "signing":
				challenge.SigningKeyID = "sha256:" + strings.Repeat("00", 32)
			case "network":
				other, _ := newIdentity()
				challenge.NetworkPublicKey = other.start("", "").NetworkPublicKey
			case "expired":
				challenge.ExpiresAt = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
			case "late":
				challenge.ExpiresAt = time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
			case "sealed":
				raw, _ := base64.StdEncoding.DecodeString(challenge.NetworkChallenge)
				raw[len(raw)-1] ^= 1
				challenge.NetworkChallenge = base64.StdEncoding.EncodeToString(raw)
			}
			if _, err := i.admission(start, challenge, testToken().ExpiresAt, time.Now().UTC().Truncate(time.Second)); err == nil {
				t.Fatal("invalid challenge signed")
			}
		})
	}
}

func TestEnrollmentTrustAndCredentialParsing(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:8080", "https://user:password@example.test", "https://example.test/path", "https://example.test?token=secret", "https://example.test#fragment", "https://example.test?"} {
		if _, _, err := enrollmentClient(origin, ""); err == nil {
			t.Fatal("unsafe enrollment origin accepted")
		}
	}
	for _, data := range []string{`{}`, `{"token":"secret"}`, strings.Repeat("x", 16385)} {
		if _, err := readBootstrap(strings.NewReader(data)); err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid credential accepted or disclosed")
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted TLS origin received credential") }))
	defer server.Close()
	client, origin, err := enrollmentClient(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	var challenge contracts.EnrollmentChallengeV1
	i, _ := newIdentity()
	if err := postEnrollment(context.Background(), client, origin, testToken().Token, 200, i.start("deployment:test", "device:test"), &challenge); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestConcurrentIdentityStorage(t *testing.T) {
	_, path := testStore(t)
	if other, err := openIdentityStore(path, false); err == nil {
		other.close()
		t.Fatal("concurrent store acquired")
	}
}

func TestCorruptReceiptNeverAppearsInErrors(t *testing.T) {
	s, _ := testStore(t)
	if _, err := s.load(true); err != nil {
		t.Fatal(err)
	}
	marker := "private-storage-error-marker"
	if s.write(receiptFile, []byte(`{"`+marker+`":"secret"}`)) != nil {
		t.Fatal("write invalid receipt fixture")
	}
	if _, err := s.status(); err == nil || strings.Contains(err.Error(), marker) || strings.Contains(err.Error(), "secret") {
		t.Fatal("invalid receipt accepted or disclosed")
	}
}

func TestFailedAdmissionRetainsIdentity(t *testing.T) {
	for _, failure := range []string{"rejected", "lost-response", "wrong-receipt", "scope-change", "server-error", "bad-gateway", "unavailable", "gateway-timeout"} {
		t.Run(failure, func(t *testing.T) {
			s, path := testStore(t)
			serverStatus := map[string]int{"server-error": 500, "bad-gateway": 502, "unavailable": 503, "gateway-timeout": 504}[failure]
			var starts []contracts.EnrollmentStartV1
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/enrollment/challenges" {
					var start contracts.EnrollmentStartV1
					if json.NewDecoder(r.Body).Decode(&start) != nil {
						t.Error("decode start")
						return
					}
					starts = append(starts, start)
					json.NewEncoder(w).Encode(testChallenge(t, start))
					return
				}
				if failure == "lost-response" {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						connection.Close()
					}
					return
				}
				if failure == "wrong-receipt" {
					receipt := testAccepted(starts[0])
					receipt.DeviceID = "other-device"
					w.WriteHeader(201)
					json.NewEncoder(w).Encode(receipt)
					return
				}
				if serverStatus != 0 {
					w.WriteHeader(serverStatus)
				} else {
					w.WriteHeader(403)
				}
				fmt.Fprint(w, "private-server-error-marker")
			}))
			defer server.Close()
			client := server.Client()
			defer client.CloseIdleConnections()
			token := testToken()
			_, err := enroll(context.Background(), s, client, server.URL, token)
			if err == nil || strings.Contains(err.Error(), "private-server-error-marker") || strings.Contains(err.Error(), token.Token) {
				t.Fatal("failed admission accepted or secret disclosed")
			}
			if serverStatus != 0 && (!strings.Contains(err.Error(), "uncertain") || strings.Contains(err.Error(), "rejected")) {
				t.Fatal("server failure reported a definite rejection")
			}
			if failure == "rejected" && !strings.Contains(err.Error(), "rejected") {
				t.Fatal("authorization rejection lost its classification")
			}
			before, err := s.read(keyFile)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.read(receiptFile); !os.IsNotExist(err) {
				t.Fatal("failed admission saved receipt")
			}
			if failure == "scope-change" {
				token.DeviceID = "other-device"
			}
			if _, err := enroll(context.Background(), s, client, server.URL, token); err == nil {
				t.Fatal("failed admission accepted on retry")
			}
			after, err := s.read(keyFile)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed admission replaced keys")
			}
			if failure == "scope-change" {
				if len(starts) != 1 {
					t.Fatal("scope change reached remote peer")
				}
			} else if len(starts) != 2 || starts[0] != starts[1] {
				t.Fatal("retry used another identity")
			}
			s.close()
			out, err := identityStatusProcess(path).CombinedOutput()
			if err == nil || bytes.Contains(out, []byte(token.Token)) || bytes.Contains(out, []byte("private-server-error-marker")) {
				t.Fatal("pending process status succeeded or disclosed secret")
			}
		})
	}
}
