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
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// A fake tunnel isolates HTTP authorization from the real transport process test.
type meshTestNode struct {
	peer         string
	disconnected bool
}

func (*meshTestNode) Addr() string { return "" }
func (*meshTestNode) Listen(context.Context, string, string) (net.Listener, error) {
	return nil, errors.New("unused")
}
func (n *meshTestNode) PeerKey(net.Addr) (string, error) { return n.peer, nil }
func (n *meshTestNode) DisconnectClient(string) error    { n.disconnected = true; return nil }
func (*meshTestNode) Close() error                       { return nil }

type meshTestRepository struct {
	binding DeviceNetworkBinding
	denied  bool
	calls   int
	err     error
}

func (r *meshTestRepository) NetworkPeerBinding(context.Context, string) (DeviceNetworkBinding, error) {
	if r.denied {
		return DeviceNetworkBinding{}, errors.New("unavailable")
	}
	return r.binding, nil
}
func (r *meshTestRepository) AcceptEvidence(context.Context, contracts.EvidenceEnvelopeV1) error {
	r.calls++
	return r.err
}

func TestMeshHTTPAdmissionAndBoundary(t *testing.T) {
	_, envelope := repositoryEnvelopes(t)
	now, err := time.Parse(time.RFC3339, envelope.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	node := &meshTestNode{peer: "peer"}
	repo := &meshTestRepository{binding: DeviceNetworkBinding{DeploymentID: envelope.DeploymentID, DeviceID: envelope.DeviceID, SigningKeyID: envelope.SigningKeyID, SigningPublicKey: repositoryFixtureKey().Public().(ed25519.PublicKey), NetworkPublicKey: node.peer}}
	s := MeshHTTPServer(MeshConfig{Node: node, Repository: repo, Logger: slog.New(slog.DiscardHandler), Now: func() time.Time { return now }})
	request := func(path string, e contracts.EvidenceEnvelopeV1) int {
		data, _ := json.Marshal(e)
		r := httptest.NewRequest("POST", path, bytes.NewReader(data))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, node.peer))
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, r)
		return w.Code
	}
	if got := request("/v1/evidence", envelope); got != 204 || repo.calls != 1 {
		t.Fatalf("valid peer status=%d calls=%d", got, repo.calls)
	}
	for _, path := range []string{"/admin/bootstrap-tokens", "/v1/enrollment", "/auth/login", "/v1/telemetry"} {
		if got := request(path, envelope); got != 404 {
			t.Fatalf("separate boundary %s status=%d", path, got)
		}
	}
	repo.binding.DeviceID = "other-device"
	if got := request("/v1/evidence", envelope); got != 403 {
		t.Fatalf("cross-device status=%d", got)
	}
	repo.binding.DeviceID = envelope.DeviceID
	tampered := envelope
	tampered.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	if got := request("/v1/evidence", tampered); got != 409 {
		t.Fatalf("tampered status=%d", got)
	}
	repo.denied = true
	if got := request("/v1/evidence", envelope); got != 403 || !node.disconnected {
		t.Fatalf("revoked/unavailable status=%d disconnect=%v", got, node.disconnected)
	}
	if repo.calls != 1 {
		t.Fatalf("rejected evidence reached ingestion: calls=%d", repo.calls)
	}
	repo.denied, repo.err = false, ErrRepositoryUnavailable
	if got := request("/v1/evidence", envelope); got != 503 || repo.calls != 2 {
		t.Fatalf("uncertain storage status=%d calls=%d", got, repo.calls)
	}
}

func TestMeshAdmissionPersistsAndRevocationDenies(t *testing.T) {
	b := newEnrollmentTestBed(t)
	token := b.issue(t, "device:mesh")
	keys := newEnrollmentKeys(t)
	challenge := b.challenge(t, token, keys)
	request := admissionForChallenge(t, b.clock, challenge, keys)
	b.submit(t, token, request, http.StatusCreated)
	// An independent repository resolves the durable binding, never a process allowlist.
	reopened, err := NewPostgresRepository(context.Background(), b.db, RepositoryConfig{DeploymentID: token.DeploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := reopened.NetworkPeerBinding(context.Background(), request.NetworkPublicKey)
	if err != nil || binding.DeviceID != token.DeviceID || binding.SigningKeyID != request.Enrollment.SigningKeyID {
		t.Fatal("durable peer binding differs")
	}
	unknown := newEnrollmentKeys(t)
	if _, err := reopened.NetworkPeerBinding(context.Background(), hex.EncodeToString(unknown.networkPublic[:])); err == nil {
		t.Fatal("unknown peer admitted")
	}
	if _, err := b.db.Exec(`UPDATE device_enrollments SET revoked_at=$1 WHERE device_id=$2`, b.clock.Now(), token.DeviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.NetworkPeerBinding(context.Background(), request.NetworkPublicKey); err == nil {
		t.Fatal("revoked peer admitted")
	}
}

type meshTestDevice struct {
	id, keyID, peer string
	signing         ed25519.PrivateKey
}

func enrollMeshTestDevice(t *testing.T, b *enrollmentTestBed, id string) meshTestDevice {
	t.Helper()
	token := b.issue(t, id)
	keys := newEnrollmentKeys(t)
	request := admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys)
	b.submit(t, token, request, http.StatusCreated)
	return meshTestDevice{id: id, keyID: request.Enrollment.SigningKeyID, peer: request.NetworkPublicKey, signing: keys.signing}
}

func meshTestTelemetry(t *testing.T, device string, collectedAt time.Time) []byte {
	t.Helper()
	fixture, err := os.ReadFile("../../packages/contracts/fixtures/telemetry/v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Vectors []struct{ Telemetry json.RawMessage }
	}
	var telemetry contracts.TelemetryV2
	if json.Unmarshal(fixture, &raw) != nil || len(raw.Vectors) == 0 || json.Unmarshal(raw.Vectors[0].Telemetry, &telemetry) != nil {
		t.Fatal("valid telemetry fixture unavailable")
	}
	telemetry.DeviceID, telemetry.CollectedAt = device, collectedAt
	payload, err := json.Marshal(telemetry)
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func setMeshTestPayload(e *contracts.EvidenceEnvelopeV1, payload []byte) {
	digest := sha256.Sum256(payload)
	e.PayloadBase64, e.PayloadSHA256 = base64.StdEncoding.EncodeToString(payload), hex.EncodeToString(digest[:])
}

func signMeshTestEvidence(t *testing.T, e *contracts.EvidenceEnvelopeV1, key ed25519.PrivateKey) {
	t.Helper()
	message, err := e.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = hex.EncodeToString(ed25519.Sign(key, message))
}

type meshSecurityEvent struct {
	Level           string `json:"level"`
	Msg             string `json:"msg"`
	Event           string `json:"event"`
	Reason          string `json:"reason"`
	Peer            string `json:"peer"`
	DeviceID        string `json:"device_id"`
	ClaimedDeviceID string `json:"claimed_device_id"`
}

func TestEvidenceVerificationRejectsBeforeIngestion(t *testing.T) {
	bed := newEnrollmentTestBed(t)
	a, b := enrollMeshTestDevice(t, bed, "device:a"), enrollMeshTestDevice(t, bed, "device:b")
	var logs bytes.Buffer
	node := &meshTestNode{}
	server := MeshHTTPServer(MeshConfig{Node: node, Repository: bed.repo, Logger: slog.New(slog.NewJSONHandler(&logs, nil)), Now: bed.clock.Now})
	deployment := bed.repo.deploymentID

	evidence := func(d meshTestDevice, issuedAt time.Time) contracts.EvidenceEnvelopeV1 {
		e := contracts.EvidenceEnvelopeV1{EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: deployment, DeviceID: d.id, SigningKeyID: d.keyID, Sequence: contracts.FirstEvidenceSequenceV1, IssuedAt: issuedAt.Format(time.RFC3339), ExpiresAt: issuedAt.Add(time.Hour).Format(time.RFC3339)}, PayloadSchemaVersion: contracts.TelemetryV2Version}
		setMeshTestPayload(&e, meshTestTelemetry(t, d.id, bed.clock.Now()))
		signMeshTestEvidence(t, &e, d.signing)
		return e
	}
	durableState := func() (samples int, marks [2]uint64) {
		t.Helper()
		if err := bed.db.QueryRow(`SELECT count(*) FROM device_evidence`).Scan(&samples); err != nil {
			t.Fatal(err)
		}
		for i, d := range []meshTestDevice{a, b} {
			if err := bed.db.QueryRow(`SELECT last_sequence FROM device_enrollments WHERE device_id=$1`, d.id).Scan(&marks[i]); err != nil {
				t.Fatal(err)
			}
		}
		return samples, marks
	}
	send := func(peer string, e contracts.EvidenceEnvelopeV1) (int, []meshSecurityEvent) {
		t.Helper()
		logs.Reset()
		node.disconnected = false
		data, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "/v1/evidence", bytes.NewReader(data))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, peer))
		w := httptest.NewRecorder()
		server.Handler.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("evidence response can be cached")
		}
		if e.Signature != "" && strings.Contains(logs.String(), e.Signature) || strings.Contains(logs.String(), e.PayloadBase64) {
			t.Fatal("security event disclosed signature or payload")
		}
		var events []meshSecurityEvent
		for _, line := range bytes.Split(bytes.TrimSpace(logs.Bytes()), []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			var event meshSecurityEvent
			if err := json.Unmarshal(line, &event); err != nil {
				t.Fatal(err)
			}
			events = append(events, event)
		}
		return w.Code, events
	}

	unrelated := newEnrollmentKeys(t)
	unknownPeer := hex.EncodeToString(unrelated.networkPublic[:])
	issued := bed.clock.Now()
	cases := []struct {
		name, peer, reason, deviceID string
		status                       int
		advance                      time.Duration
		envelope                     func() contracts.EvidenceEnvelopeV1
	}{
		{name: "forged", peer: a.peer, reason: contracts.EnvelopeRejectionInvalidSignature, deviceID: a.id, status: 409, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			signMeshTestEvidence(t, &e, unrelated.signing)
			return e
		}},
		{name: "altered payload with recomputed digest", peer: a.peer, reason: contracts.EnvelopeRejectionInvalidSignature, deviceID: a.id, status: 409, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			setMeshTestPayload(&e, meshTestTelemetry(t, a.id, issued.Add(-time.Minute)))
			return e
		}},
		{name: "altered payload with stale digest", peer: a.peer, reason: contracts.EnvelopeRejectionInvalidPayload, deviceID: a.id, status: 400, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			e.PayloadBase64 = base64.StdEncoding.EncodeToString(meshTestTelemetry(t, a.id, issued.Add(-time.Minute)))
			return e
		}},
		{name: "wrong key", peer: a.peer, reason: contracts.EnvelopeRejectionKeyMismatch, deviceID: a.id, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			e.SigningKeyID = b.keyID
			signMeshTestEvidence(t, &e, b.signing)
			return e
		}},
		{name: "misbound peer", peer: b.peer, reason: contracts.EnvelopeRejectionUnauthorizedPeer, deviceID: b.id, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 { return evidence(a, issued) }},
		{name: "unknown peer", peer: unknownPeer, reason: contracts.EnvelopeRejectionUnauthorizedPeer, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 { return evidence(a, issued) }},
		{name: "expired", peer: a.peer, reason: contracts.EnvelopeRejectionExpired, deviceID: a.id, status: 409, advance: time.Hour, envelope: func() contracts.EvidenceEnvelopeV1 { return evidence(a, issued) }},
		{name: "future timestamp", peer: a.peer, reason: contracts.EnvelopeRejectionFutureTimestamp, deviceID: a.id, status: 409, envelope: func() contracts.EvidenceEnvelopeV1 {
			return evidence(a, issued.Add(contracts.EnvelopeMaxFutureSkewV1+time.Second))
		}},
		{name: "wrong schema version", peer: a.peer, reason: contracts.EnvelopeRejectionInvalidPayload, deviceID: a.id, status: 400, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			e.SchemaVersion = "device-audit.evidence.v2"
			return e
		}},
		{name: "wrong deployment", peer: a.peer, reason: contracts.EnvelopeRejectionDeploymentMismatch, deviceID: a.id, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			e.DeploymentID = "deployment:other"
			signMeshTestEvidence(t, &e, a.signing)
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			samples, marks := durableState()
			e := tc.envelope()
			bed.clock.Advance(tc.advance)
			status, events := send(tc.peer, e)
			bed.clock.Advance(-tc.advance)
			if status != tc.status {
				t.Fatalf("status=%d want %d", status, tc.status)
			}
			if len(events) != 1 {
				t.Fatalf("security events=%d want 1", len(events))
			}
			got, claimed := events[0], e.DeviceID
			if tc.deviceID == "" {
				claimed = "" // The envelope is never decoded for an unadmitted peer.
			}
			if got.Msg != "evidence rejected" || got.Level != "WARN" || got.Event != "evidence_rejected" || got.Reason != tc.reason || got.Peer != tc.peer || got.DeviceID != tc.deviceID || got.ClaimedDeviceID != claimed {
				t.Fatalf("security event=%+v", got)
			}
			if node.disconnected != (tc.deviceID == "") {
				t.Fatalf("disconnected=%v", node.disconnected)
			}
			if gotSamples, gotMarks := durableState(); gotSamples != samples || gotMarks != marks {
				t.Fatalf("durable state changed: samples=%d marks=%v", gotSamples, gotMarks)
			}
		})
	}

	status, events := send(a.peer, evidence(a, issued))
	samples, marks := durableState()
	if status != http.StatusNoContent || len(events) != 0 || samples != 1 || marks != [2]uint64{contracts.FirstEvidenceSequenceV1, contracts.EnrollmentSequenceV1} {
		t.Fatalf("valid evidence status=%d events=%d samples=%d marks=%v", status, len(events), samples, marks)
	}
}
