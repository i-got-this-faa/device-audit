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
	"github.com/i-got-this-faa/device-audit/packages/federated"
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
	binding    DeviceNetworkBinding
	denied     bool
	bindingErr error
	calls      int
	err        error
}

func (r *meshTestRepository) NetworkPeerBinding(context.Context, string) (DeviceNetworkBinding, error) {
	if r.bindingErr != nil {
		return DeviceNetworkBinding{}, r.bindingErr
	}
	if r.denied {
		return DeviceNetworkBinding{}, errors.New("unavailable")
	}
	return r.binding, nil
}
func (r *meshTestRepository) AcceptEvidence(_ context.Context, e contracts.EvidenceEnvelopeV1) (time.Time, error) {
	r.calls++
	issued, _ := time.Parse(time.RFC3339, e.IssuedAt)
	return issued, r.err
}

// meshTestAckKey is a test-only controller acknowledgement key.
var meshTestAckKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x89}, ed25519.SeedSize))

func newMeshTestServer(t *testing.T, cfg MeshConfig) *http.Server {
	t.Helper()
	cfg.AcknowledgementKey = meshTestAckKey
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	s, err := MeshHTTPServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// recordMeshEvidence serves one request as the given tunnel peer. It does not
// use testing.T, so concurrent goroutines may call it.
func recordMeshEvidence(s *http.Server, peer string, e contracts.EvidenceEnvelopeV1) *httptest.ResponseRecorder {
	data, _ := json.Marshal(e)
	r := httptest.NewRequest(http.MethodPost, "/v1/evidence", bytes.NewReader(data))
	r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, peer))
	w := httptest.NewRecorder()
	s.Handler.ServeHTTP(w, r)
	return w
}

// meshAcknowledgement returns the response's acknowledgement, if any, after
// checking it with the endpoint's pinned-key correlation rule.
func meshAcknowledgement(t *testing.T, w *httptest.ResponseRecorder, e contracts.EvidenceEnvelopeV1) *contracts.AcknowledgementV1 {
	t.Helper()
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("evidence response can be cached")
	}
	if w.Header().Get("Content-Type") != "application/json" {
		return nil
	}
	var ack contracts.AcknowledgementV1
	if err := json.Unmarshal(w.Body.Bytes(), &ack); err != nil {
		t.Fatalf("acknowledgement body: %v", err)
	}
	if err := ack.VerifyForEvidence(meshTestAckKey.Public().(ed25519.PublicKey), e); err != nil {
		t.Fatalf("acknowledgement does not verify for its request: %v", err)
	}
	return &ack
}

func serveMeshEvidence(t *testing.T, s *http.Server, peer string, e contracts.EvidenceEnvelopeV1) (int, *contracts.AcknowledgementV1) {
	t.Helper()
	w := recordMeshEvidence(s, peer, e)
	return w.Code, meshAcknowledgement(t, w, e)
}

func TestMeshHTTPServerRequiresAcknowledgementKey(t *testing.T) {
	if _, err := MeshHTTPServer(MeshConfig{Node: &meshTestNode{}, Repository: &meshTestRepository{}}); err == nil {
		t.Fatal("mesh evidence server started without an acknowledgement key")
	}
}

func TestMeshHTTPAdmissionAndBoundary(t *testing.T) {
	_, envelope := repositoryEnvelopes(t)
	now, err := time.Parse(time.RFC3339, envelope.IssuedAt)
	if err != nil {
		t.Fatal(err)
	}
	node := &meshTestNode{peer: "peer"}
	repo := &meshTestRepository{binding: DeviceNetworkBinding{DeploymentID: envelope.DeploymentID, DeviceID: envelope.DeviceID, SigningKeyID: envelope.SigningKeyID, SigningPublicKey: repositoryFixtureKey().Public().(ed25519.PublicKey), NetworkPublicKey: node.peer}}
	s := newMeshTestServer(t, MeshConfig{Node: node, Repository: repo, Now: func() time.Time { return now }})
	request := func(path string, e contracts.EvidenceEnvelopeV1) int {
		data, _ := json.Marshal(e)
		r := httptest.NewRequest("POST", path, bytes.NewReader(data))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, node.peer))
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, r)
		return w.Code
	}
	if got, ack := serveMeshEvidence(t, s, node.peer, envelope); got != 200 || ack == nil || ack.Status != "accepted" || ack.ReceivedAt != envelope.IssuedAt || repo.calls != 1 {
		t.Fatalf("valid peer status=%d ack=%+v calls=%d", got, ack, repo.calls)
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
	repo.bindingErr = ErrRepositoryUnavailable
	if got, ack := serveMeshEvidence(t, s, node.peer, envelope); got != http.StatusServiceUnavailable || ack != nil {
		t.Fatalf("temporary admission failure status=%d ack=%+v", got, ack)
	}
	repo.bindingErr = nil
	if got, ack := serveMeshEvidence(t, s, node.peer, envelope); got != 503 || ack != nil || repo.calls != 2 {
		t.Fatalf("uncertain storage status=%d signed=%v calls=%d", got, ack != nil, repo.calls)
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
	server := newMeshTestServer(t, MeshConfig{Node: node, Repository: bed.repo, Logger: slog.New(slog.NewJSONHandler(&logs, nil)), Now: bed.clock.Now})
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
	send := func(peer string, e contracts.EvidenceEnvelopeV1) (int, *contracts.AcknowledgementV1, []meshSecurityEvent) {
		t.Helper()
		logs.Reset()
		node.disconnected = false
		status, ack := serveMeshEvidence(t, server, peer, e)
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
		return status, ack, events
	}

	unrelated := newEnrollmentKeys(t)
	unknownPeer := hex.EncodeToString(unrelated.networkPublic[:])
	issued := bed.clock.Now()
	cases := []struct {
		name, peer, reason, deviceID string
		status                       int
		signed                       bool // a correlatable request naming the peer's own device
		advance                      time.Duration
		envelope                     func() contracts.EvidenceEnvelopeV1
	}{
		{name: "forged", signed: true, peer: a.peer, reason: contracts.EnvelopeRejectionInvalidSignature, deviceID: a.id, status: 409, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			signMeshTestEvidence(t, &e, unrelated.signing)
			return e
		}},
		{name: "altered payload with recomputed digest", signed: true, peer: a.peer, reason: contracts.EnvelopeRejectionInvalidSignature, deviceID: a.id, status: 409, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			setMeshTestPayload(&e, meshTestTelemetry(t, a.id, issued.Add(-time.Minute)))
			return e
		}},
		{name: "altered payload with stale digest", signed: true, peer: a.peer, reason: contracts.EnvelopeRejectionInvalidPayload, deviceID: a.id, status: 400, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			e.PayloadBase64 = base64.StdEncoding.EncodeToString(meshTestTelemetry(t, a.id, issued.Add(-time.Minute)))
			return e
		}},
		{name: "wrong key", signed: true, peer: a.peer, reason: contracts.EnvelopeRejectionKeyMismatch, deviceID: a.id, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 {
			e := evidence(a, issued)
			e.SigningKeyID = b.keyID
			signMeshTestEvidence(t, &e, b.signing)
			return e
		}},
		{name: "misbound peer", peer: b.peer, reason: contracts.EnvelopeRejectionUnauthorizedPeer, deviceID: b.id, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 { return evidence(a, issued) }},
		{name: "unknown peer", peer: unknownPeer, reason: contracts.EnvelopeRejectionUnauthorizedPeer, status: 403, envelope: func() contracts.EvidenceEnvelopeV1 { return evidence(a, issued) }},
		{name: "expired", signed: true, peer: a.peer, reason: contracts.EnvelopeRejectionExpired, deviceID: a.id, status: 409, advance: time.Hour, envelope: func() contracts.EvidenceEnvelopeV1 { return evidence(a, issued) }},
		{name: "future timestamp", signed: true, peer: a.peer, reason: contracts.EnvelopeRejectionFutureTimestamp, deviceID: a.id, status: 409, envelope: func() contracts.EvidenceEnvelopeV1 {
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
			status, ack, events := send(tc.peer, e)
			bed.clock.Advance(-tc.advance)
			if status != tc.status {
				t.Fatalf("status=%d want %d", status, tc.status)
			}
			if (ack != nil) != tc.signed {
				t.Fatalf("signed acknowledgement=%v want %v", ack != nil, tc.signed)
			}
			if ack != nil && (ack.Status != "rejected" || *ack.RejectionReason != tc.reason || ack.LastSequence != nil) {
				t.Fatalf("rejection acknowledgement=%+v", ack)
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

	status, ack, events := send(a.peer, evidence(a, issued))
	samples, marks := durableState()
	if status != http.StatusOK || ack == nil || ack.Status != "accepted" || len(events) != 0 || samples != 1 || marks != [2]uint64{contracts.FirstEvidenceSequenceV1, contracts.EnrollmentSequenceV1} {
		t.Fatalf("valid evidence status=%d events=%d samples=%d marks=%v", status, len(events), samples, marks)
	}
}

type meshTestUpdateRepo struct {
	*meshTestRepository
	created bool
	err     error
	calls   int
}

func (r *meshTestUpdateRepo) AcceptUpdate(_ context.Context, u contracts.FederatedUpdateV1) (federated.AcceptedUpdate, bool, error) {
	r.calls++
	if r.err != nil {
		return federated.AcceptedUpdate{}, false, r.err
	}
	return federated.AcceptedUpdate{
		DeploymentID: u.DeploymentID,
		RoundID:      u.RoundID,
		CandidateID:  u.CandidateID,
		DeviceID:     u.DeviceID,
		Sequence:     u.Sequence,
		AcceptedAt:   time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC),
	}, r.created, nil
}

func TestMeshHTTPFederatedUpdateBoundary(t *testing.T) {
	key := repositoryFixtureKey()
	keyID, err := contracts.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	issued := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
	weights := []byte{0x3f, 0xd0, 0, 0, 0, 0, 0, 0, 0xbf, 0xe0, 0, 0, 0, 0, 0, 0}
	sum := sha256.Sum256(weights)
	update := contracts.FederatedUpdateV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.FederatedUpdateV1Version,
			DeploymentID:  "deployment:mesh",
			DeviceID:      "device:mesh",
			SigningKeyID:  keyID,
			Sequence:      contracts.FirstEvidenceSequenceV1,
			IssuedAt:      issued.Format(time.RFC3339),
			ExpiresAt:     issued.Add(time.Hour).Format(time.RFC3339),
		},
		RoundID:          "round:1",
		BaseModelVersion: "baseline.1",
		BaseModelSHA256:  strings.Repeat("a", 64),
		CandidateID:      "candidate:1",
		FeatureVersion:   contracts.FeatureVersionHDDSMART7DV1,
		SampleCount:      24,
		WeightsBase64:    base64.StdEncoding.EncodeToString(weights),
		UpdateSHA256:     hex.EncodeToString(sum[:]),
	}
	signing, err := update.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	update.Signature = hex.EncodeToString(ed25519.Sign(key, signing))

	node := &meshTestNode{peer: "peer:mesh"}
	baseRepo := &meshTestRepository{binding: DeviceNetworkBinding{
		DeploymentID:     update.DeploymentID,
		DeviceID:         update.DeviceID,
		SigningKeyID:     update.SigningKeyID,
		SigningPublicKey: key.Public().(ed25519.PublicKey),
		NetworkPublicKey: node.peer,
	}}
	// Without FederatedUpdateRepository support, fail closed with 503.
	noUpdateSrv := newMeshTestServer(t, MeshConfig{Node: node, Repository: baseRepo, Now: func() time.Time { return issued }})
	sendRaw := func(srv *http.Server, target, peer string, raw []byte) int {
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(raw))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, peer))
		w := httptest.NewRecorder()
		srv.Handler.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("missing Cache-Control: no-store")
		}
		return w.Code
	}
	encoded, _ := json.Marshal(update)
	if got := sendRaw(noUpdateSrv, "/v1/federated/updates", node.peer, encoded); got != http.StatusServiceUnavailable {
		t.Fatalf("unsupported repo status=%d want 503", got)
	}

	repo := &meshTestUpdateRepo{meshTestRepository: baseRepo, created: true}
	srv := newMeshTestServer(t, MeshConfig{Node: node, Repository: repo, Now: func() time.Time { return issued }})
	if got := sendRaw(srv, "/v1/federated/updates", node.peer, encoded); got != http.StatusCreated {
		t.Fatalf("valid update status=%d want 201", got)
	}
	repo.created = false
	if got := sendRaw(srv, "/v1/federated/updates", node.peer, encoded); got != http.StatusOK {
		t.Fatalf("repeat update status=%d want 200", got)
	}
	if got := sendRaw(srv, "/v1/federated/updates?extra=1", node.peer, encoded); got != http.StatusBadRequest {
		t.Fatalf("query string status=%d want 400", got)
	}
	oversized := append([]byte(`{"pad":"`), bytes.Repeat([]byte("a"), 65<<10)...)
	oversized = append(oversized, []byte(`"}`)...)
	if got := sendRaw(srv, "/v1/federated/updates", node.peer, oversized); got != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status=%d want 413", got)
	}
	if got := sendRaw(srv, "/v1/federated/updates", "peer:other", encoded); got != http.StatusForbidden {
		t.Fatalf("wrong peer status=%d want 403", got)
	}
	repo.err = federated.ErrUpdateConflict
	if got := sendRaw(srv, "/v1/federated/updates", node.peer, encoded); got != http.StatusConflict {
		t.Fatalf("conflict status=%d want 409", got)
	}
	repo.err = nil
	if repo.calls != 3 {
		t.Fatalf("repository calls=%d want 3 (malformed/unauthenticated stopped before repo)", repo.calls)
	}
}
