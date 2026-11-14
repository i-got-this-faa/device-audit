package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

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
	binding  DeviceNetworkBinding
	denied   bool
	accepted int
	err      error
}

func (r *meshTestRepository) NetworkPeerBinding(context.Context, string) (DeviceNetworkBinding, error) {
	if r.denied {
		return DeviceNetworkBinding{}, errors.New("unavailable")
	}
	return r.binding, nil
}
func (r *meshTestRepository) AcceptEvidence(_ context.Context, e contracts.EvidenceEnvelopeV1) error {
	if e.VerifySignature(repositoryFixtureKey().Public().(ed25519.PublicKey)) != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidSignature}
	}
	if r.err != nil {
		return r.err
	}
	r.accepted++
	return nil
}

func TestMeshHTTPAdmissionAndBoundary(t *testing.T) {
	_, envelope := repositoryEnvelopes(t)
	node := &meshTestNode{peer: "peer"}
	repo := &meshTestRepository{binding: DeviceNetworkBinding{DeploymentID: envelope.DeploymentID, DeviceID: envelope.DeviceID, SigningKeyID: envelope.SigningKeyID, NetworkPublicKey: node.peer}}
	s := MeshHTTPServer(node, repo)
	request := func(path string, e contracts.EvidenceEnvelopeV1) int {
		data, _ := json.Marshal(e)
		r := httptest.NewRequest("POST", path, bytes.NewReader(data))
		r = r.WithContext(context.WithValue(r.Context(), meshPeerContextKey{}, node.peer))
		w := httptest.NewRecorder()
		s.Handler.ServeHTTP(w, r)
		return w.Code
	}
	if got := request("/v1/evidence", envelope); got != 204 || repo.accepted != 1 {
		t.Fatalf("valid peer status=%d accepted=%d", got, repo.accepted)
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
	repo.err = ErrRepositoryUnavailable
	if got := request("/v1/evidence", envelope); got != 503 {
		t.Fatalf("uncertain storage status=%d", got)
	}
	repo.denied = true
	if got := request("/v1/evidence", envelope); got != 403 || !node.disconnected {
		t.Fatalf("revoked/unavailable status=%d disconnect=%v", got, node.disconnected)
	}
	if repo.accepted != 1 {
		t.Fatal("denial mutated evidence")
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
