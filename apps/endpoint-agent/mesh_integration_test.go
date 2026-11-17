package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestEndpointMeshProcess(t *testing.T) {
	path := os.Getenv("DEVICE_AUDIT_TEST_MESH_DIR")
	if path == "" {
		t.Skip("subprocess entry")
	}
	var cfg struct{ Pin, Region, AckKey, Out string }
	d := json.NewDecoder(os.Stdin)
	var envelope json.RawMessage
	if d.Decode(&cfg) != nil || d.Decode(&envelope) != nil {
		t.Fatal("private config failed")
	}
	controllerKey, err := hex.DecodeString(cfg.AckKey)
	if err != nil {
		t.Fatal("decode pinned acknowledgement key")
	}
	// A rejected acknowledgement is verified and recorded; only an unverified answer fails.
	ack, err := sendMeshEvidence(context.Background(), path, cfg.Pin, controllerKey, cfg.Region, bytes.NewReader(envelope))
	if ack.Signature == "" {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(ack)
	if os.WriteFile(cfg.Out, encoded, 0o600) != nil {
		t.Fatal("write acknowledgement")
	}
}

// This continues actual TLS enrollment through persisted endpoint state, a fresh
// endpoint process, Tailcat, the real HTTP handler and PostgreSQL evidence storage.
func endpointMeshRoundTrip(t *testing.T, repo *controller.PostgresRepository, path string, i *identity, receipt contracts.EnrollmentAcceptedV1) {
	t.Helper()
	ctx := context.Background()
	d := derpserver.New(key.NewNode(), func(string, ...any) {})
	defer d.Close()
	h := httptest.NewTLSServer(derpserver.Handler(d))
	defer h.Close()
	region := &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "loopback", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: h.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	regionData, _ := json.Marshal(region)
	regionPath := filepath.Join(t.TempDir(), "region.json")
	if os.WriteFile(regionPath, regionData, 0600) != nil {
		t.Fatal("write region config")
	}
	dir := filepath.Join(t.TempDir(), "controller")
	if err := mesh.InitializeServer(dir); err != nil {
		t.Fatal(err)
	}
	pin, err := mesh.ServerPublicKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile("../../packages/contracts/fixtures/telemetry/v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	// Only the first, valid vector is decoded; later vectors are deliberately malformed.
	var raw struct {
		Vectors []struct{ Telemetry json.RawMessage }
	}
	if json.Unmarshal(fixture, &raw) != nil || len(raw.Vectors) == 0 {
		t.Fatal("telemetry fixture unavailable")
	}
	var telemetry contracts.TelemetryV2
	if json.Unmarshal(raw.Vectors[0].Telemetry, &telemetry) != nil {
		t.Fatal("decode valid telemetry fixture")
	}
	telemetry.DeviceID = receipt.DeviceID
	telemetry.CollectedAt = time.Now().UTC().Truncate(time.Second)
	payload, _ := json.Marshal(telemetry)
	digest := sha256.Sum256(payload)
	_, ackKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ackPublic := ackKey.Public().(ed25519.PublicKey)
	envelope := contracts.EvidenceEnvelopeV1{EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID, Sequence: 2, IssuedAt: telemetry.CollectedAt.Format(time.RFC3339), ExpiresAt: telemetry.CollectedAt.Add(time.Hour).Format(time.RFC3339)}, PayloadSchemaVersion: contracts.TelemetryV2Version, PayloadBase64: base64.StdEncoding.EncodeToString(payload), PayloadSHA256: hex.EncodeToString(digest[:])}
	// Phase 0 sends sequence 2. After a server and client restart, phase 1
	// replays sequence 2 and then sends sequence 3.
	for phase := 0; phase < 2; phase++ {
		node, err := mesh.NewServer(mesh.ServerConfig{Context: ctx, StateDir: dir, DERP: mesh.DERPConfig{Region: region}, Allow: func(peer string) bool { _, err := repo.NetworkPeerBinding(ctx, peer); return err == nil }})
		if err != nil {
			t.Fatal(err)
		}
		ln, err := node.Listen(ctx, "tcp", ":8080")
		if err != nil {
			node.Close()
			t.Fatal(err)
		}
		server, err := controller.MeshHTTPServer(controller.MeshConfig{Node: node, Repository: repo, AcknowledgementKey: ackKey})
		if err != nil {
			node.Close()
			t.Fatal(err)
		}
		go server.Serve(ln)
		if phase == 0 {
			s, err := openIdentityStore(path, false)
			if err != nil {
				t.Fatal(err)
			}
			err = s.write("mesh-address", []byte(node.Addr()))
			s.close()
			if err != nil {
				t.Fatal(err)
			}
		}
		sequences := map[int][]uint64{0: {2}, 1: {2, 3}}[phase]
		for _, sequence := range sequences {
			envelope.Sequence = sequence
			canonical, err := envelope.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			envelope.Signature = hex.EncodeToString(ed25519.Sign(i.signing, canonical))
			ack := runEndpointMeshProcess(t, path, pin, regionPath, ackPublic, envelope)
			if err := ack.VerifyForEvidence(ackPublic, envelope); err != nil {
				t.Fatalf("acknowledgement does not answer sequence %d: %v", sequence, err)
			}
			replayed := phase == 1 && sequence == 2
			switch {
			case replayed && (ack.Status != "rejected" || *ack.RejectionReason != contracts.EnvelopeRejectionReplay || *ack.LastSequence != 2):
				t.Fatalf("replay across restart answered %s", ack.Status)
			case !replayed && (ack.Status != "accepted" || *ack.LastSequence != sequence):
				t.Fatalf("sequence %d answered %s", sequence, ack.Status)
			}
		}
		server.Close()
		node.Close()
		stored, err := repo.Evidence(ctx, receipt.DeviceID, envelope.Sequence)
		if err != nil || !bytes.Equal(stored.PayloadBytes, payload) || stored.Envelope.VerifySignature(i.signing.Public().(ed25519.PublicKey)) != nil {
			t.Fatal("committed mesh evidence differs")
		}
	}
	t.Log("TLS enrollment -> protected endpoint state -> fresh process -> admitted Tailcat -> PostgreSQL evidence -> verified signed acknowledgement passed before and after server/client restart, including a signed replay rejection")
}

// runEndpointMeshProcess submits one envelope from a fresh endpoint process and
// returns the acknowledgement that process verified against the pinned key.
func runEndpointMeshProcess(t *testing.T, path, pin, regionPath string, ackKey ed25519.PublicKey, envelope contracts.EvidenceEnvelopeV1) contracts.AcknowledgementV1 {
	t.Helper()
	out := filepath.Join(t.TempDir(), "ack.json")
	encoded, _ := json.Marshal(envelope)
	var input bytes.Buffer
	_ = json.NewEncoder(&input).Encode(struct{ Pin, Region, AckKey, Out string }{pin, regionPath, hex.EncodeToString(ackKey), out})
	input.Write(encoded)
	command := exec.Command(os.Args[0], "-test.run=^TestEndpointMeshProcess$", "-test.timeout=25s")
	command.Env = []string{"DEVICE_AUDIT_TEST_MESH_DIR=" + path, "PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
	command.Stdin = &input
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	if err := command.Run(); err != nil {
		t.Fatal("fresh endpoint failed mesh evidence submission; private output suppressed")
	}
	data, err := os.ReadFile(out)
	var ack contracts.AcknowledgementV1
	if err != nil || json.Unmarshal(data, &ack) != nil {
		t.Fatal("endpoint recorded no acknowledgement")
	}
	return ack
}
