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
	var cfg struct{ Pin, Region string }
	d := json.NewDecoder(os.Stdin)
	var envelope json.RawMessage
	if d.Decode(&cfg) != nil || d.Decode(&envelope) != nil {
		t.Fatal("private config failed")
	}
	if err := sendMeshEvidence(context.Background(), path, cfg.Pin, cfg.Region, bytes.NewReader(envelope)); err != nil {
		t.Fatal(err)
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
	envelope := contracts.EvidenceEnvelopeV1{EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{SchemaVersion: contracts.EvidenceEnvelopeV1Version, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID, Sequence: 2, IssuedAt: telemetry.CollectedAt.Format(time.RFC3339), ExpiresAt: telemetry.CollectedAt.Add(time.Hour).Format(time.RFC3339)}, PayloadSchemaVersion: contracts.TelemetryV2Version, PayloadBase64: base64.StdEncoding.EncodeToString(payload), PayloadSHA256: hex.EncodeToString(digest[:])}
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
		server := controller.MeshHTTPServer(node, repo)
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
		envelope.Sequence = uint64(phase + 2)
		canonical, err := envelope.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		envelope.Signature = hex.EncodeToString(ed25519.Sign(i.signing, canonical))
		encoded, _ := json.Marshal(envelope)
		var input bytes.Buffer
		_ = json.NewEncoder(&input).Encode(struct{ Pin, Region string }{pin, regionPath})
		input.Write(encoded)
		command := exec.Command(os.Args[0], "-test.run=^TestEndpointMeshProcess$", "-test.timeout=25s")
		command.Env = []string{"DEVICE_AUDIT_TEST_MESH_DIR=" + path, "PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir()}
		command.Stdin = &input
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		err = command.Run()
		server.Close()
		node.Close()
		if err != nil {
			t.Fatal("fresh endpoint failed mesh evidence submission; private output suppressed")
		}
		stored, err := repo.Evidence(ctx, receipt.DeviceID, envelope.Sequence)
		if err != nil || !bytes.Equal(stored.PayloadBytes, payload) || stored.Envelope.VerifySignature(i.signing.Public().(ed25519.PublicKey)) != nil {
			t.Fatal("committed mesh evidence differs")
		}
	}
	t.Log("TLS enrollment -> protected endpoint state -> fresh process -> admitted Tailcat -> PostgreSQL evidence passed before and after server/client restart")
}
