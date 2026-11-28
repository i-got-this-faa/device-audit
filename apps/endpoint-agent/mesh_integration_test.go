package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestEndpointMeshProcess(t *testing.T) {
	if config := os.Getenv("DEVICE_AUDIT_TEST_DRAIN_CONFIG"); config != "" {
		flag.CommandLine = flag.NewFlagSet("endpoint-agent", flag.ExitOnError)
		os.Args = []string{os.Args[0], "--spool-drain", "--service-config", config}
		main()
		return
	}
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
func endpointMeshRoundTrip(t *testing.T, repo *controller.PostgresRepository, db *sql.DB, path string, i *identity, receipt contracts.EnrollmentAcceptedV1) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	d := derpserver.New(key.NewNode(), func(string, ...any) {})
	defer d.Close()
	h := httptest.NewTLSServer(derpserver.Handler(d))
	defer h.Close()
	region := &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "loopback", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: h.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	dir := t.TempDir()
	regionPath := filepath.Join(dir, "region.json")
	writeJSON(t, regionPath, region)
	controllerDir := filepath.Join(dir, "controller")
	if err := mesh.InitializeServer(controllerDir); err != nil {
		t.Fatal(err)
	}
	pin, err := mesh.ServerPublicKey(controllerDir)
	if err != nil {
		t.Fatal(err)
	}
	ackPublic, ackKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(ackPublic)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "ack.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	start := func(repo *controller.PostgresRepository, dropReply chan<- []byte) (string, func()) {
		t.Helper()
		node, err := mesh.NewServer(mesh.ServerConfig{Context: ctx, StateDir: controllerDir, DERP: mesh.DERPConfig{Region: region}, Allow: func(peer string) bool { _, err := repo.NetworkPeerBinding(ctx, peer); return err == nil }})
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
		if dropReply != nil {
			controllerHandler := server.Handler
			server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				recorded := httptest.NewRecorder()
				controllerHandler.ServeHTTP(recorded, r)
				// Commit through the real controller, then close the HTTP
				// connection before any response reaches the endpoint.
				conn, _, err := http.NewResponseController(w).Hijack()
				if err != nil {
					t.Errorf("intercept committed reply: %v", err)
					return
				}
				conn.Close()
				select {
				case dropReply <- recorded.Body.Bytes():
				default:
				}
			})
		}
		go server.Serve(ln)
		return node.Addr(), func() { server.Close(); node.Close() }
	}

	lost := make(chan []byte, 1)
	addr, stop := start(repo, lost)
	defer func() {
		if stop != nil {
			stop()
		}
	}()
	cfg := testServiceConfig(t, path)
	cfg.Delivery = &deliveryConfig{MeshServerKey: pin, DERPRegionFile: regionPath, ControllerAckKeyFile: keyPath}
	configPath := filepath.Join(dir, "service.json")
	writeJSON(t, configPath, cfg)
	envelopes := func() []contracts.EvidenceEnvelopeV1 {
		store, err := openIdentityStore(path, false)
		if err != nil {
			t.Fatal(err)
		}
		defer store.close()
		if err := store.write("mesh-address", []byte(addr)); err != nil {
			t.Fatal(err)
		}
		s, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
		if err != nil {
			t.Fatal(err)
		}
		defer s.close()
		var queued []contracts.EvidenceEnvelopeV1
		for range 2 {
			e, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if err := s.append(e); err != nil {
				t.Fatal(err)
			}
			queued = append(queued, e)
		}
		return queued
	}()

	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestEndpointMeshProcess$")
	command.Env = append(os.Environ(), "DEVICE_AUDIT_TEST_DRAIN_CONFIG="+configPath)
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	var drainErr error
	done := make(chan struct{})
	go func() { drainErr = command.Wait(); close(done) }()
	defer func() { cancel(); <-done }()

	requireSamples := func(expected int) {
		t.Helper()
		var count int
		if err := db.QueryRowContext(ctx, "SELECT count(*) FROM device_evidence WHERE deployment_id=$1 AND device_id=$2", receipt.DeploymentID, receipt.DeviceID).Scan(&count); err != nil || count != expected {
			t.Fatalf("durable evidence count=%d, want %d, err=%v", count, expected, err)
		}
	}
	var firstAck contracts.AcknowledgementV1
	select {
	case data := <-lost:
		if err := json.Unmarshal(data, &firstAck); err != nil || firstAck.Status != "accepted" || firstAck.VerifyForEvidence(ackPublic, envelopes[0]) != nil {
			t.Fatal("withheld reply was not the accepted receipt for the head")
		}
	case <-done:
		t.Fatalf("spool drain ended before the first reply was lost: %v\n%s", drainErr, &output)
	case <-ctx.Done():
		t.Fatal("did not observe a committed reply")
	}
	requireSamples(1)
	for _, e := range envelopes {
		if _, err := os.Stat(filepath.Join(cfg.EvidenceDir, recordName(e.Sequence))); err != nil {
			t.Fatalf("head or next record disappeared without a reply: %v", err)
		}
	}
	stop()
	stop = nil
	repo, err = controller.NewPostgresRepository(ctx, db, controller.RepositoryConfig{DeploymentID: receipt.DeploymentID})
	if err != nil {
		t.Fatal(err)
	}
	_, stop = start(repo, nil)
	select {
	case <-done:
		if drainErr != nil {
			t.Fatalf("drain did not recover after restart: %v\n%s", drainErr, &output)
		}
	case <-ctx.Done():
		t.Fatal("did not drain after controller restart")
	}
	requireSamples(2)
	if !bytes.Contains(output.Bytes(), []byte("retry in")) {
		t.Fatal("lost reply did not exercise retry")
	}
	if err := runSpoolCommand(ctx, configPath, "", spoolShowHead, nil, io.Discard, io.Discard); !errors.Is(err, errEmptySpool) {
		t.Fatalf("drain left evidence queued: %v", err)
	}
	for _, e := range envelopes {
		stored, err := repo.Evidence(ctx, receipt.DeviceID, e.Sequence)
		if err != nil || stored.Envelope.Signature != e.Signature {
			t.Fatalf("stored sequence %d changed: %v", e.Sequence, err)
		}
	}
	recovered := runEndpointMeshProcess(t, path, pin, regionPath, ackPublic, envelopes[0])
	if recovered.Status != "accepted" || recovered.Signature != firstAck.Signature {
		t.Fatal("fresh endpoint did not receive the original signed receipt")
	}
	requireSamples(2)
	t.Log("Tailcat drain kept both records when the committed head reply was dropped, reconnected after controller restart, recovered the original receipt, then delivered the next record")

	// The same configuration lets the service send new snapshots without
	// an operator running the drain command after each append.
	serviceCtx, stopService := context.WithCancel(ctx)
	serviceDone := make(chan struct{})
	var serviceErr error
	serviceLog := &serviceLog{path: filepath.Join(cfg.EvidenceDir, serviceLogFile)}
	go func() {
		defer close(serviceDone)
		serviceErr = runServicePipeline(serviceCtx, cfg, cpuSource(new(atomic.Bool), false), serviceLog.printf)
	}()
	defer func() { stopService(); <-serviceDone }()
	next := envelopes[1].Sequence + 1
	waitFor(t, "the service to retire a new sample", 20*time.Second, func() bool {
		var retired contracts.EvidenceEnvelopeV1
		data, err := os.ReadFile(filepath.Join(cfg.EvidenceDir, spoolRetired))
		return err == nil && json.Unmarshal(data, &retired) == nil && retired.Sequence >= next
	})
	stopService()
	<-serviceDone
	if serviceErr != nil {
		t.Fatal(serviceErr)
	}
	if _, err := repo.Evidence(ctx, receipt.DeviceID, next); err != nil {
		t.Fatalf("service retired sequence %d without a stored sample: %v", next, err)
	}

	// Poll through the pinned mesh, finish during an outage, then recover the
	// controller's committed receipt after the first result response is lost.
	component := "storage:disk-0"
	request := workflows.AssignmentRequest{
		AssignmentID: "assignment:mesh-recovery", DeviceID: receipt.DeviceID,
		ProbeID:   contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &component},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 10, MaxOutputBytes: 128}, ExpiresInSeconds: 600,
	}
	assignment, created, err := repo.CreateDiagnosticAssignment(ctx, request, ackKey, workflows.Actor{
		Issuer: "https://id.example.test", Subject: "admin:recovery",
	})
	if err != nil || !created {
		t.Fatalf("create diagnostic: %v", err)
	}

	store, err := openIdentityStore(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		t.Fatal(err)
	}
	defer spool.close()
	sender, err := cfg.Delivery.sender(store, i)
	if err != nil {
		t.Fatal(err)
	}
	defer sender.close()
	probes := 0
	delivery := diagnosticDelivery{
		store: store, identity: i, receipt: receipt, authority: ackPublic, bootID: "boot:mesh",
		sequenceMu: new(sync.Mutex), transport: sender,
		runner: workflows.NewProbeRunner(func(context.Context, workflows.Request) ([]byte, error) {
			probes++
			stop()
			stop = nil
			return []byte(`{"mesh_fixture":true}`), nil
		}),
	}
	pollCtx, endPoll := context.WithTimeout(ctx, 20*time.Second)
	err = delivery.pollAndExecute(pollCtx, time.Now())
	endPoll()
	if err != nil || probes != 1 || delivery.job == nil {
		t.Fatalf("did not spool the offline completion: probes=%d, err=%v", probes, err)
	}
	original, err := delivery.job.result()
	if err != nil || original.CheckAssignment(assignment.SignedAssignment) != nil || original.State != "succeeded" {
		t.Fatalf("invalid offline result: %+v, %v", original, err)
	}
	offlineCtx, endOffline := context.WithTimeout(ctx, time.Second)
	err = sender.sendDiagnostic(offlineCtx, delivery.job)
	endOffline()
	if !errors.Is(err, errDeliveryRetry) {
		t.Fatalf("expected result transport to be offline: %v", err)
	}
	// In case sampling queued an older envelope before it stopped, drain it
	// through the same ordered service delivery path before faulting the result.
	_, stop = start(repo, nil)
	for {
		_, head, err := spool.head()
		if errors.Is(err, io.EOF) || (err == nil && head.Sequence > original.Sequence) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := delivery.step(ctx, spool, ackPublic, sender.send); err != nil {
			t.Fatal(err)
		}
	}
	stop()
	sender.resetOnRetry(errDeliveryRetry)
	diagnosticReply := make(chan []byte, 1)
	_, stop = start(repo, diagnosticReply)
	if err := sender.sendDiagnostic(ctx, delivery.job); !errors.Is(err, errDeliveryRetry) {
		t.Fatalf("lost diagnostic response should be retryable: %v", err)
	}
	select {
	case data := <-diagnosticReply:
		var ack workflows.ResultReceipt
		if json.Unmarshal(data, &ack) != nil || ack.Status != "accepted" || !ack.Created || ack.Sequence != original.Sequence {
			t.Fatalf("controller did not commit the first result: %+v", ack)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	stop()
	_, stop = start(repo, nil)
	if _, err := delivery.step(ctx, spool, ackPublic, sender.send); err != nil || delivery.job != nil || probes != 1 {
		t.Fatalf("did not retire the original diagnostic after retry: %v", err)
	}
	reported, err := repo.DiagnosticAssignment(ctx, request.AssignmentID)
	if err != nil || reported.Result == nil || reported.Result.Signature != original.Signature ||
		len(reported.Events) != 3 || len(reported.Result.Evidence) != 1 ||
		reported.Result.Evidence[0] != original.Evidence[0] {
		t.Fatalf("durable result lost its signature or evidence reference: %+v, %v", reported, err)
	}
	t.Log("diagnostic completed with the mesh down and retired after retrying a committed result whose reply was dropped")
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
