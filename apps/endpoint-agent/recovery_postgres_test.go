//go:build linux

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/networking/relay"
	"github.com/i-got-this-faa/device-audit/networking/relay/relaytest"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// NET03 #54. The scenario is opt-in because a long partition takes minutes.
// Run it with `make recovery-proof`.
const (
	recoveryProofEnv      = "DEVICE_AUDIT_RECOVERY_PROOF"
	recoveryPartitionEnv  = "DEVICE_AUDIT_RECOVERY_PARTITION"
	recoveryModesEnv      = "DEVICE_AUDIT_RECOVERY_MODES"
	recoveryControllerEnv = "DEVICE_AUDIT_RECOVERY_CONTROLLER"
	recoveryServiceEnv    = "DEVICE_AUDIT_RECOVERY_SERVICE"

	defaultRecoveryPartition = 90 * time.Second
	// recoveryLimit is the documented bound from restoring a path to the
	// whole backlog being stored: one capped retry delay, one relay preflight
	// timeout, one HTTP timeout and the Tailcat session setup.
	recoveryLimit = maxDeliveryBackoff + 30*time.Second
	// A held outage. Long enough for several failed attempts.
	shortOutage = 15 * time.Second
	// visibleLimit bounds how long a lost path takes to be logged as an
	// unavailable relay: the in-flight request's 15 s HTTP timeout, the 5 s
	// session teardown bound, a retry delay and the 10 s relay preflight.
	visibleLimit = 40 * time.Second
)

type recoveryControllerConfig struct {
	DatabaseURL  string
	DeploymentID string
	StateDir     string
	RegionFile   string
	AckKey       string // hex Ed25519 private key, test only
}

type recoveryControllerReport struct {
	Address  string
	RelayErr string
}

// TestRecoveryProcess is the child entry for the controller and the service.
func TestRecoveryProcess(t *testing.T) {
	switch {
	case os.Getenv(recoveryControllerEnv) != "":
		runRecoveryController(t, os.Getenv(recoveryControllerEnv))
	case os.Getenv(recoveryServiceEnv) != "":
		runRecoveryService(t, os.Getenv(recoveryServiceEnv))
	default:
		t.Skip("subprocess entry")
	}
}

// runRecoveryController mirrors the controller binary's mesh startup: the
// relay preflight is reported, not fatal, and the mesh HTTP boundary serves
// the PostgreSQL repository until the parent kills the process.
func runRecoveryController(t *testing.T, path string) {
	var cfg recoveryControllerConfig
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		t.Fatal("read controller config")
	}
	ctx := context.Background()
	db, err := database.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		t.Fatal("open database")
	}
	repo, err := controller.NewPostgresRepository(ctx, db, controller.RepositoryConfig{DeploymentID: cfg.DeploymentID})
	if err != nil {
		t.Fatal(err)
	}
	regionJSON, err := os.ReadFile(cfg.RegionFile)
	if err != nil {
		t.Fatal("read region")
	}
	region, err := mesh.DecodeRegion(regionJSON)
	if err != nil {
		t.Fatal(err)
	}
	report := recoveryControllerReport{}
	if err := mesh.CheckServerRelay(ctx, cfg.StateDir, mesh.DERPConfig{Region: region}); err != nil {
		report.RelayErr = err.Error()
	}
	node, err := mesh.NewServer(mesh.ServerConfig{Context: ctx, StateDir: cfg.StateDir, DERP: mesh.DERPConfig{Region: region}, Allow: func(peer string) bool {
		_, err := repo.NetworkPeerBinding(ctx, peer)
		return err == nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := mesh.WriteAddress(cfg.StateDir, node.Addr()); err != nil {
		t.Fatal(err)
	}
	ln, err := node.Listen(ctx, "tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(cfg.AckKey)
	if err != nil || len(raw) != ed25519.PrivateKeySize {
		t.Fatal("decode acknowledgement key")
	}
	server, err := controller.MeshHTTPServer(controller.MeshConfig{Node: node, Repository: repo, AcknowledgementKey: ed25519.PrivateKey(raw)})
	if err != nil {
		t.Fatal(err)
	}
	report.Address = node.Addr()
	if json.NewEncoder(os.Stdout).Encode(report) != nil {
		t.Fatal("report readiness")
	}
	// The parent ends this process with SIGKILL, like a crash. Any return
	// is unexpected; fail so the parent reports it instead of timing out.
	err = server.Serve(ln)
	t.Fatalf("controller mesh server stopped serving: %v", err)
}

// runRecoveryService runs the production service pipeline with fixture
// sensors and a log the parent reads. The parent ends it with SIGKILL.
func runRecoveryService(t *testing.T, path string) {
	var cfg serviceConfig
	data, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(data, &cfg) != nil {
		t.Fatal("read service config")
	}
	log := &serviceLog{path: filepath.Join(cfg.EvidenceDir, serviceLogFile)}
	err = runServicePipeline(context.Background(), cfg, cpuSource(new(atomic.Bool), false), log.printf)
	log.printf("service pipeline returned: %v", err)
	select {}
}

type recoveryProcess struct {
	cmd    *exec.Cmd
	done   chan struct{}
	killed atomic.Bool
	mu     sync.Mutex
	output strings.Builder // controller stdout after readiness
}

func (p *recoveryProcess) kill() {
	p.killed.Store(true)
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	<-p.done
}

// failure describes a process that exited without being killed, or "".
func (p *recoveryProcess) failure() string {
	if p == nil || p.killed.Load() {
		return ""
	}
	select {
	case <-p.done:
	default:
		return ""
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return fmt.Sprintf("controller exited unexpectedly (%v):\n%s", p.cmd.ProcessState, p.output.String())
}

type recoveryHarness struct {
	t            *testing.T
	ctx          context.Context
	db           *sql.DB
	deploymentID string
	deviceID     string
	env          []string
	controller   string // config path
	evidenceDir  string
	ctl          *recoveryProcess

	relayConfig relay.Config
	relayAddr   string
	admission   string
	admitted    []string
	relay       *relay.Relay
	relayDone   chan error
}

func (h *recoveryHarness) child(envName, config string, stdout *bytes.Buffer) *recoveryProcess {
	h.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRecoveryProcess$", "-test.timeout=0")
	cmd.Env = append([]string{envName + "=" + config, "PATH=" + os.Getenv("PATH"), "HOME=" + h.t.TempDir()}, h.env...)
	if stdout != nil {
		cmd.Stdout = stdout
	}
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	p := &recoveryProcess{cmd: cmd, done: make(chan struct{})}
	go func() { _ = cmd.Wait(); close(p.done) }()
	h.t.Cleanup(p.kill)
	return p
}

func (h *recoveryHarness) startController() (*recoveryProcess, recoveryControllerReport) {
	h.t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRecoveryProcess$", "-test.timeout=0")
	cmd.Env = append([]string{recoveryControllerEnv + "=" + h.controller, "PATH=" + os.Getenv("PATH"), "HOME=" + h.t.TempDir()}, h.env...)
	out, err := cmd.StdoutPipe()
	if err != nil {
		h.t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	p := &recoveryProcess{cmd: cmd, done: make(chan struct{})}
	reports := make(chan recoveryControllerReport, 1)
	go func() {
		var r recoveryControllerReport
		s := bufio.NewScanner(out)
		s.Buffer(make([]byte, 64<<10), 64<<10)
		for s.Scan() {
			if json.Unmarshal(s.Bytes(), &r) == nil && r.Address != "" {
				reports <- r
				break
			}
		}
		for s.Scan() {
			p.mu.Lock()
			p.output.Write(s.Bytes())
			p.output.WriteByte('\n')
			p.mu.Unlock()
		}
		_ = cmd.Wait()
		close(p.done)
	}()
	h.t.Cleanup(p.kill)
	select {
	case r := <-reports:
		h.ctl = p
		return p, r
	case <-p.done:
		h.t.Fatal("controller process exited before it was ready")
	case <-time.After(45 * time.Second):
		h.t.Fatal("controller process did not become ready")
	}
	return nil, recoveryControllerReport{}
}

func (h *recoveryHarness) startRelay() {
	h.t.Helper()
	r, err := relay.New(h.relayConfig)
	if err != nil {
		h.t.Fatal(err)
	}
	// The region file names a fixed port, so a restart rebinds the same one.
	var ln net.Listener
	for i := 0; ; i++ {
		ln, err = net.Listen("tcp", h.relayAddr)
		if err == nil {
			break
		}
		if i == 50 {
			h.t.Fatalf("rebind relay port: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	h.relay, h.relayDone = r, make(chan error, 1)
	go func() { h.relayDone <- r.Serve(ln) }()
}

func (h *recoveryHarness) stopRelay() {
	h.t.Helper()
	if h.relay == nil {
		return
	}
	h.relay.Close()
	if err := <-h.relayDone; err != nil {
		h.t.Errorf("relay serve: %v", err)
	}
	h.relay = nil
}

func (h *recoveryHarness) writeAdmission(keys ...string) {
	relaytest.WriteAdmission(h.t, h.admission, keys...)
}

type storedRange struct{ count, low, high uint64 }

func (h *recoveryHarness) stored() storedRange {
	h.t.Helper()
	var r storedRange
	if err := h.db.QueryRowContext(h.ctx, "SELECT count(*), coalesce(min(sequence),0), coalesce(max(sequence),0) FROM device_evidence WHERE deployment_id=$1 AND device_id=$2", h.deploymentID, h.deviceID).Scan(&r.count, &r.low, &r.high); err != nil {
		h.t.Fatal(err)
	}
	return r
}

// queued counts signed records waiting in the spool.
func (h *recoveryHarness) queued() int {
	h.t.Helper()
	files, err := filepath.Glob(filepath.Join(h.evidenceDir, "spool-*.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	return len(files)
}

func (h *recoveryHarness) serviceLog() string {
	data, _ := os.ReadFile(filepath.Join(h.evidenceDir, serviceLogFile))
	return string(data)
}

// waitStored waits until at least count rows exist and returns the elapsed time.
func (h *recoveryHarness) waitStored(what string, count uint64, timeout time.Duration) time.Duration {
	h.t.Helper()
	return h.waitFor(what, timeout, func() (uint64, uint64) { return h.stored().count, count })
}

// waitCollectedAfter waits for count rows whose samples were taken after since,
// so a delivery already in flight before since cannot satisfy it.
func (h *recoveryHarness) waitCollectedAfter(what string, since time.Time, count uint64, timeout time.Duration) time.Duration {
	h.t.Helper()
	return h.waitFor(what, timeout, func() (uint64, uint64) {
		var n uint64
		if err := h.db.QueryRowContext(h.ctx, "SELECT count(*) FROM device_evidence WHERE deployment_id=$1 AND device_id=$2 AND collected_at > $3", h.deploymentID, h.deviceID, since).Scan(&n); err != nil {
			h.t.Fatal(err)
		}
		return n, count
	})
}

// waitRange waits until every sequence in low..high is stored.
func (h *recoveryHarness) waitRange(what string, low, high uint64, timeout time.Duration) time.Duration {
	h.t.Helper()
	return h.waitFor(what, timeout, func() (uint64, uint64) {
		var n uint64
		if err := h.db.QueryRowContext(h.ctx, "SELECT count(*) FROM device_evidence WHERE deployment_id=$1 AND device_id=$2 AND sequence BETWEEN $3 AND $4", h.deploymentID, h.deviceID, low, high).Scan(&n); err != nil {
			h.t.Fatal(err)
		}
		return n, high - low + 1
	})
}

// waitFor polls observe until have >= want. An observation counts only if its
// query finished within timeout, so a late commit cannot pass the limit.
func (h *recoveryHarness) waitFor(what string, timeout time.Duration, observe func() (have, want uint64)) time.Duration {
	h.t.Helper()
	start := time.Now()
	for {
		have, want := observe()
		elapsed := time.Since(start)
		if have >= want && elapsed <= timeout {
			return elapsed
		}
		if failure := h.ctl.failure(); failure != "" {
			h.t.Fatalf("%s: %s", what, failure)
		}
		if elapsed > timeout {
			h.t.Fatalf("%s: %d of %d after %s\nservice log:\n%s", what, have, want, timeout, h.serviceLog())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// queuedRange returns the lowest and highest sequences waiting in the spool.
func (h *recoveryHarness) queuedRange() (low, high uint64, n int) {
	h.t.Helper()
	files, err := filepath.Glob(filepath.Join(h.evidenceDir, "spool-*.json"))
	if err != nil {
		h.t.Fatal(err)
	}
	for _, f := range files {
		var seq uint64
		if _, err := fmt.Sscanf(filepath.Base(f), "spool-%016d.json", &seq); err != nil {
			h.t.Fatalf("unexpected spool record %s", f)
		}
		if n == 0 || seq < low {
			low = seq
		}
		high = max(high, seq)
		n++
	}
	return low, high, n
}

// holdNoDelivery asserts that nothing reaches storage for d. It returns how
// long the service log took, after offset, to report the unavailable relay,
// or -1 if it never did.
// before is the row count taken while the path was already down.
func (h *recoveryHarness) holdNoDelivery(what string, d time.Duration, offset int, before uint64) time.Duration {
	h.t.Helper()
	start := time.Now()
	visible := time.Duration(-1)
	for time.Since(start) < d {
		if now := h.stored(); now.count != before {
			h.t.Fatalf("%s: evidence was stored without an admitted path (%d -> %d rows)", what, before, now.count)
		}
		if offset >= 0 && visible < 0 && strings.Contains(h.logSince(offset), mesh.ErrRelayUnavailable.Error()) {
			visible = time.Since(start)
		}
		time.Sleep(250 * time.Millisecond)
	}
	return visible
}

// firstLine returns the first log line containing marker, or "".
func firstLine(log, marker string) string {
	for line := range strings.Lines(log) {
		if strings.Contains(line, marker) {
			return strings.TrimSpace(line)
		}
	}
	return ""
}

// logSince returns service log lines added after offset.
func (h *recoveryHarness) logSince(offset int) string {
	l := h.serviceLog()
	if offset > len(l) {
		return ""
	}
	return l[offset:]
}

// TestRelayRestartAndPartitionRecovery drives the service pipeline through
// relay restart, controller crash restart, a long partition of both and a relay
// admission denial, against PostgreSQL. Each mode runs every process on this
// host: "direct" leaves UDP to Tailcat, "derp" forces every packet through the
// scoped relay with the upstream TS_DEBUG_ALWAYS_USE_DERP knob.
func TestRelayRestartAndPartitionRecovery(t *testing.T) {
	if os.Getenv(recoveryProofEnv) != "1" {
		t.Skip(recoveryProofEnv + "=1 runs the multi-minute recovery proof (make recovery-proof)")
	}
	configured := os.Getenv("TEST_DATABASE_URL")
	if configured == "" {
		t.Fatal("TEST_DATABASE_URL is required for the recovery proof")
	}
	partition := defaultRecoveryPartition
	if value := os.Getenv(recoveryPartitionEnv); value != "" {
		d, err := time.ParseDuration(value)
		if err != nil || d < shortOutage {
			t.Fatalf("%s must be a duration of at least %s", recoveryPartitionEnv, shortOutage)
		}
		partition = d
	}
	modes := []string{"direct", "derp"}
	if value := os.Getenv(recoveryModesEnv); value != "" {
		modes = strings.Split(value, ",")
	}
	for _, mode := range modes {
		if mode != "direct" && mode != "derp" {
			t.Fatalf("unknown recovery mode %q", mode)
		}
		t.Run(mode, func(t *testing.T) { recoveryScenario(t, configured, mode == "derp", partition) })
	}
}

func recoveryScenario(t *testing.T, configured string, forced bool, partition time.Duration) {
	ctx := t.Context()
	mode := map[bool]string{false: "direct", true: "derp"}[forced]
	deploymentID := "deployment:recovery-" + mode
	server, ca, repo, db := postgresEnrollment(t, configured, deploymentID)
	client, origin, err := enrollmentClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	token, err := repo.IssueBootstrapToken(ctx, contracts.BootstrapTokenRequestV1{SchemaVersion: contracts.BootstrapTokenRequestV1Version, DeviceID: "device:recovery-" + mode}, "https://id.example.test", "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	store, statePath := testStore(t)
	accepted, err := enroll(ctx, store, client, origin, token)
	if err != nil {
		t.Fatal(err)
	}
	store.close()

	var name string
	if err := db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil {
		t.Fatal(err)
	}
	isolated, err := url.Parse(configured)
	if err != nil {
		t.Fatal(err)
	}
	isolated.Path = "/" + name

	dir := t.TempDir()
	controllerDir := filepath.Join(dir, "controller")
	if err := mesh.InitializeServer(controllerDir); err != nil {
		t.Fatal(err)
	}
	pin, err := mesh.ServerPublicKey(controllerDir)
	if err != nil {
		t.Fatal(err)
	}
	ackPublic, ackPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(ackPublic)
	if err != nil {
		t.Fatal(err)
	}
	ackFile := filepath.Join(dir, "ack.pem")
	if err := os.WriteFile(ackFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}

	// The production relay package with a certificate that the children trust
	// only through SSL_CERT_FILE. The region has no InsecureForTests.
	relayDir := filepath.Join(dir, "relay")
	if err := os.Mkdir(relayDir, 0o700); err != nil {
		t.Fatal(err)
	}
	rootCA := relaytest.NewCA(t, relayDir)
	cert, certKey := rootCA.Valid(t, relayDir, relaytest.Hostname)
	nodeKey := filepath.Join(relayDir, "relay.key")
	if err := relay.InitializeNodeKey(nodeKey); err != nil {
		t.Fatal(err)
	}
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	relayAddr := probe.Addr().String()
	port := probe.Addr().(*net.TCPAddr).Port
	probe.Close()
	h := &recoveryHarness{t: t, ctx: ctx, db: db, deploymentID: deploymentID, deviceID: accepted.DeviceID,
		relayAddr: relayAddr, admission: filepath.Join(relayDir, "admission.json"),
		admitted: []string{pin, accepted.NetworkPublicKey}}
	h.relayConfig = relay.Config{Hostname: relaytest.Hostname, CertFile: cert, KeyFile: certKey, NodeKeyFile: nodeKey, AdmissionFile: h.admission}
	h.writeAdmission(h.admitted...)
	regionFile := filepath.Join(dir, "region.json")
	writeJSON(t, regionFile, relay.Region(900, relaytest.Hostname, "127.0.0.1", port, ""))
	h.env = []string{"SSL_CERT_FILE=" + rootCA.File}
	if forced {
		h.env = append(h.env, "TS_DEBUG_ALWAYS_USE_DERP=1")
	}

	h.controller = filepath.Join(dir, "controller.json")
	writeJSON(t, h.controller, recoveryControllerConfig{DatabaseURL: isolated.String(), DeploymentID: deploymentID, StateDir: controllerDir, RegionFile: regionFile, AckKey: hex.EncodeToString(ackPrivate)})
	cfg := testServiceConfig(t, statePath)
	cfg.Delivery = &deliveryConfig{MeshServerKey: pin, DERPRegionFile: regionFile, ControllerAckKeyFile: ackFile}
	h.evidenceDir = cfg.EvidenceDir
	servicePath := filepath.Join(dir, "service.json")
	writeJSON(t, servicePath, cfg)

	// Steady state.
	h.startRelay()
	t.Cleanup(h.stopRelay)
	ctl, ready := h.startController()
	if ready.RelayErr != "" {
		t.Fatalf("controller relay preflight failed with the relay up: %s", ready.RelayErr)
	}
	address := ready.Address
	s, err := openIdentityStore(statePath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.write("mesh-address", []byte(address)); err != nil {
		t.Fatal(err)
	}
	s.close()
	countersBefore := h.relay.Counters()
	service := h.child(recoveryServiceEnv, servicePath, nil)
	first := h.waitStored("first delivery", 1, 60*time.Second)
	// first is measured from the service start.
	h.waitStored("steady delivery", 2, 30*time.Second)
	countersAfter := h.relay.Counters()
	relayed := countersAfter.OtherPackets - countersBefore.OtherPackets
	t.Logf("%s steady: first record stored %s after service start; relay non-disco packets +%d", mode, first.Round(time.Millisecond), relayed)
	if forced && relayed == 0 {
		t.Fatal("forced DERP delivered without relayed WireGuard packets")
	}

	// Relay restart. A direct session keeps delivering through the outage;
	// a forced-DERP session has no path and must stall, then reconnect.
	offset := len(h.serviceLog())
	h.stopRelay()
	outage := time.Now()
	if forced {
		h.holdNoDelivery("relay down, forced DERP", shortOutage, offset, h.stored().count)
		h.startRelay()
		reconnect := h.waitCollectedAfter("delivery after relay restart", outage, 1, recoveryLimit)
		// A request already in flight may finish once Tailcat reconnects,
		// inside its 15 s HTTP timeout, so a short outage need not log a retry.
		retries := strings.Count(h.logSince(offset), "retry in")
		t.Logf("derp relay restart: no evidence stored during %s outage (%d logged retries); next record stored %s after relay restart", shortOutage, retries, reconnect.Round(time.Millisecond))
	} else {
		// Only a sample taken after the relay stopped proves the direct path.
		during := h.waitCollectedAfter("direct delivery with the relay down", outage, 1, 30*time.Second)
		t.Logf("direct relay restart: established direct session stored a record sampled after the relay stopped, %s into the outage", during.Round(time.Millisecond))
		restart := time.Now()
		h.startRelay()
		h.waitCollectedAfter("delivery after relay restart", restart, 1, recoveryLimit)
		t.Logf("direct relay restart: relay back after %s", time.Since(outage).Round(time.Millisecond))
	}

	// Controller crash and restart with the relay up.
	ctl.kill()
	killed := time.Now()
	ctl, ready = h.startController()
	if ready.RelayErr != "" || ready.Address != address {
		t.Fatalf("controller restart changed address or failed relay preflight: %q", ready.RelayErr)
	}
	// Only a sample taken after the replacement is ready can have been
	// stored by it rather than by the killed process.
	replaced := time.Now()
	reconnect := h.waitCollectedAfter("delivery after controller restart", replaced, 1, recoveryLimit)
	t.Logf("%s controller restart: process killed, replacement ready in %s, record sampled after readiness stored %s later", mode, replaced.Sub(killed).Round(time.Millisecond), reconnect.Round(time.Millisecond))

	// Long partition: relay and controller both down. Sampling continues
	// into the spool, nothing is stored and the failure is logged.
	offset = len(h.serviceLog())
	h.stopRelay()
	ctl.kill()
	partitioned := time.Now()
	before := h.stored().count
	visible := h.holdNoDelivery("long partition", partition, offset, before)
	log := h.logSince(offset)
	if visible < 0 || visible > visibleLimit || !strings.Contains(log, "evidence not sent") {
		t.Fatalf("partition was not reported as an unavailable self-hosted relay:\n%s", log)
	}
	retries := strings.Count(log, "retry in")
	t.Logf("%s long partition: relay unavailable first logged %s into the partition; %d retries logged in %s", mode, visible.Round(time.Millisecond), retries, partition)
	if strings.Contains(h.serviceLog(), "spool delivery stopped") {
		t.Fatalf("delivery gave up during the partition:\n%s", h.serviceLog())
	}
	// The controller starts while the relay is still down. It reports the
	// relay and keeps running; a cold session cannot form without the relay.
	ctl, ready = h.startController()
	if !strings.Contains(ready.RelayErr, mesh.ErrRelayUnavailable.Error()) || ready.Address != address {
		t.Fatalf("controller did not report the unavailable relay: %q", ready.RelayErr)
	}
	h.holdNoDelivery("controller up, relay down", shortOutage, -1, before)
	low, high, backlog := h.queuedRange()
	// Sampling every 5 s must have queued new evidence during the outage.
	if minimum := int((partition + shortOutage) / (10 * time.Second)); backlog < minimum || high <= h.stored().high {
		t.Fatalf("partition queued %d records (%d..%d), want at least %d newer than stored", backlog, low, high, minimum)
	}
	if held := h.stored().count; held != before {
		t.Fatalf("evidence stored while the relay was down: %d -> %d", before, held)
	}
	h.startRelay()
	drained := h.waitRange("partition backlog", low, high, recoveryLimit)
	t.Logf("%s long partition: %s with relay and controller down, then %s with only the relay down; %d queued records (sequences %d..%d) stored %s after relay restart (limit %s)",
		mode, partition, shortOutage, backlog, low, high, drained.Round(time.Millisecond), recoveryLimit)
	t.Logf("%s long partition: total outage %s", mode, time.Since(partitioned).Round(time.Second))

	if forced {
		// The relay drops the endpoint's network key. Admission is re-read on
		// each connection, so a restart forces the endpoint to reconnect. The
		// controller key stays admitted.
		h.stopRelay()
		before = h.stored().count
		h.writeAdmission(pin)
		h.startRelay()
		// Failures from the stopped relay are logged before this offset, so
		// a report after it comes from the running relay refusing the key.
		offset = len(h.serviceLog())
		denied := h.holdNoDelivery("endpoint key removed from relay admission", visibleLimit, offset, before)
		line := firstLine(h.logSince(offset), mesh.ErrRelayUnavailable.Error())
		// The preflight reaches the relay, which closes the connection after
		// the handshake; a stopped relay would refuse the TCP connection.
		if denied < 0 || !strings.Contains(line, "relay admission denied") || strings.Contains(line, "connection refused") {
			t.Fatalf("relay admission denial was not reported by the running relay:\n%s", h.logSince(offset))
		}
		t.Logf("derp relay admission: running relay refused the key: %s", line[strings.Index(line, mesh.ErrRelayUnavailable.Error()):])
		h.writeAdmission(h.admitted...)
		readmitted := h.waitStored("delivery after relay readmission", before+1, recoveryLimit)
		t.Logf("derp relay admission: endpoint key removed, nothing stored for %s, relay unavailable logged after %s; key restored without relay restart, next record stored %s later", visibleLimit, denied.Round(time.Millisecond), readmitted.Round(time.Millisecond))
	}

	// Drain once: wait for an empty spool, stop the service, then check that
	// every signed sequence was stored exactly once with no gap.
	waitFor(t, "an empty spool", 60*time.Second, func() bool { return h.queued() == 0 })
	service.kill()
	final := h.stored()
	if final.low != accepted.LastSequence+1 {
		t.Fatalf("first stored sequence %d, want %d after the enrollment receipt", final.low, accepted.LastSequence+1)
	}
	if final.count != final.high-final.low+1 {
		t.Fatalf("stored sequences %d..%d have gaps or duplicates: %d rows", final.low, final.high, final.count)
	}
	queued := h.queued()
	data, err := os.ReadFile(filepath.Join(h.evidenceDir, spoolRetired))
	var retired contracts.EvidenceEnvelopeV1
	if err != nil || json.Unmarshal(data, &retired) != nil {
		t.Fatal("read retired spool head")
	}
	if retired.Sequence > final.high || final.high-retired.Sequence > uint64(queued) {
		t.Fatalf("retired head %d does not match stored high %d with %d queued", retired.Sequence, final.high, queued)
	}
	if strings.Contains(h.serviceLog(), "spool delivery stopped") {
		t.Fatalf("delivery stopped:\n%s", h.serviceLog())
	}
	stored, err := controller.NewPostgresRepository(ctx, db, controller.RepositoryConfig{DeploymentID: deploymentID})
	if err != nil {
		t.Fatal(err)
	}
	for seq := final.low; seq <= final.high; seq++ {
		e, err := stored.Evidence(ctx, accepted.DeviceID, seq)
		if err != nil || e.Envelope.VerifySignature(mustSigningKey(t, statePath)) != nil {
			t.Fatalf("stored sequence %d is missing or not signed by the device: %v", seq, err)
		}
	}
	t.Logf("%s drain once: sequences %d..%d stored once each (%d rows), spool empty, no delivery stop", mode, final.low, final.high, final.count)
}

func mustSigningKey(t *testing.T, statePath string) ed25519.PublicKey {
	t.Helper()
	s, err := openIdentityStore(statePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	i, err := s.load(false)
	if err != nil {
		t.Fatal(err)
	}
	return i.signing.Public().(ed25519.PublicKey)
}
