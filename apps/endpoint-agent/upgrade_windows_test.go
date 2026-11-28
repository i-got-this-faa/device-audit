//go:build windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"tailscale.com/derp/derpserver"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type upgradeMeshRepository struct {
	binding controller.DeviceNetworkBinding
	mu      sync.Mutex
	seen    map[uint64]contracts.EvidenceEnvelopeV1
	high    uint64
}

func (r *upgradeMeshRepository) NetworkPeerBinding(_ context.Context, peer string) (controller.DeviceNetworkBinding, error) {
	if peer != r.binding.NetworkPublicKey {
		return controller.DeviceNetworkBinding{}, errors.New("unknown fixture mesh key")
	}
	return r.binding, nil
}

func (r *upgradeMeshRepository) AcceptEvidence(_ context.Context, e contracts.EvidenceEnvelopeV1) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.seen[e.Sequence]; ok && existing == e {
		return time.Now(), nil
	}
	if e.Sequence <= r.high {
		return time.Time{}, errors.New("sequence reuse or reordering")
	}
	r.seen[e.Sequence], r.high = e, e.Sequence
	return time.Now(), nil
}

// Backup and restore semantics are used only by the disposable fixture to
// provision the private mesh address and snapshot encrypted identity state.
func enableFixtureBackupPrivileges(t *testing.T) {
	t.Helper()
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	for _, privilege := range []string{"SeBackupPrivilege", "SeRestorePrivilege"} {
		name, _ := windows.UTF16PtrFromString(privilege)
		var state windows.Tokenprivileges
		state.PrivilegeCount = 1
		state.Privileges[0].Attributes = windows.SE_PRIVILEGE_ENABLED
		if err := windows.LookupPrivilegeValue(nil, name, &state.Privileges[0].Luid); err != nil {
			t.Fatal(err)
		}
		if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func fixturePrivateFile(t *testing.T, path string, descriptor *windows.SECURITY_DESCRIPTOR) *os.File {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	var attrs *windows.SecurityAttributes
	access, creation := uint32(windows.GENERIC_READ), uint32(windows.OPEN_EXISTING)
	if descriptor != nil {
		attrs = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
		access, creation = windows.GENERIC_WRITE, windows.CREATE_NEW
	}
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, attrs, creation, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	return os.NewFile(uintptr(handle), path)
}

func verifyWindowsReleaseUpgrade(t *testing.T, root, program string, signingKey ed25519.PublicKey, enrollments func() int32) {
	t.Helper()
	pwsh := func(args ...string) ([]byte, error) {
		cmd := exec.Command("pwsh", append([]string{"-NoProfile", "-NonInteractive"}, args...)...)
		return cmd.CombinedOutput()
	}
	stop := func() {
		if out, err := pwsh("-Command", "Stop-Service DeviceAuditEndpoint"); err != nil {
			t.Fatalf("stop: %v %s", err, out)
		}
	}
	stop()
	enableFixtureBackupPrivileges(t)
	identityDir := filepath.Join(root, "identity")
	readPrivate := func(name string) []byte {
		t.Helper()
		file := fixturePrivateFile(t, filepath.Join(identityDir, name), nil)
		defer file.Close()
		data, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	admission := readPrivate(receiptFile)
	keys := readPrivate(keyFile)
	var receipt contracts.EnrollmentAcceptedV1
	if err := json.Unmarshal(admission, &receipt); err != nil {
		t.Fatal(err)
	}
	counter := func() uint64 {
		t.Helper()
		state, err := decodeSequence(readPrivate(sequenceFile), receipt)
		if err != nil {
			t.Fatal(err)
		}
		return state.LastReserved
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	relay := derpserver.New(key.NewNode(), func(string, ...any) {})
	defer relay.Close()
	relayHTTP := httptest.NewTLSServer(derpserver.Handler(relay))
	defer relayHTTP.Close()
	region := &tailcfg.DERPRegion{RegionID: 1, Nodes: []*tailcfg.DERPNode{{Name: "loopback", RegionID: 1, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none", DERPPort: relayHTTP.Listener.Addr().(*net.TCPAddr).Port, STUNPort: -1, InsecureForTests: true}}}
	controllerDir := filepath.Join(t.TempDir(), "controller")
	if err := mesh.InitializeServer(controllerDir); err != nil {
		t.Fatal(err)
	}
	pin, err := mesh.ServerPublicKey(controllerDir)
	if err != nil {
		t.Fatal(err)
	}
	node, err := mesh.NewServer(mesh.ServerConfig{Context: ctx, StateDir: controllerDir, DERP: mesh.DERPConfig{Region: region}, Allow: func(peer string) bool { return peer == receipt.NetworkPublicKey }})
	if err != nil {
		t.Fatal(err)
	}
	defer node.Close()
	ln, err := node.Listen(ctx, "tcp", ":8080")
	if err != nil {
		t.Fatal(err)
	}
	public, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := &upgradeMeshRepository{binding: controller.DeviceNetworkBinding{
		DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID, SigningKeyID: receipt.SigningKeyID,
		SigningPublicKey: signingKey, NetworkPublicKey: receipt.NetworkPublicKey,
	}, seen: map[uint64]contracts.EvidenceEnvelopeV1{}}
	server, err := controller.MeshHTTPServer(controller.MeshConfig{Node: node, Repository: repo, AcknowledgementKey: signer})
	if err != nil {
		t.Fatal(err)
	}
	var online atomic.Bool
	handler := server.Handler
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !online.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	})
	go server.Serve(ln)
	defer server.Close()

	sid, _, _, err := windows.LookupSID("", `NT SERVICE\DeviceAuditEndpoint`)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:BAD:P(A;;FA;;;SY)(A;;FA;;;" + sid.String() + ")(A;;RC;;;OW)")
	if err != nil {
		t.Fatal(err)
	}
	address := fixturePrivateFile(t, filepath.Join(identityDir, "mesh-address"), sd)
	_, err = address.WriteString(node.Addr())
	if err := errors.Join(err, address.Close()); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "service.json")
	cfg, err := loadServiceConfig(configPath)
	if err != nil {
		t.Fatal(err)
	}
	regionPath := filepath.Join(program, "qualification-region.json")
	writeJSON(t, regionPath, region)
	ackPath := filepath.Join(program, "qualification-ack.pem")
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ackPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg.Delivery = &deliveryConfig{MeshServerKey: pin, DERPRegionFile: regionPath, ControllerAckKeyFile: ackPath}
	writeJSON(t, configPath, cfg)

	snapshot := func() map[uint64][]byte {
		t.Helper()
		data := map[uint64][]byte{}
		paths, err := filepath.Glob(filepath.Join(cfg.EvidenceDir, "spool-*.json"))
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			seq, ok := spoolSequence(filepath.Base(path), "spool-")
			if !ok {
				t.Fatalf("invalid spool filename %s", path)
			}
			data[seq], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		return data
	}
	before := snapshot()
	mark := counter()
	if len(before) == 0 || mark < contracts.FirstEvidenceSequenceV1 {
		t.Fatal("prior package did not queue and reserve evidence")
	}
	model, err := os.ReadFile(cfg.Inference.ArtifactFile)
	if err != nil {
		t.Fatal(err)
	}
	update, err := filepath.Abs("../../packaging/windows/Update-DeviceAudit.ps1")
	if err != nil {
		t.Fatal(err)
	}
	upgradeArgs := func(packageDir string) []string {
		return []string{"-PackageDir", packageDir, "-SignerSHA256", os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_SIGNER"),
			"-SourceCommit", os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_COMMIT"), "-ModelPublisherSHA256",
			os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_MODEL_PIN"), "-StartupTimeoutSeconds", "45"}
	}
	registration, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\DeviceAuditEndpoint`, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer registration.Close()
	image := func() string {
		t.Helper()
		v, _, err := registration.GetStringValue("ImagePath")
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	prior := image()
	runUpdate := func(packageDir string) ([]byte, error) {
		return pwsh(append([]string{"-File", update}, upgradeArgs(packageDir)...)...)
	}
	incompatible := os.Getenv("DEVICE_AUDIT_UPGRADE_TEST_INCOMPATIBLE_PACKAGE")
	if out, err := runUpdate(incompatible); err == nil || !strings.Contains(string(out), "does not declare compatible endpoint state version 1") || image() != prior || counter() != mark {
		t.Fatalf("incompatible upgrade changed service or state: %v %s", err, out)
	}

	journal := filepath.Join(program, "upgrade-pending.json")
	failing := os.Getenv("DEVICE_AUDIT_UPGRADE_TEST_START_FAILURE_PACKAGE")
	if out, err := runUpdate(failing); err == nil || !strings.Contains(string(out), "Restored the prior service image") || image() != prior {
		t.Fatalf("failed trial did not automatically restore the prior service: %v %s", err, out)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("automatic recovery left the journal: %v", err)
	}
	stop()
	mark = counter()
	packageDir := os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_PACKAGE")
	// Interrupt the installer at the real cutover after the candidate reports
	// readiness and has a chance to reserve and queue new evidence.
	script, err := os.ReadFile(update)
	if err != nil {
		t.Fatal(err)
	}
	commitLine := 0
	for n, line := range strings.Split(string(script), "\n") {
		if strings.Contains(line, `'binPath=', $command, 'start=', 'auto'`) {
			commitLine = n + 1
		}
	}
	if commitLine == 0 {
		t.Fatal("upgrade cutover location missing")
	}
	driver := filepath.Join(t.TempDir(), "interrupt.ps1")
	driverText := fmt.Sprintf(`
param($PackageDir, $SignerSHA256, $SourceCommit, $ModelPublisherSHA256, $StartupTimeoutSeconds)
$null = Set-PSBreakpoint -Script $env:DEVICE_AUDIT_UPGRADE_SCRIPT -Line %d -Action {
    Start-Sleep -Seconds 8
    Stop-Process -Id $PID -Force
}
& $env:DEVICE_AUDIT_UPGRADE_SCRIPT @PSBoundParameters
`, commitLine)
	if err := os.WriteFile(driver, []byte(driverText), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", append([]string{"-NoProfile", "-NonInteractive", "-File", driver}, upgradeArgs(packageDir)...)...)
	cmd.Env = append(os.Environ(), "DEVICE_AUDIT_UPGRADE_SCRIPT="+update)
	if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(image(), "--upgrade-readiness-token") {
		t.Fatalf("installer was not interrupted during trial: %v %s", err, out)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatal(err)
	}
	stop()
	trialMark := counter()
	if trialMark <= mark {
		t.Fatalf("candidate did not advance the live mark: %d <= %d", trialMark, mark)
	}
	if out, err := pwsh("-File", update, "-Recover"); err != nil || image() != prior {
		t.Fatalf("interruption recovery did not restore prior image: %v %s", err, out)
	}
	stop()
	if counter() < trialMark {
		t.Fatal("recovery reset the live counter")
	}
	for n, data := range before {
		if queued, err := os.ReadFile(filepath.Join(cfg.EvidenceDir, recordName(n))); err != nil || !bytes.Equal(data, queued) {
			t.Fatalf("recovery changed queued sequence %d: %v", n, err)
		}
	}

	if out, err := runUpdate(packageDir); err != nil || image() == prior || strings.Contains(image(), "--upgrade-readiness-token") {
		t.Fatalf("compatible upgrade did not commit: %v %s", err, out)
	}
	if version, err := os.ReadFile(filepath.Join(root, endpointStateFile)); err != nil || string(version) != "1\n" {
		t.Fatalf("migration did not record state v1: %v", err)
	}
	if _, err := os.Stat(journal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("upgrade journal remained: %v", err)
	}
	if !bytes.Equal(keys, readPrivate(keyFile)) || !bytes.Equal(admission, readPrivate(receiptFile)) || enrollments() != 2 {
		t.Fatal("upgrade changed the admitted keys/receipt or enrolled again")
	}
	if after, err := os.ReadFile(cfg.Inference.ArtifactFile); err != nil || !bytes.Equal(model, after) {
		t.Fatalf("upgrade changed the last-working provisioned model: %v", err)
	}

	online.Store(true)
	waitFor(t, "authenticated delivery of the old backlog and fresh samples", 90*time.Second, func() bool {
		repo.mu.Lock()
		defer repo.mu.Unlock()
		if repo.high <= trialMark {
			return false
		}
		for n, data := range before {
			var queued contracts.EvidenceEnvelopeV1
			if json.Unmarshal(data, &queued) != nil || repo.seen[n] != queued {
				return false
			}
		}
		return true
	})
	waitFor(t, "retirement via authenticated acknowledgement", 30*time.Second, func() bool {
		for n := range before {
			if _, err := os.Stat(filepath.Join(cfg.EvidenceDir, recordName(n))); !errors.Is(err, os.ErrNotExist) {
				return false
			}
		}
		return true
	})
	t.Log("upgraded the prior Windows package, recovered an interrupted trial without resetting sequence state, and drained original signed evidence through Tailcat and signed controller acknowledgements")
}
