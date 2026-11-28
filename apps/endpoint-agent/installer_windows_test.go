//go:build windows

package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"golang.org/x/sys/windows"
)

// TestWindowsReleaseCleanInstall is opt-in on an elevated disposable machine.
func TestWindowsReleaseCleanInstall(t *testing.T) {
	testWindowsReleaseInstall(t, false)
}

func TestWindowsReleaseUpgrade(t *testing.T) {
	if os.Getenv("DEVICE_AUDIT_UPGRADE_TEST_PRIOR_PACKAGE") == "" {
		t.Skip("no installer upgrade qualification packages requested")
	}
	testWindowsReleaseInstall(t, true)
}

func testWindowsReleaseInstall(t *testing.T, upgrade bool) {
	t.Helper()
	pkg := os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_PACKAGE")
	if pkg == "" {
		t.Skip("no installer qualification package requested")
	}
	pin := os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_SIGNER")
	commit := os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_COMMIT")
	modelPin := os.Getenv("DEVICE_AUDIT_INSTALLER_TEST_MODEL_PIN")
	if upgrade {
		pkg = os.Getenv("DEVICE_AUDIT_UPGRADE_TEST_PRIOR_PACKAGE")
		commit = os.Getenv("DEVICE_AUDIT_UPGRADE_TEST_PRIOR_COMMIT")
	}
	installer, err := filepath.Abs("../../packaging/windows/Install-DeviceAudit.ps1")
	if err != nil {
		t.Fatal(err)
	}
	program := filepath.Join(os.Getenv("ProgramFiles"), "DeviceAudit")
	state := filepath.Join(os.Getenv("ProgramData"), "DeviceAudit")
	root := filepath.Join(state, "Endpoint")
	sc := filepath.Join(os.Getenv("SystemRoot"), "System32", "sc.exe")
	requireClean := func() {
		t.Helper()
		for _, path := range []string{program, state} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("qualification requires a clean machine or rollback left %s: %v", path, err)
			}
		}
		out, err := exec.Command(sc, "query", serviceName).CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1060 {
			t.Fatalf("expected no endpoint registration: %s (%v)", out, err)
		}
	}
	requireClean()

	server, ca, requests, public := fixtureEnrollmentServer(t)
	temporary := t.TempDir()
	private := filepath.Join(temporary, "private")
	sd, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	privateName, err := windows.UTF16PtrFromString(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.CreateDirectory(privateName, &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}); err != nil {
		t.Fatal(err)
	}
	bootstrap := filepath.Join(private, "bootstrap.json")
	sampling := *testServiceConfig(t, filepath.Join(temporary, "identity")).SamplingConfig
	launch := func(directory, signer, source, publisher string) ([]byte, error) {
		return exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-File", installer,
			"-PackageDir", directory, "-SignerSHA256", signer, "-SourceCommit", source,
			"-ModelPublisherSHA256", publisher, "-EnrollmentOrigin", server.URL, "-CAFile", ca,
			"-BootstrapFile", bootstrap, "-SamplingConfig", sampling, "-StartupTimeoutSeconds", "35").CombinedOutput()
	}
	refused := func(name, directory, signer, source, publisher, message string) {
		t.Helper()
		out, err := launch(directory, signer, source, publisher)
		if err == nil || !strings.Contains(string(out), message) {
			t.Fatalf("%s: unexpected installer result: %s (%v)", name, out, err)
		}
		requireClean()
		t.Logf("refused %s and left no service or state", name)
	}
	if !upgrade {
		writeJSON(t, bootstrap, testToken())
		refused("wrong release signer", pkg, strings.Repeat("0", 64), commit, modelPin, "pinned certificate")
		refused("wrong source commit", pkg, pin, strings.Repeat("0", 40), modelPin, "signed provenance")
		refused("wrong model publisher", pkg, pin, commit, strings.Repeat("0", 64), "deployment pin")
		tampered := filepath.Join(temporary, "tampered")
		if err := os.Mkdir(tampered, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"device-audit-windows-amd64.zip", "provenance.json", "provenance.p7s"} {
			data, err := os.ReadFile(filepath.Join(pkg, name))
			if err != nil {
				t.Fatal(err)
			}
			if name == "device-audit-windows-amd64.zip" {
				data[len(data)-1] ^= 1
			}
			if err := os.WriteFile(filepath.Join(tampered, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		refused("changed archive", tampered, pin, commit, modelPin, "archive digest")
		manifest := filepath.Join(tampered, "provenance.json")
		data, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifest, append(data, byte('\n')), 0600); err != nil {
			t.Fatal(err)
		}
		refused("modified signed provenance", tampered, pin, commit, modelPin, "release signature is invalid")

		expired := testToken()
		expired.ExpiresAt = time.Now().UTC().Add(-time.Hour).Truncate(time.Second).Format(time.RFC3339)
		writeJSON(t, bootstrap, expired)
		refused("expired bootstrap", pkg, pin, commit, modelPin, "The endpoint")
		if requests.Load() != 0 {
			t.Fatal("a rejected install submitted an enrollment request")
		}
	}
	writeJSON(t, bootstrap, testToken())
	out, err := launch(pkg, pin, commit, modelPin)
	if err != nil {
		t.Fatalf("clean install: %s (%v)", out, err)
	}
	t.Cleanup(func() {
		out, err := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-File",
			filepath.Join(program, "Uninstall-EndpointService.ps1"), "-PurgeState").CombinedOutput()
		if err != nil {
			t.Errorf("uninstall: %s (%v)", out, err)
			return
		}
		if err := errors.Join(os.RemoveAll(program), os.Remove(state)); err != nil {
			t.Error(err)
		}
		requireClean()
	})
	if requests.Load() != 2 {
		t.Fatalf("enrollment requests = %d", requests.Load())
	}
	var encodedKey ed25519.PublicKey
	select {
	case encodedKey = <-public:
	default:
		t.Fatal("fixture did not admit a signing key")
	}
	if _, err := os.Stat(filepath.Join(root, "enrollment", "bootstrap.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("provisioned bootstrap remained: %v", err)
	}
	publisher, err := os.ReadFile(filepath.Join(program, "model", "publisher.pem"))
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(publisher)) != modelPin {
		t.Fatalf("model publisher was not installed: %v", err)
	}
	for _, name := range []string{"provenance.json", "provenance.p7s"} {
		if _, err := os.Stat(filepath.Join(program, name)); err != nil {
			t.Fatalf("release evidence not retained: %v", err)
		}
	}
	files, err := filepath.Glob(filepath.Join(root, "evidence", "spool-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("installer reported success with no evidence: %v", err)
	}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var envelope contracts.EvidenceEnvelopeV1
		if err := json.Unmarshal(data, &envelope); err != nil {
			t.Fatal(err)
		}
		if err := envelope.VerifySignature(encodedKey); err != nil {
			t.Fatal(err)
		}
		payload, err := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
		if err != nil {
			t.Fatal(err)
		}
		var telemetry contracts.TelemetryV2
		if err := json.Unmarshal(payload, &telemetry); err != nil {
			t.Fatal(err)
		}
		if telemetry.Source != "endpoint" || telemetry.DeviceID != testToken().DeviceID ||
			telemetry.Metrics.MemoryPercent == nil || telemetry.Metrics.MemoryPercent.Value == nil {
			t.Fatal("expected real Windows memory telemetry bound to the fixture admission")
		}
	}
	t.Logf("verified %d signed real Windows telemetry envelopes against the fixture admission key", len(files))
	if upgrade {
		verifyWindowsReleaseUpgrade(t, root, program, encodedKey, requests.Load)
	}
}
