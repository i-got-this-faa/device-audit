//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Outside the SCM, and under any account but LocalService, service mode
// refuses to start instead of running with a different identity or privilege.
func TestServiceRefusesUnsupportedRuntime(t *testing.T) {
	if err := runService(`C:\absent\service.json`, ""); err == nil || !strings.Contains(err.Error(), "service control manager") {
		t.Fatalf("interactive --service = %v", err)
	}
	if _, err := checkServiceToken(); err == nil || !strings.Contains(err.Error(), "LocalService") {
		t.Fatalf("interactive token accepted: %v", err)
	}
}

// Evidence storage readable or writable by anyone beyond SYSTEM,
// Administrators and the service principal is refused.
func TestEvidenceACLIsRestricted(t *testing.T) {
	principal, err := storagePrincipal()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	setTestACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+principal+")(A;OICI;RC;;;OW)(D;OICI;WD;;;WD)")
	if err := checkEvidenceACL(dir); err != nil {
		t.Fatalf("private evidence dir refused: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, evidenceLogFile), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	setTestACL(t, filepath.Join(dir, evidenceLogFile), "D:P(A;;FA;;;"+principal+")(A;;FR;;;BU)")
	if err := checkEvidenceACL(dir); err == nil {
		t.Fatal("evidence file readable by Users accepted")
	}
	setTestACL(t, dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;"+principal+")(A;OICI;FR;;;WD)")
	if err := checkEvidenceACL(dir); err == nil {
		t.Fatal("evidence dir readable by Everyone accepted")
	}
}

// The real binary fails explicitly for an interactive --service and for
// --service mixed with another mode.
func TestServiceCommandLine(t *testing.T) {
	bin := t.TempDir() + `\endpoint-agent.exe`
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	for args, want := range map[string]string{
		"--service --service-config C:\\absent\\service.json": "service control manager",
		"--service": "requires --service-config",
		"--service --service-config C:\\x.json --sample --device-id device:test": "runs alone",
	} {
		out, err := exec.Command(bin, strings.Fields(args)...).CombinedOutput()
		if err == nil || !strings.Contains(string(out), want) {
			t.Fatalf("%s: %v %s", args, err, out)
		}
	}
}

func makeTestEvidencePrivate(t *testing.T, path string) {
	t.Helper()
	principal, err := storagePrincipal()
	if err != nil {
		t.Fatal(err)
	}
	setTestACL(t, path, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;"+principal+")(A;OICI;RC;;;OW)")
}

func TestSpoolFileRequiresOwnerRights(t *testing.T) {
	dir := t.TempDir()
	makeTestEvidencePrivate(t, dir)
	path := filepath.Join(dir, "record")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	check := func() error {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		return validateSpoolFile(f)
	}
	if err := check(); err != nil {
		t.Fatalf("inherited owner rights: %v", err)
	}
	principal, err := storagePrincipal()
	if err != nil {
		t.Fatal(err)
	}
	for _, ace := range []string{"", "(A;;WD;;;OW)"} {
		setTestACL(t, path, "D:P(A;;FA;;;"+principal+")"+ace)
		if err := check(); err == nil {
			t.Fatalf("unsafe owner rights accepted: %q", ace)
		}
	}
}
