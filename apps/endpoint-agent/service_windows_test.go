//go:build windows

package main

import (
	"os/exec"
	"strings"
	"testing"
)

// Outside the SCM, and under any account but LocalService, service mode
// refuses to start instead of running with a different identity or privilege.
func TestServiceRefusesUnsupportedRuntime(t *testing.T) {
	if err := runService(`C:\absent\service.json`); err == nil || !strings.Contains(err.Error(), "service control manager") {
		t.Fatalf("interactive --service = %v", err)
	}
	if _, err := checkServiceToken(); err == nil || !strings.Contains(err.Error(), "LocalService") {
		t.Fatalf("interactive token accepted: %v", err)
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
