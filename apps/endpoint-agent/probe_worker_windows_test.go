package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
	"golang.org/x/sys/windows"
)

func diagnosticTestRequest() workflows.Request {
	component := "storage:disk-0"
	return workflows.Request{ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &component},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 3, MaxOutputBytes: 256}}
}

func TestProbeWorkerProcess(t *testing.T) {
	if len(os.Args) < 2 {
		return
	}
	mode, ok := strings.CutPrefix(os.Args[len(os.Args)-1], "probe-test:")
	if !ok {
		return
	}
	if _, err := workflows.ParseRequest(os.Stdin); err != nil {
		os.Exit(90)
	}
	switch mode {
	case "hang":
		time.Sleep(30 * time.Second)
	case "noisy":
		for {
			if _, err := io.WriteString(os.Stdout, strings.Repeat("x", 1024)); err != nil {
				os.Exit(91)
			}
		}
	case "cpu":
		for {
		}
	case "memory":
		p, err := windows.VirtualAlloc(0, 128<<20, windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
		if err == nil {
			_ = windows.VirtualFree(p, 0, windows.MEM_RELEASE)
			os.Exit(92)
		}
		_, _ = fmt.Fprint(os.Stdout, "{\"memory_limit_enforced\":true}\n")
		os.Exit(0)
	case "ok":
		_, _ = fmt.Fprint(os.Stdout, "{}\n")
		os.Exit(0)
	}
	os.Exit(93)
}

func probeTestRunner(executable, mode string) *workflows.ProbeRunner {
	return workflows.NewProbeRunner(func(ctx context.Context, r workflows.Request) ([]byte, error) {
		return runWindowsProbeProcess(ctx, r, executable, []string{"-test.run=^TestProbeWorkerProcess$", "--", "probe-test:" + mode}, 300*time.Millisecond)
	})
}

func TestProbeWorkerWindowsLimits(t *testing.T) {
	// A race-instrumented worker needs extra committed shadow memory. Use
	// the production job cap with a normal process even under go test -race.
	worker := filepath.Join(t.TempDir(), "probe-worker.test.exe")
	if out, err := exec.Command("go", "test", "-c", "-race=false", "-o", worker, ".").CombinedOutput(); err != nil {
		t.Fatalf("build worker: %v %s", err, out)
	}
	for _, tc := range []struct{ mode, detail string }{
		{"hang", "wall_budget"}, {"noisy", "output_budget"}, {"cpu", "cpu_budget"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			start := time.Now()
			req := diagnosticTestRequest()
			data, err := probeTestRunner(worker, tc.mode).Run(context.Background(), req)
			var failure *workflows.Failure
			if !errors.As(err, &failure) || failure.Detail != tc.detail || len(data) != 0 || time.Since(start) > 6*time.Second {
				t.Fatalf("limit %s: %v, %d bytes, %s", tc.detail, err, len(data), time.Since(start))
			}
		})
	}
	if data, err := probeTestRunner(worker, "memory").Run(context.Background(), diagnosticTestRequest()); string(data) != "{\"memory_limit_enforced\":true}" && (err == nil || !strings.Contains(err.Error(), "memory_budget")) {
		t.Fatalf("Windows job did not deny over-budget allocation: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(250*time.Millisecond, cancel)
	_, err := probeTestRunner(worker, "hang").Run(ctx, diagnosticTestRequest())
	var failure *workflows.Failure
	if !errors.As(err, &failure) || failure.Detail != "cancel_requested" {
		t.Fatalf("cancellation: %v", err)
	}
	if data, err := probeTestRunner(worker, "ok").Run(context.Background(), diagnosticTestRequest()); err != nil || string(data) != "{}" {
		t.Fatalf("healthy probe after exhaustion: %v", err)
	}
}

func TestAssignedProbeWindowsCommand(t *testing.T) {
	store, stateDir, _, receipt := admittedStore(t)
	store.close()
	key, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	keyPath, bin := filepath.Join(dir, "diagnostic.pem"), filepath.Join(dir, "endpoint-agent.exe")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build endpoint: %v %s", err, out)
	}
	keyID, _ := contracts.SigningKeyIDV1(key)
	now := time.Now().UTC().Truncate(time.Second)
	lookback, limit := uint32(1), uint32(1)
	a := contracts.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticAssignmentV1Version, DeploymentID: receipt.DeploymentID, DeviceID: receipt.DeviceID,
			SigningKeyID: keyID, Sequence: 1, IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
		},
		AssignmentID: "assignment:worker", ProbeID: contracts.DiagnosticProbeSystemErrorsV1,
		Arguments: contracts.DiagnosticArgumentsV1{LookbackSeconds: &lookback, MaxEntries: &limit},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 10, MaxOutputBytes: 1},
	}
	message, err := a.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(private, message))
	run := func(a contracts.DiagnosticAssignmentV1) ([]byte, int) {
		t.Helper()
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "--run-assigned-probe", "--state-dir", stateDir, "--diagnostic-controller-key-file", keyPath)
		cmd.Stdin = bytes.NewReader(data)
		out, err := cmd.CombinedOutput()
		if cmd.ProcessState == nil {
			t.Fatal(err)
		}
		return out, cmd.ProcessState.ExitCode()
	}
	out, code := run(a)
	var failure probeFailure
	if code != 1 || json.Unmarshal(out, &failure) != nil || failure.Detail != "output_budget" {
		t.Fatalf("signed cap: exit %d, %s", code, out)
	}
	a.Budget.MaxOutputBytes++
	if out, code := run(a); code != 2 || !bytes.Contains(out, []byte("signature or target rejected")) {
		t.Fatalf("changed signed cap: exit %d, %s", code, out)
	}
}
