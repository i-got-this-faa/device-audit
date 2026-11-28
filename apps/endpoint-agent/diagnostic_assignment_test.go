package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func TestEndpointDiagnosticAssignment(t *testing.T) {
	store, stateDir, device, receipt := admittedStore(t)
	store.close()
	authority, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := contracts.SigningKeyIDV1(authority)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(authority)
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(t.TempDir(), "authority.pem")
	if err := os.WriteFile(pin, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	component := "storage:disk-0"
	assignment := contracts.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticAssignmentV1Version, DeploymentID: receipt.DeploymentID,
			DeviceID: receipt.DeviceID, SigningKeyID: keyID, Sequence: 1,
			IssuedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
		},
		AssignmentID: "assignment:1", ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &component},
		Budget:    contracts.DiagnosticBudgetV1{WallSeconds: 5, MaxOutputBytes: 16},
	}
	sign := func(a contracts.DiagnosticAssignmentV1) contracts.DiagnosticAssignmentV1 {
		t.Helper()
		message, err := a.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		a.Signature = hex.EncodeToString(ed25519.Sign(signer, message))
		return a
	}
	assignment = sign(assignment)

	const boot = "test-boot"
	calls := 0
	wantOutput := []byte(`{"sample":1}`)
	runner := workflows.NewProbeRunner(func(ctx context.Context, req workflows.Request) ([]byte, error) {
		calls++
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 5*time.Second || req.Budget != assignment.Budget ||
			req.ProbeID != assignment.ProbeID || req.Arguments.ComponentID == nil || *req.Arguments.ComponentID != component {
			t.Fatalf("incorrect worker request or deadline: %+v %s", req, deadline)
		}
		// The command retains the cross-process identity lock while executing.
		if other, err := openIdentityStore(stateDir, false); err == nil {
			other.close()
			t.Fatal("second execution could acquire identity lock")
		}
		if calls == 2 {
			return nil, &workflows.Failure{Reason: workflows.ReasonPermissionDenied}
		}
		return wantOutput, nil
	})
	runRaw := func(data []byte) (contracts.DiagnosticResultV1, error) {
		return executeDiagnosticAssignment(context.Background(), stateDir, pin, func() (string, error) { return boot, nil }, runner, bytes.NewReader(data))
	}
	encode := func(a contracts.DiagnosticAssignmentV1) []byte {
		t.Helper()
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	reject := func(data []byte, want error, expectedCalls int) {
		t.Helper()
		if result, err := runRaw(data); !errors.Is(err, want) || result.Signature != "" || calls != expectedCalls {
			t.Fatalf("expected %v without execution, got %v, %d calls", want, err, calls)
		}
	}
	altered := assignment
	altered.Budget.MaxOutputBytes++
	reject(encode(altered), workflows.ErrAssignmentUnauthorized, 0)
	wrongDevice := assignment
	wrongDevice.DeviceID = "device:other"
	reject(encode(sign(wrongDevice)), workflows.ErrAssignmentUnauthorized, 0)
	wrongDeployment := assignment
	wrongDeployment.DeploymentID = "deployment:other"
	reject(encode(sign(wrongDeployment)), workflows.ErrAssignmentUnauthorized, 0)

	expired := assignment
	expired.IssuedAt = now.Add(-time.Minute).Format(time.RFC3339)
	expired.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339)
	reject(encode(sign(expired)), workflows.ErrAssignmentExpired, 0)
	tooLate := assignment
	tooLate.IssuedAt = now.Add(-time.Minute).Format(time.RFC3339)
	tooLate.ExpiresAt = now.Add(2 * time.Second).Format(time.RFC3339)
	reject(encode(sign(tooLate)), workflows.ErrAssignmentExpired, 0)
	future := assignment
	future.IssuedAt = now.Add(10 * time.Second).Format(time.RFC3339)
	reject(encode(sign(future)), workflows.ErrAssignmentExpired, 0)

	raw := encode(assignment)
	reject(bytes.Replace(raw, []byte(assignment.SchemaVersion), []byte("unknown.v1"), 1), workflows.ErrAssignmentInvalid, 0)
	reject(bytes.Replace(raw, []byte(assignment.ProbeID), []byte("unknown.v1"), 1), workflows.ErrAssignmentInvalid, 0)
	reject(bytes.Replace(raw, []byte(`"component_id":`), []byte(`"command":"foo","component_id":`), 1), workflows.ErrAssignmentInvalid, 0)
	reject(bytes.Replace(raw, []byte(`"sequence":1`), []byte(`"sequence":1,"sequence":1`), 1), workflows.ErrAssignmentInvalid, 0)
	reject(append(bytes.Clone(raw), []byte(" {}")...), workflows.ErrAssignmentInvalid, 0)
	reject(bytes.Repeat([]byte(" "), 16<<10+1), workflows.ErrAssignmentInvalid, 0)

	check := func(a contracts.DiagnosticAssignmentV1, sequence uint64, state string) contracts.DiagnosticResultV1 {
		t.Helper()
		result, err := runRaw(encode(a))
		if err != nil || result.VerifySignature(device.signing.Public().(ed25519.PublicKey)) != nil ||
			result.CheckAssignment(a) != nil || result.Sequence != sequence || result.State != state ||
			result.BootID != boot || result.StartedAt == nil {
			t.Fatalf("invalid outcome for %s: %+v (%v)", state, result, err)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		assertNoPrivateMaterial(t, device, raw)
		return result
	}
	success := check(assignment, 2, "succeeded")
	sum := fmt.Sprintf("%x", sha256.Sum256(wantOutput))
	if len(success.Evidence) != 1 || success.Evidence[0].SHA256 != sum ||
		success.Evidence[0].SizeBytes != uint32(len(wantOutput)) {
		t.Fatalf("incorrect evidence attribution: %+v", success.Evidence)
	}
	if data, err := os.ReadFile(filepath.Join(stateDir, success.Evidence[0].ReferenceID+".evidence")); err != nil || !bytes.Equal(data, wantOutput) {
		t.Fatalf("signed evidence reference has no matching local bytes: %v", err)
	}

	// Every invocation reopens the identity. Both replay keys survive that boundary.
	reject(raw, workflows.ErrAssignmentReplay, 1)
	duplicate := assignment
	duplicate.Sequence++
	reject(encode(sign(duplicate)), workflows.ErrAssignmentReplay, 1)
	stale := assignment
	stale.AssignmentID = "assignment:stale"
	reject(encode(sign(stale)), workflows.ErrAssignmentReplay, 1)

	next := assignment
	next.AssignmentID = "assignment:2"
	next.Sequence++
	failed := check(sign(next), 3, "failed")
	if failed.Reason == nil || *failed.Reason != "permission_denied" || len(failed.Evidence) != 0 || calls != 2 {
		t.Fatalf("incorrect failed outcome: %+v, %d calls", failed, calls)
	}
	reject(encode(sign(next)), workflows.ErrAssignmentReplay, 2)

	store, err = openIdentityStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	err = store.root.Remove(sequenceFile)
	store.close()
	if err != nil {
		t.Fatal(err)
	}
	third := next
	third.AssignmentID = "assignment:3"
	third.Sequence++
	if result, err := runRaw(encode(sign(third))); err == nil || result.Signature != "" || calls != 2 {
		t.Fatalf("lost device sequence state started work: %v, %d calls", err, calls)
	}
}
