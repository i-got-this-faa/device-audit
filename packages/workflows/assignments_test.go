package workflows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestExecuteDiagnosticAssignmentTransitions(t *testing.T) {
	ctrlPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	ctrlPub := ctrlPriv.Public().(ed25519.PublicKey)
	ctrlKeyID, _ := contracts.SigningKeyIDV1(ctrlPub)
	devPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	devPub := devPriv.Public().(ed25519.PublicKey)

	now := time.Now().UTC().Truncate(time.Second)
	comp := "storage:disk-0"
	a := contracts.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticAssignmentV1Version,
			DeploymentID:  "deployment:diag",
			DeviceID:      "device:diag",
			SigningKeyID:  ctrlKeyID,
			Sequence:      1,
			IssuedAt:      now.Format(time.RFC3339),
			ExpiresAt:     now.Add(10 * time.Minute).Format(time.RFC3339),
		},
		AssignmentID: "assign:1",
		ProbeID:      contracts.DiagnosticProbeStorageHealthV1,
		Arguments:    contracts.DiagnosticArgumentsV1{ComponentID: &comp},
		Budget:       contracts.DiagnosticBudgetV1{WallSeconds: 10, MaxOutputBytes: 4096},
	}
	msg, err := a.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(ctrlPriv, msg))

	execution := AssignmentExecution{
		DeploymentID: a.DeploymentID, DeviceID: a.DeviceID, BootID: "boot:1", SigningKey: devPriv,
		Claim:        func(string, time.Time) (uint64, error) { return 2, nil },
		SaveEvidence: func([]byte) (string, error) { return "ref:1", nil },
	}
	runner := NewProbeRunner(func(_ context.Context, _ Request) ([]byte, error) {
		return []byte("{}"), nil
	})
	res, err := ExecuteDiagnosticAssignment(context.Background(), runner, a, ctrlPub, execution)
	if err != nil || res.State != "succeeded" || res.VerifySignature(devPub) != nil || res.CheckAssignment(a) != nil {
		t.Fatalf("succeeded result failed: state=%s err=%v verify=%v check=%v", res.State, err, res.VerifySignature(devPub), res.CheckAssignment(a))
	}

	// Cancel after durable admission and before starting the worker.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	execution.Claim = func(string, time.Time) (uint64, error) {
		cancel()
		return 3, nil
	}
	runner = NewProbeRunner(func(context.Context, Request) ([]byte, error) {
		t.Fatal("cancelled assignment started a probe")
		return nil, nil
	})
	canc, err := ExecuteDiagnosticAssignment(ctx, runner, a, ctrlPub, execution)
	if err != nil || canc.State != "cancelled" || canc.StartedAt != nil || canc.CheckAssignment(a) != nil || canc.VerifySignature(devPub) != nil {
		t.Fatalf("cancelled result failed: state=%s err=%v check=%v", canc.State, err, canc.CheckAssignment(a))
	}

	execution.Claim = func(string, time.Time) (uint64, error) { return 4, nil }
	execution.SaveEvidence = func([]byte) (string, error) { return "", errors.New("disk unavailable") }
	runner = NewProbeRunner(func(context.Context, Request) ([]byte, error) { return []byte("{}"), nil })
	failed, err := ExecuteDiagnosticAssignment(context.Background(), runner, a, ctrlPub, execution)
	if err != nil || failed.State != "failed" || len(failed.Evidence) != 0 || failed.CheckAssignment(a) != nil || failed.VerifySignature(devPub) != nil {
		t.Fatalf("failed evidence write: state=%s err=%v", failed.State, err)
	}
}
