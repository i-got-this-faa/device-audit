package workflows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestExecuteAssignedToResultTransitions(t *testing.T) {
	ctrlPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	ctrlPub := ctrlPriv.Public().(ed25519.PublicKey)
	ctrlKeyID, _ := contracts.SigningKeyIDV1(ctrlPub)
	devPriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	devPub := devPriv.Public().(ed25519.PublicKey)

	now := time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC)
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

	runner := NewProbeRunner(func(_ context.Context, _ Request) ([]byte, error) {
		return []byte(`{"schema_version":"device-audit.probe-evidence.v1","status":"ok"}`), nil
	})
	res, err := ExecuteAssignedToResult(context.Background(), runner, a, ctrlPub, devPriv, "deployment:diag", "device:diag", "boot:1", "ref:1", 2, func() time.Time { return now })
	if err != nil || res.State != "succeeded" || res.VerifySignature(devPub) != nil || res.CheckAssignment(a) != nil {
		t.Fatalf("succeeded result failed: state=%s err=%v verify=%v check=%v", res.State, err, res.VerifySignature(devPub), res.CheckAssignment(a))
	}

	// Wrong target yields signed rejected result without calling probe.
	called := 0
	badTargetRunner := NewProbeRunner(func(_ context.Context, _ Request) ([]byte, error) {
		called++
		return nil, nil
	})
	rej, err := ExecuteAssignedToResult(context.Background(), badTargetRunner, a, ctrlPub, devPriv, "deployment:diag", "device:other", "boot:1", "ref:1", 2, func() time.Time { return now })
	if err != nil || called != 0 || rej.State != "rejected" {
		t.Fatalf("wrong target state=%s called=%d err=%v", rej.State, called, err)
	}

	// Canceled context produces signed cancelled terminal result.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canc, err := ExecuteAssignedToResult(ctx, runner, a, ctrlPub, devPriv, "deployment:diag", "device:diag", "boot:1", "ref:1", 2, func() time.Time { return now })
	if err != nil || canc.State != "cancelled" || canc.CheckAssignment(a) != nil {
		t.Fatalf("cancelled result failed: state=%s err=%v check=%v", canc.State, err, canc.CheckAssignment(a))
	}
}
