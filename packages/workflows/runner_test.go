package workflows

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestProbeRunnerSignedBudgetAndConcurrency(t *testing.T) {
	key, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := contracts.SigningKeyIDV1(key)
	component := "storage:disk-0"
	now := time.Now().UTC().Truncate(time.Second)
	a := contracts.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticAssignmentV1Version, DeploymentID: "deployment", DeviceID: "device",
			SigningKeyID: kid, Sequence: 1, IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
		},
		AssignmentID: "assignment", ProbeID: contracts.DiagnosticProbeStorageHealthV1,
		Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &component}, Budget: contracts.DiagnosticBudgetV1{WallSeconds: 5, MaxOutputBytes: 128},
	}
	sign := func() {
		t.Helper()
		message, err := a.SigningBytes()
		if err != nil {
			t.Fatal(err)
		}
		a.Signature = hex.EncodeToString(ed25519.Sign(private, message))
	}
	sign()
	started := make(chan Request, 1)
	var calls atomic.Int32
	runner := NewProbeRunner(func(ctx context.Context, req Request) ([]byte, error) {
		calls.Add(1)
		started <- req
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if _, err := runner.RunAssigned(context.Background(), a, key, "deployment", "wrong"); err == nil || calls.Load() != 0 {
		t.Fatal("wrong target reached worker")
	}
	tampered := a
	tampered.Budget.MaxOutputBytes++
	if _, err := runner.RunAssigned(context.Background(), tampered, key, "deployment", "device"); err == nil || calls.Load() != 0 {
		t.Fatal("unsigned budget change reached worker")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := runner.RunAssigned(ctx, a, key, "deployment", "device")
		done <- err
	}()
	var req Request
	select {
	case req = <-started:
	case <-time.After(time.Second):
		t.Fatal("valid signed assignment did not start")
	}
	if req.Budget != a.Budget {
		t.Fatal("worker did not receive the signed budget")
	}
	var failure *Failure
	if _, err := runner.Run(context.Background(), req); !errors.As(err, &failure) || failure.Detail != "concurrency_budget" {
		t.Fatalf("concurrent probe: %v", err)
	}
	cancel()
	if err := <-done; !errors.As(err, &failure) || failure.Reason != ReasonCancelled {
		t.Fatalf("cancellation: %v", err)
	}
	a.ExpiresAt = now.Add(-time.Second).Format(time.RFC3339)
	sign()
	if _, err := runner.RunAssigned(context.Background(), a, key, "deployment", "device"); !errors.As(err, &failure) || failure.Reason != ReasonExpired || calls.Load() != 1 {
		t.Fatalf("expired assignment: %v", err)
	}
}
