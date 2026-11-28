package workflows

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ProbeRunner executes probes in a bounded worker provided by the endpoint. A
// slot remains occupied until that worker has exited and been reaped.
type ProbeRunner struct {
	slots   chan struct{}
	execute func(context.Context, Request) ([]byte, error)
}

func NewProbeRunner(execute func(context.Context, Request) ([]byte, error)) *ProbeRunner {
	return &ProbeRunner{slots: make(chan struct{}, 1), execute: execute}
}

func (r *ProbeRunner) Run(ctx context.Context, req Request) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	return r.run(ctx, req, time.Time{}, time.Now().Add(time.Duration(req.Budget.WallSeconds)*time.Second))
}

// RunAssigned verifies the pinned controller and target before allocating a
// worker. Assignment delivery and durable deduplication are caller concerns.
func (r *ProbeRunner) RunAssigned(ctx context.Context, a contracts.DiagnosticAssignmentV1, key ed25519.PublicKey, deployment, device string) ([]byte, error) {
	if err := verifyAssignmentTarget(a, key, deployment, device); err != nil {
		return nil, err
	}
	started := time.Now()
	if a.CanStart(started) != nil {
		return nil, &Failure{Reason: ReasonExpired, Detail: "deadline_exceeded"}
	}
	deadline, _ := time.Parse(time.RFC3339, a.ExpiresAt)
	return r.run(ctx, Request{ProbeID: a.ProbeID, Arguments: a.Arguments, Budget: a.Budget}, deadline, started.Add(time.Duration(a.Budget.WallSeconds)*time.Second))
}

func verifyAssignmentTarget(a contracts.DiagnosticAssignmentV1, key ed25519.PublicKey, deployment, device string) error {
	if a.Validate() != nil {
		return ErrAssignmentInvalid
	}
	if a.VerifySignature(key) != nil || a.DeploymentID != deployment || a.DeviceID != device {
		return ErrAssignmentUnauthorized
	}
	return nil
}

func (r *ProbeRunner) run(ctx context.Context, req Request, expires, deadline time.Time) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, stoppedProbe(err, false)
	}
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	default:
		return nil, &Failure{Reason: ReasonBudgetExhausted, Detail: "concurrency_budget"}
	}
	signedDeadline := !expires.IsZero() && !deadline.Before(expires)
	if signedDeadline {
		deadline = expires
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, stoppedProbe(err, signedDeadline && !time.Now().Before(expires))
	}
	data, err := r.execute(ctx, req)
	var failure *Failure
	// A worker may cross a limit and then be reaped after the caller's
	// deadline. Preserve the resource reason it already observed.
	if errors.As(err, &failure) && failure.Reason == ReasonBudgetExhausted {
		switch failure.Detail {
		case "cpu_budget", "memory_budget", "output_budget":
			return nil, &Failure{Reason: failure.Reason, Detail: failure.Detail}
		}
	}
	if ctx.Err() != nil {
		return nil, stoppedProbe(ctx.Err(), signedDeadline && !time.Now().Before(expires))
	}
	if errors.As(err, &failure) && len(failure.Partial) > int(req.Budget.MaxOutputBytes) {
		return nil, &Failure{Reason: failure.Reason, Detail: failure.Detail}
	}
	if len(data) > int(req.Budget.MaxOutputBytes) {
		return nil, &Failure{Reason: ReasonBudgetExhausted, Detail: "output_budget"}
	}
	return data, err
}

func stoppedProbe(err error, signedDeadline bool) *Failure {
	if errors.Is(err, context.Canceled) {
		return &Failure{Reason: ReasonCancelled, Detail: "cancel_requested"}
	}
	if signedDeadline {
		return &Failure{Reason: ReasonExpired, Detail: "deadline_exceeded"}
	}
	return &Failure{Reason: ReasonBudgetExhausted, Detail: "wall_budget"}
}
