package workflows

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// AssignmentExecution supplies the admitted identity and durable storage for
// one assignment. Claim must atomically exclude another execution of the same
// assignment and reserve a device evidence sequence before returning.
type AssignmentExecution struct {
	DeploymentID string
	DeviceID     string
	BootID       string
	SigningKey   ed25519.PrivateKey
	Claim        func(assignmentDigest string, admittedAt time.Time) (uint64, error)
	SaveEvidence func(output []byte) (referenceID string, err error)
}

var diagnosticOpaqueID = regexp.MustCompile(contracts.OpaqueIDPattern)

// ExecuteDiagnosticAssignment authenticates and claims the assignment before
// starting a worker. Only authenticated, admitted execution can sign a result.
func ExecuteDiagnosticAssignment(ctx context.Context, runner *ProbeRunner, a contracts.DiagnosticAssignmentV1, authority ed25519.PublicKey, execution AssignmentExecution) (contracts.DiagnosticResultV1, error) {
	return executeAssignment(ctx, runner, a, authority, execution, time.Now)
}

// ExecuteAssignedToResult is the low-level adapter for callers that already
// manage sequence reservation and evidence references.
func ExecuteAssignedToResult(ctx context.Context, runner *ProbeRunner, a contracts.DiagnosticAssignmentV1, authority ed25519.PublicKey, signingKey ed25519.PrivateKey, deployment, device, bootID, evidenceRefID string, sequence uint64, now func() time.Time) (contracts.DiagnosticResultV1, error) {
	if now == nil {
		now = time.Now
	}
	return executeAssignment(ctx, runner, a, authority, AssignmentExecution{
		DeploymentID: deployment, DeviceID: device, BootID: bootID, SigningKey: signingKey,
		Claim:        func(string, time.Time) (uint64, error) { return sequence, nil },
		SaveEvidence: func([]byte) (string, error) { return evidenceRefID, nil },
	}, now)
}

func executeAssignment(ctx context.Context, runner *ProbeRunner, a contracts.DiagnosticAssignmentV1, authority ed25519.PublicKey, execution AssignmentExecution, now func() time.Time) (contracts.DiagnosticResultV1, error) {
	empty := contracts.DiagnosticResultV1{}
	if err := verifyAssignmentTarget(a, authority, execution.DeploymentID, execution.DeviceID); err != nil {
		return empty, err
	}
	if len(execution.SigningKey) != ed25519.PrivateKeySize || !diagnosticOpaqueID.MatchString(execution.BootID) || execution.Claim == nil || execution.SaveEvidence == nil {
		return empty, ErrAssignmentInvalid
	}
	if a.CanStart(now()) != nil {
		return empty, ErrAssignmentExpired
	}
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	msg, _ := a.SigningBytes()
	digest, _ := contracts.EnvelopeRequestSHA256V1(msg, a.Signature)
	seq, err := execution.Claim(digest, now().UTC())
	if err != nil {
		return empty, err
	}
	if seq < contracts.FirstEvidenceSequenceV1 || seq > contracts.MaxEnvelopeSequence {
		return empty, ErrAssignmentInvalid
	}

	started := now()
	deadline, _ := time.Parse(time.RFC3339, a.ExpiresAt)
	deviceKey := execution.SigningKey.Public().(ed25519.PublicKey)
	deviceKeyID, _ := contracts.SigningKeyIDV1(deviceKey)
	result := contracts.DiagnosticResultV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticResultV1Version,
			DeploymentID:  execution.DeploymentID,
			DeviceID:      execution.DeviceID,
			SigningKeyID:  deviceKeyID,
			Sequence:      seq,
		},
		AssignmentID:     a.AssignmentID,
		AssignmentSHA256: digest,
		BootID:           execution.BootID,
		Evidence:         []contracts.DiagnosticEvidenceV1{},
	}
	finished := started
	switch {
	case !started.Before(deadline):
		result.State = string(StatusExpired)
		reason := "deadline_exceeded"
		result.Reason = &reason
	case a.CanStart(started) != nil:
		// CT06 expiry requires observation at or after the signed deadline.
		return empty, ErrAssignmentExpired
	case ctx.Err() != nil:
		result.State = string(StatusCancelled)
		reason := "cancel_requested"
		result.Reason = &reason
	default:
		start := started.UTC().Truncate(time.Second).Format(time.RFC3339)
		result.StartedAt = &start
		limit := started.Add(time.Duration(a.Budget.WallSeconds) * time.Second)
		// Match the runner's monotonic clock to the assignment clock.
		observed := now()
		wall := time.Now()
		output, runErr := runner.run(ctx, Request{ProbeID: a.ProbeID, Arguments: a.Arguments, Budget: a.Budget}, wall.Add(deadline.Sub(observed)), wall.Add(limit.Sub(observed)))
		finished = now()
		result.State, result.Reason, output = diagnosticOutcome(output, runErr)
		if result.State == string(StatusExpired) && finished.Before(deadline) {
			finished = deadline
		}
		if result.State != string(StatusExpired) {
			// A killed worker can finish reaping after the execution cut-off.
			if finished.After(limit) {
				finished = limit
			}
		}
		if len(output) > 0 {
			ref, saveErr := execution.SaveEvidence(output)
			if saveErr != nil || !diagnosticOpaqueID.MatchString(ref) {
				result.State = string(StatusFailed)
				reason := "probe_error"
				result.Reason = &reason
			} else {
				sum := sha256.Sum256(output)
				result.Evidence = append(result.Evidence, contracts.DiagnosticEvidenceV1{
					ReferenceID: ref, SHA256: hex.EncodeToString(sum[:]), SizeBytes: uint32(len(output)),
				})
			}
		}
	}
	issued := now().UTC()
	if issued.Before(finished) {
		issued = finished.UTC()
	}
	result.FinishedAt = finished.UTC().Truncate(time.Second).Format(time.RFC3339)
	result.IssuedAt = issued.Truncate(time.Second).Format(time.RFC3339)
	result.ExpiresAt = issued.Add(time.Hour).Truncate(time.Second).Format(time.RFC3339)
	message, err := result.SigningBytes()
	if err != nil {
		return empty, err
	}
	result.Signature = hex.EncodeToString(ed25519.Sign(execution.SigningKey, message))
	if err := result.CheckAssignment(a); err != nil {
		return empty, err
	}
	return result, result.VerifySignature(deviceKey)
}

func diagnosticOutcome(output []byte, err error) (string, *string, []byte) {
	if err == nil && len(output) > 0 {
		return string(StatusSucceeded), nil, output
	}
	state, reason := StatusFailed, "probe_error"
	var failure *Failure
	if !errors.As(err, &failure) {
		return string(state), &reason, nil
	}
	switch failure.Reason {
	case ReasonCancelled:
		state, reason = StatusCancelled, "cancel_requested"
		return string(state), &reason, nil
	case ReasonExpired:
		state, reason = StatusExpired, "deadline_exceeded"
		return string(state), &reason, nil
	case ReasonBudgetExhausted:
		reason = "budget_exhausted"
	case ReasonPermissionDenied:
		reason = "permission_denied"
	}
	return string(state), &reason, failure.Partial
}
