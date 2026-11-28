package workflows

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// AssignmentStatus is the lifecycle state of one signed diagnostic assignment.
type AssignmentStatus string

const (
	StatusPending         AssignmentStatus = "pending"
	StatusLeased          AssignmentStatus = "leased"
	StatusCancelRequested AssignmentStatus = "cancel_requested"
	StatusSucceeded       AssignmentStatus = "succeeded"
	StatusFailed          AssignmentStatus = "failed"
	StatusCancelled       AssignmentStatus = "cancelled"
	StatusExpired         AssignmentStatus = "expired"
	StatusRebooted        AssignmentStatus = "rebooted"
	StatusRejected        AssignmentStatus = "rejected"
)

// IsTerminal reports whether status is final and can never transition again.
func (s AssignmentStatus) IsTerminal() bool {
	switch s {
	case StatusSucceeded, StatusFailed, StatusCancelled, StatusExpired, StatusRebooted, StatusRejected:
		return true
	default:
		return false
	}
}

var (
	ErrAssignmentInvalid       = errors.New("diagnostic assignment is invalid")
	ErrAssignmentNotFound      = errors.New("diagnostic assignment not found")
	ErrAssignmentConflict      = errors.New("diagnostic assignment conflicts with committed state")
	ErrAssignmentExpired       = errors.New("diagnostic assignment or delivery lease is expired")
	ErrAssignmentReplay        = errors.New("diagnostic result sequence is stale or replayed")
	ErrAssignmentUnauthorized  = errors.New("diagnostic assignment or result signature is unauthorized")
	ErrAssignmentDeviceRevoked = errors.New("diagnostic target device is revoked")
	ErrAssignmentTerminal      = errors.New("diagnostic assignment is already in a terminal state")
	ErrAssignmentCorrupt       = errors.New("stored diagnostic assignment or result failed integrity verification")
)

// Actor identifies the authenticated administrator session behind an action.
type Actor = contracts.ModelActorV1

// AssignmentRequest is an operator request to sign and enqueue one allowlisted
// read-only diagnostic probe for an enrolled, non-revoked device.
type AssignmentRequest struct {
	AssignmentID     string                          `json:"assignment_id"`
	DeviceID         string                          `json:"device_id"`
	ProbeID          string                          `json:"probe_id"`
	Arguments        contracts.DiagnosticArgumentsV1 `json:"arguments"`
	Budget           contracts.DiagnosticBudgetV1    `json:"budget"`
	ExpiresInSeconds uint32                          `json:"expires_in_seconds"`
}

// AssignmentEvent records one durable state transition of an assignment.
type AssignmentEvent struct {
	FromStatus string    `json:"from_status,omitempty"`
	ToStatus   string    `json:"to_status"`
	Reason     string    `json:"reason"`
	At         time.Time `json:"at"`
	By         *Actor    `json:"by,omitempty"`
}

// AssignmentRecord is the controller's durable view of one signed assignment,
// its lease/cancellation status, transition history, and terminal result.
type AssignmentRecord struct {
	SchemaVersion       string                           `json:"schema_version"`
	DeploymentID        string                           `json:"deployment_id"`
	AssignmentID        string                           `json:"assignment_id"`
	AssignmentSHA256    string                           `json:"assignment_sha256"`
	DeviceID            string                           `json:"device_id"`
	ProbeID             string                           `json:"probe_id"`
	Status              AssignmentStatus                 `json:"status"`
	AssignmentSequence  uint64                           `json:"assignment_sequence"`
	IssuedAt            time.Time                        `json:"issued_at"`
	ExpiresAt           time.Time                        `json:"expires_at"`
	DeliveryCount       uint32                           `json:"delivery_count"`
	FirstDispatchedAt   *time.Time                       `json:"first_dispatched_at"`
	LastDispatchedAt    *time.Time                       `json:"last_dispatched_at"`
	LeaseExpiresAt      *time.Time                       `json:"lease_expires_at"`
	CancelRequested     bool                             `json:"cancel_requested"`
	CancelRequestedAt   *time.Time                       `json:"cancel_requested_at"`
	CancelledBy         *Actor                           `json:"cancelled_by,omitempty"`
	TerminalReason      *string                          `json:"terminal_reason"`
	TerminalAt          *time.Time                       `json:"terminal_at"`
	CreatedAt           time.Time                        `json:"created_at"`
	RequestedBy         Actor                            `json:"requested_by"`
	SignedAssignment    contracts.DiagnosticAssignmentV1 `json:"signed_assignment"`
	Result              *contracts.DiagnosticResultV1    `json:"result"`
	ResultRequestSHA256 *string                          `json:"result_request_sha256"`
	ResultAcceptedAt    *time.Time                       `json:"result_accepted_at"`
	Events              []AssignmentEvent                `json:"events"`
}

// AssignmentListPage is one bounded page of assignments for a device.
type AssignmentListPage struct {
	SchemaVersion string             `json:"schema_version"`
	DeploymentID  string             `json:"deployment_id"`
	DeviceID      string             `json:"device_id"`
	Assignments   []AssignmentRecord `json:"assignments"`
	NextAfter     *string            `json:"next_after"`
}

// PollResponse carries signed assignments leased to an authenticated device peer
// alongside any assignment IDs with active cancellation requests.
type PollResponse struct {
	Status              string                             `json:"status"`
	DeviceID            string                             `json:"device_id"`
	PolledAt            time.Time                          `json:"polled_at"`
	LeaseExpiresAt      *time.Time                         `json:"lease_expires_at"`
	Assignments         []contracts.DiagnosticAssignmentV1 `json:"assignments"`
	CancelAssignmentIDs []string                           `json:"cancel_assignment_ids"`
}

// ResultReceipt acknowledges durable terminal ingestion over the mesh.
type ResultReceipt struct {
	Status       string `json:"status"`
	AssignmentID string `json:"assignment_id,omitempty"`
	DeviceID     string `json:"device_id,omitempty"`
	State        string `json:"state,omitempty"`
	Sequence     uint64 `json:"sequence,omitempty"`
	AcceptedAt   string `json:"accepted_at,omitempty"`
	Created      bool   `json:"created,omitempty"`
	Reason       string `json:"rejection_reason,omitempty"`
}

// AssignmentCoordinator manages signed diagnostic assignments and terminal
// results in durable storage.
type AssignmentCoordinator interface {
	CreateDiagnosticAssignment(ctx context.Context, req AssignmentRequest, signer ed25519.PrivateKey, by Actor) (AssignmentRecord, bool, error)
	CancelDiagnosticAssignment(ctx context.Context, assignmentID string, by Actor) (AssignmentRecord, error)
	DiagnosticAssignment(ctx context.Context, assignmentID string) (AssignmentRecord, error)
	ListDeviceDiagnosticAssignments(ctx context.Context, deviceID string, limit int, after string) (AssignmentListPage, error)
	PollDiagnosticAssignments(ctx context.Context, deviceID string, leaseTTL time.Duration) (PollResponse, error)
	SubmitDiagnosticResult(ctx context.Context, result contracts.DiagnosticResultV1) (AssignmentRecord, bool, error)
}

// ExecuteAssignedToResult runs one signed assignment under controller/target
// verification and produces a device-signed DiagnosticResultV1 reporting its
// bounded terminal outcome (`succeeded`, `failed`, `cancelled`, `expired`, or
// `rejected`) with SHA-256 evidence digest binding.
func ExecuteAssignedToResult(
	ctx context.Context,
	runner *ProbeRunner,
	a contracts.DiagnosticAssignmentV1,
	controllerPub ed25519.PublicKey,
	deviceSigningKey ed25519.PrivateKey,
	deployment, device, bootID, evidenceRefID string,
	resultSequence uint64,
	now func() time.Time,
) (contracts.DiagnosticResultV1, error) {
	if now == nil {
		now = time.Now
	}
	if len(controllerPub) != ed25519.PublicKeySize || len(deviceSigningKey) != ed25519.PrivateKeySize {
		return contracts.DiagnosticResultV1{}, ErrAssignmentUnauthorized
	}
	signingBytes, err := a.SigningBytes()
	if err != nil {
		return contracts.DiagnosticResultV1{}, fmt.Errorf("%w: %v", ErrAssignmentInvalid, err)
	}
	assignDigest, err := contracts.EnvelopeRequestSHA256V1(signingBytes, a.Signature)
	if err != nil {
		return contracts.DiagnosticResultV1{}, fmt.Errorf("%w: %v", ErrAssignmentInvalid, err)
	}
	deviceKeyID, err := contracts.SigningKeyIDV1(deviceSigningKey.Public().(ed25519.PublicKey))
	if err != nil {
		return contracts.DiagnosticResultV1{}, err
	}

	buildResult := func(startedAt *string, finishedAt time.Time, state string, reason *string, evidence []contracts.DiagnosticEvidenceV1) (contracts.DiagnosticResultV1, error) {
		issued := now().UTC().Truncate(time.Second)
		if finishedAt.After(issued) {
			issued = finishedAt
		}
		res := contracts.DiagnosticResultV1{
			EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
				SchemaVersion: contracts.DiagnosticResultV1Version,
				DeploymentID:  deployment,
				DeviceID:      device,
				SigningKeyID:  deviceKeyID,
				Sequence:      resultSequence,
				IssuedAt:      issued.Format(time.RFC3339),
				ExpiresAt:     issued.Add(time.Hour).Format(time.RFC3339),
			},
			AssignmentID:     a.AssignmentID,
			AssignmentSHA256: assignDigest,
			BootID:           bootID,
			StartedAt:        startedAt,
			FinishedAt:       finishedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
			State:            state,
			Reason:           reason,
			Evidence:         evidence,
		}
		if res.Evidence == nil {
			res.Evidence = []contracts.DiagnosticEvidenceV1{}
		}
		msg, err := res.SigningBytes()
		if err != nil {
			return contracts.DiagnosticResultV1{}, err
		}
		res.Signature = hex.EncodeToString(ed25519.Sign(deviceSigningKey, msg))
		return res, nil
	}

	if a.VerifySignature(controllerPub) != nil || a.DeploymentID != deployment || a.DeviceID != device {
		reason := "assignment_denied"
		return buildResult(nil, now().UTC().Truncate(time.Second), string(StatusRejected), &reason, nil)
	}
	if a.CanStart(now().UTC().Truncate(time.Second)) != nil {
		reason := "deadline_exceeded"
		return buildResult(nil, now().UTC().Truncate(time.Second), string(StatusExpired), &reason, nil)
	}

	nowUTC := now().UTC()
	started := nowUTC.Truncate(time.Second)
	startedStr := started.Format(time.RFC3339)
	deadline, _ := time.Parse(time.RFC3339, a.ExpiresAt)
	// Translate synthetic/caller clock remaining lifetime to wall-clock context deadline.
	realDeadline := time.Now().Add(deadline.Sub(nowUTC))
	output, runErr := runner.run(ctx, Request{ProbeID: a.ProbeID, Arguments: a.Arguments, Budget: a.Budget}, realDeadline)
	finished := now().UTC().Truncate(time.Second)
	if finished.Before(started) {
		finished = started
	}

	if runErr == nil {
		sum := sha256.Sum256(output)
		return buildResult(&startedStr, finished, string(StatusSucceeded), nil, []contracts.DiagnosticEvidenceV1{{
			ReferenceID: evidenceRefID,
			SHA256:      hex.EncodeToString(sum[:]),
			SizeBytes:   uint32(len(output)),
		}})
	}

	var failure *Failure
	if errors.As(runErr, &failure) {
		switch failure.Reason {
		case ReasonCancelled:
			r := "cancel_requested"
			return buildResult(&startedStr, finished, string(StatusCancelled), &r, nil)
		case ReasonExpired:
			if finished.Before(deadline) {
				finished = deadline
			}
			r := "deadline_exceeded"
			return buildResult(&startedStr, finished, string(StatusExpired), &r, nil)
		case ReasonBudgetExhausted:
			r := "budget_exhausted"
			return buildResult(&startedStr, finished, string(StatusFailed), &r, partialEvidence(evidenceRefID, failure.Partial))
		case ReasonPermissionDenied:
			r := "permission_denied"
			return buildResult(&startedStr, finished, string(StatusFailed), &r, partialEvidence(evidenceRefID, failure.Partial))
		default:
			r := "probe_error"
			return buildResult(&startedStr, finished, string(StatusFailed), &r, partialEvidence(evidenceRefID, failure.Partial))
		}
	}
	r := "probe_error"
	return buildResult(&startedStr, finished, string(StatusFailed), &r, nil)
}

func partialEvidence(refID string, partial []byte) []contracts.DiagnosticEvidenceV1 {
	if len(partial) == 0 {
		return nil
	}
	sum := sha256.Sum256(partial)
	return []contracts.DiagnosticEvidenceV1{{
		ReferenceID: refID,
		SHA256:      hex.EncodeToString(sum[:]),
		SizeBytes:   uint32(len(partial)),
	}}
}
