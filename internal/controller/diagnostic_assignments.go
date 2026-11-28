package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

const (
	DiagnosticAssignmentRecordVersion = "device-audit.diagnostic-assignment-record.v1"
	DiagnosticAssignmentListVersion   = "device-audit.diagnostic-assignment-list.v1"
	defaultDiagnosticLeaseTTL         = 6 * time.Minute
	maxDiagnosticLeaseTTL             = 24 * time.Hour
	diagnosticPageMax                 = 100
	diagnosticPageDefault             = 50
)

var _ workflows.AssignmentCoordinator = (*PostgresRepository)(nil)

// CreateDiagnosticAssignment validates, signs, and persistently queues one
// device-bound expiring diagnostic assignment using a monotonic controller-per-device
// sequence. Refuses unknown or revoked devices and conflicting retries.
func (s *PostgresRepository) CreateDiagnosticAssignment(ctx context.Context, req workflows.AssignmentRequest, signer ed25519.PrivateKey, by workflows.Actor) (workflows.AssignmentRecord, bool, error) {
	if !repositoryIDPattern.MatchString(req.AssignmentID) || !repositoryIDPattern.MatchString(req.DeviceID) {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: invalid assignment_id or device_id", workflows.ErrAssignmentInvalid)
	}
	if err := req.Arguments.ValidateFor(req.ProbeID); err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	if req.Budget.WallSeconds < 1 || req.Budget.WallSeconds > 300 || req.Budget.MaxOutputBytes < 1 || req.Budget.MaxOutputBytes > 1048576 {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: invalid diagnostic budget", workflows.ErrAssignmentInvalid)
	}
	expiresSec := time.Duration(req.ExpiresInSeconds) * time.Second
	if req.ExpiresInSeconds == 0 || expiresSec > 24*time.Hour || req.ExpiresInSeconds < req.Budget.WallSeconds {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: expires_in_seconds must fit wall_seconds within 24h", workflows.ErrAssignmentInvalid)
	}
	if len(signer) != ed25519.PrivateKeySize {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: diagnostic signing key required", workflows.ErrAssignmentInvalid)
	}
	if err := by.Validate(); err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	controllerPub := signer.Public().(ed25519.PublicKey)
	controllerKeyID, err := contracts.SigningKeyIDV1(controllerPub)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	defer tx.Rollback()

	// Lock device enrollment first so creation is ordered strictly against RevokeDevice.
	var revokedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`,
		s.deploymentID, req.DeviceID).Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: unknown device %s", ErrRepositoryNotFound, req.DeviceID)
		}
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}

	// Check existing assignment after enrollment check: an identical retry returns stored state cleanly.
	if existing, found, err := s.readDiagnosticAssignmentTx(ctx, tx, req.AssignmentID); err != nil {
		return workflows.AssignmentRecord{}, false, err
	} else if found {
		if !sameDiagnosticRequest(existing, req) {
			return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: assignment %s already exists with different parameters", workflows.ErrAssignmentConflict, req.AssignmentID)
		}
		tx.Rollback()
		return existing, false, nil
	}

	if revokedAt.Valid {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: device %s is revoked", workflows.ErrAssignmentDeviceRevoked, req.DeviceID)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_controller_sequences (deployment_id, device_id, last_sequence)
		VALUES ($1,$2,0) ON CONFLICT (deployment_id, device_id) DO NOTHING`,
		s.deploymentID, req.DeviceID); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	var seq uint64
	if err := tx.QueryRowContext(ctx, `UPDATE diagnostic_controller_sequences
		SET last_sequence = last_sequence + 1
		WHERE deployment_id=$1 AND device_id=$2
		RETURNING last_sequence`, s.deploymentID, req.DeviceID).Scan(&seq); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	issued := now.Truncate(time.Second)
	expires := issued.Add(expiresSec)
	a := contracts.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: contracts.EnvelopeHeaderV1{
			SchemaVersion: contracts.DiagnosticAssignmentV1Version,
			DeploymentID:  s.deploymentID,
			DeviceID:      req.DeviceID,
			SigningKeyID:  controllerKeyID,
			Sequence:      seq,
			IssuedAt:      issued.Format(time.RFC3339),
			ExpiresAt:     expires.Format(time.RFC3339),
		},
		AssignmentID: req.AssignmentID,
		ProbeID:      req.ProbeID,
		Arguments:    req.Arguments,
		Budget:       req.Budget,
	}
	signingBytes, err := a.SigningBytes()
	if err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	a.Signature = hex.EncodeToString(ed25519.Sign(signer, signingBytes))
	if err := a.VerifySignature(controllerPub); err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	assignSHAHex, err := contracts.EnvelopeRequestSHA256V1(signingBytes, a.Signature)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	assignDigest := decodeRepositoryDigest(assignSHAHex)
	argsJSON, err := json.Marshal(a.Arguments)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	signedJSON, err := json.Marshal(a)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignments (
			deployment_id, assignment_id, device_id, controller_key_id, assignment_sequence,
			assignment_sha256, probe_id, arguments, wall_seconds, max_output_bytes,
			issued_at, expires_at, signed_assignment, status, delivery_count,
			created_at, actor_issuer, actor_subject
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'pending',0,$14,$15,$16)`,
		s.deploymentID, a.AssignmentID, a.DeviceID, a.SigningKeyID, a.Sequence,
		assignDigest, a.ProbeID, string(argsJSON), a.Budget.WallSeconds, a.Budget.MaxOutputBytes,
		issued, expires, string(signedJSON), now, by.Issuer, by.Subject); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignment_events (
			deployment_id, assignment_id, from_status, to_status, reason, at, actor_issuer, actor_subject
		) VALUES ($1,$2,NULL,'pending','created',$3,$4,$5)`,
		s.deploymentID, a.AssignmentID, now, by.Issuer, by.Subject); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}

	rec, _, err := s.readDiagnosticAssignmentTx(ctx, tx, a.AssignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	if err := repositoryCommit(tx); err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	return rec, true, nil
}

// CancelDiagnosticAssignment cancels an assignment or persists an active
// cancellation request on a leased assignment. Already-terminal assignments
// are returned unchanged without creating a second terminal transition.
func (s *PostgresRepository) CancelDiagnosticAssignment(ctx context.Context, assignmentID string, by workflows.Actor) (workflows.AssignmentRecord, error) {
	if !repositoryIDPattern.MatchString(assignmentID) {
		return workflows.AssignmentRecord{}, workflows.ErrAssignmentNotFound
	}
	if err := by.Validate(); err != nil {
		return workflows.AssignmentRecord{}, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return workflows.AssignmentRecord{}, err
	}
	defer tx.Rollback()

	rec, found, err := s.lockDiagnosticAssignmentTx(ctx, tx, assignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, err
	}
	if !found {
		return workflows.AssignmentRecord{}, workflows.ErrAssignmentNotFound
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if changed, err := s.expireAssignmentTx(ctx, tx, rec, now); err != nil {
		return workflows.AssignmentRecord{}, err
	} else if changed {
		rec, _, err = s.readDiagnosticAssignmentTx(ctx, tx, assignmentID)
		if err != nil {
			return workflows.AssignmentRecord{}, err
		}
		if err := repositoryCommit(tx); err != nil {
			return workflows.AssignmentRecord{}, err
		}
		return rec, nil
	}

	switch rec.Status {
	case workflows.StatusPending:
		if _, err := tx.ExecContext(ctx, `UPDATE diagnostic_assignments
			SET status='cancelled', cancel_requested_at=$3, cancel_actor_issuer=$4, cancel_actor_subject=$5,
				terminal_reason='cancel_requested', terminal_at=$3
			WHERE deployment_id=$1 AND assignment_id=$2`,
			s.deploymentID, assignmentID, now, by.Issuer, by.Subject); err != nil {
			return workflows.AssignmentRecord{}, repositoryUnavailable(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignment_events (
				deployment_id, assignment_id, from_status, to_status, reason, at, actor_issuer, actor_subject
			) VALUES ($1,$2,'pending','cancelled','cancel_requested',$3,$4,$5)`,
			s.deploymentID, assignmentID, now, by.Issuer, by.Subject); err != nil {
			return workflows.AssignmentRecord{}, repositoryUnavailable(err)
		}
	case workflows.StatusLeased:
		if _, err := tx.ExecContext(ctx, `UPDATE diagnostic_assignments
			SET status='cancel_requested', cancel_requested_at=$3, cancel_actor_issuer=$4, cancel_actor_subject=$5
			WHERE deployment_id=$1 AND assignment_id=$2`,
			s.deploymentID, assignmentID, now, by.Issuer, by.Subject); err != nil {
			return workflows.AssignmentRecord{}, repositoryUnavailable(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignment_events (
				deployment_id, assignment_id, from_status, to_status, reason, at, actor_issuer, actor_subject
			) VALUES ($1,$2,'leased','cancel_requested','cancel_requested',$3,$4,$5)`,
			s.deploymentID, assignmentID, now, by.Issuer, by.Subject); err != nil {
			return workflows.AssignmentRecord{}, repositoryUnavailable(err)
		}
	case workflows.StatusCancelRequested:
		// Already awaiting cancellation; idempotent without adding another transition.
		tx.Rollback()
		return rec, nil
	default:
		// Terminal states (succeeded, failed, cancelled, expired, rebooted, rejected) stay unchanged.
		tx.Rollback()
		return rec, nil
	}

	updated, _, err := s.readDiagnosticAssignmentTx(ctx, tx, assignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, err
	}
	if err := repositoryCommit(tx); err != nil {
		return workflows.AssignmentRecord{}, err
	}
	return updated, nil
}

// PollDiagnosticAssignments expires overdue dispatch and reporting windows, refuses revoked
// devices, leases an eligible pending assignment when no live lease exists, and returns
// active cancellation IDs.
func (s *PostgresRepository) PollDiagnosticAssignments(ctx context.Context, deviceID string, leaseTTL time.Duration) (workflows.PollResponse, error) {
	if !repositoryIDPattern.MatchString(deviceID) {
		return workflows.PollResponse{}, fmt.Errorf("%w: invalid device_id", workflows.ErrAssignmentInvalid)
	}
	if leaseTTL == 0 {
		leaseTTL = defaultDiagnosticLeaseTTL
	}
	if leaseTTL < time.Second || leaseTTL > maxDiagnosticLeaseTTL {
		return workflows.PollResponse{}, fmt.Errorf("%w: lease TTL must be between 1s and 24h", workflows.ErrAssignmentInvalid)
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return workflows.PollResponse{}, err
	}
	defer tx.Rollback()

	var revokedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`,
		s.deploymentID, deviceID).Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return workflows.PollResponse{}, fmt.Errorf("%w: unknown device %s", ErrRepositoryNotFound, deviceID)
		}
		return workflows.PollResponse{}, repositoryUnavailable(err)
	}
	if revokedAt.Valid {
		return workflows.PollResponse{}, fmt.Errorf("%w: device %s is revoked", workflows.ErrAssignmentDeviceRevoked, deviceID)
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	if err := s.expireDeviceAssignmentsTx(ctx, tx, deviceID, now); err != nil {
		return workflows.PollResponse{}, err
	}

	cancelIDs := []string{}
	cancelRows, err := tx.QueryContext(ctx, `SELECT assignment_id FROM diagnostic_assignments
		WHERE deployment_id=$1 AND device_id=$2 AND status='cancel_requested'
		ORDER BY issued_at ASC, assignment_sequence ASC FOR UPDATE`,
		s.deploymentID, deviceID)
	if err != nil {
		return workflows.PollResponse{}, repositoryUnavailable(err)
	}
	for cancelRows.Next() {
		var id string
		if err := cancelRows.Scan(&id); err != nil {
			cancelRows.Close()
			return workflows.PollResponse{}, repositoryUnavailable(err)
		}
		cancelIDs = append(cancelIDs, id)
	}
	if err := cancelRows.Err(); err != nil {
		cancelRows.Close()
		return workflows.PollResponse{}, repositoryUnavailable(err)
	}
	cancelRows.Close()

	assignments := []contracts.DiagnosticAssignmentV1{}
	var leasePtr *time.Time
	var pendingID string
	var expiresAt time.Time
	var wallSeconds int
	var signedJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT assignment_id, expires_at, wall_seconds, signed_assignment
		FROM diagnostic_assignments
		WHERE deployment_id=$1 AND device_id=$2 AND status='pending'
			AND NOT EXISTS (SELECT 1 FROM diagnostic_assignments
				WHERE deployment_id=$1 AND device_id=$2 AND status IN ('leased','cancel_requested')
					AND lease_expires_at > $3)
		ORDER BY issued_at ASC, assignment_sequence ASC
		LIMIT 1 FOR UPDATE`, s.deploymentID, deviceID, now).
		Scan(&pendingID, &expiresAt, &wallSeconds, &signedJSON)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return workflows.PollResponse{}, repositoryUnavailable(err)
	}
	if err == nil {
		var signed contracts.DiagnosticAssignmentV1
		if json.Unmarshal(signedJSON, &signed) != nil || signed.Validate() != nil {
			return workflows.PollResponse{}, fmt.Errorf("%w: corrupt stored assignment %s", workflows.ErrAssignmentCorrupt, pendingID)
		}
		leaseUntil := now.Add(leaseTTL)
		expUTC := expiresAt.UTC()
		if leaseUntil.After(expUTC) {
			leaseUntil = expUTC
		}
		if _, err := tx.ExecContext(ctx, `UPDATE diagnostic_assignments
			SET status='leased', delivery_count = delivery_count + 1,
				first_dispatched_at = COALESCE(first_dispatched_at, $3),
				last_dispatched_at = $3, lease_expires_at = $4
			WHERE deployment_id=$1 AND assignment_id=$2`,
			s.deploymentID, pendingID, now, leaseUntil); err != nil {
			return workflows.PollResponse{}, repositoryUnavailable(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignment_events (
				deployment_id, assignment_id, from_status, to_status, reason, at
			) VALUES ($1,$2,'pending','leased','dispatched',$3)`,
			s.deploymentID, pendingID, now); err != nil {
			return workflows.PollResponse{}, repositoryUnavailable(err)
		}
		assignments = append(assignments, signed)
		leasePtr = &leaseUntil
	}

	if err := repositoryCommit(tx); err != nil {
		return workflows.PollResponse{}, err
	}
	return workflows.PollResponse{
		Status:              "ok",
		DeviceID:            deviceID,
		PolledAt:            now,
		LeaseExpiresAt:      leasePtr,
		Assignments:         assignments,
		CancelAssignmentIDs: cancelIDs,
	}, nil
}

// SubmitDiagnosticResult validates an enrolled device's signed DiagnosticResultV1
// against its stored assignment and commits at most one terminal transition while
// advancing device_enrollments.last_sequence atomically.
func (s *PostgresRepository) SubmitDiagnosticResult(ctx context.Context, result contracts.DiagnosticResultV1) (workflows.AssignmentRecord, bool, error) {
	if err := result.Validate(); err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	if result.DeploymentID != s.deploymentID {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: deployment mismatch", workflows.ErrAssignmentUnauthorized)
	}
	signingBytes, err := result.SigningBytes()
	if err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	reqDigestHex, err := contracts.EnvelopeRequestSHA256V1(signingBytes, result.Signature)
	if err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}
	reqDigest := decodeRepositoryDigest(reqDigestHex)

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	defer tx.Rollback()

	// Lock enrollment first (ordered strictly with Create, Poll, AcceptEvidence, RevokeDevice).
	var enrolledKey string
	var pubKeyBytes []byte
	var lastSequence uint64
	var revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT signing_key_id, public_key, last_sequence, revoked_at
		FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`,
		s.deploymentID, result.DeviceID).Scan(&enrolledKey, &pubKeyBytes, &lastSequence, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: unknown device %s", workflows.ErrAssignmentUnauthorized, result.DeviceID)
	}
	if err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	if enrolledKey != result.SigningKeyID || len(pubKeyBytes) != ed25519.PublicKeySize {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: signing key mismatch", workflows.ErrAssignmentUnauthorized)
	}
	if revokedAt.Valid {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %w: device %s is revoked", workflows.ErrAssignmentUnauthorized, workflows.ErrAssignmentDeviceRevoked, result.DeviceID)
	}
	if err := result.VerifySignature(ed25519.PublicKey(pubKeyBytes)); err != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentUnauthorized, err)
	}

	rec, found, err := s.lockDiagnosticAssignmentTx(ctx, tx, result.AssignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	if !found {
		return workflows.AssignmentRecord{}, false, workflows.ErrAssignmentNotFound
	}
	if rec.DeviceID != result.DeviceID {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: assignment target device mismatch", workflows.ErrAssignmentUnauthorized)
	}
	if err := result.CheckAssignment(rec.SignedAssignment); err != nil {
		if result.AssignmentSHA256 != rec.AssignmentSHA256 {
			return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentConflict, err)
		}
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %v", workflows.ErrAssignmentInvalid, err)
	}

	// Idempotent duplicate vs conflicting result check after authenticating signature.
	if rec.Result != nil {
		storedDigest := decodeRepositoryDigest(*rec.ResultRequestSHA256)
		if !bytes.Equal(storedDigest, reqDigest) || rec.Result.Sequence != result.Sequence || !sameDiagnosticResult(*rec.Result, result) {
			return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: conflicting terminal result for %s", workflows.ErrAssignmentConflict, result.AssignmentID)
		}
		tx.Rollback()
		return rec, false, nil
	}

	if rec.Status.IsTerminal() {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %w: assignment is already %s", workflows.ErrAssignmentTerminal, workflows.ErrAssignmentConflict, rec.Status)
	}
	if rec.Status == workflows.StatusPending {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: assignment has not been dispatched", workflows.ErrAssignmentConflict)
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	if changed, err := s.expireAssignmentTx(ctx, tx, rec, now); err != nil {
		return workflows.AssignmentRecord{}, false, err
	} else if changed {
		if err := repositoryCommit(tx); err != nil {
			return workflows.AssignmentRecord{}, false, err
		}
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: %w: reporting window expired before result ingestion", workflows.ErrAssignmentExpired, workflows.ErrAssignmentTerminal)
	}

	rIssued, _ := time.Parse(time.RFC3339, result.IssuedAt)
	rExpires, _ := time.Parse(time.RFC3339, result.ExpiresAt)
	if !now.Before(rExpires) {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: result envelope expired", workflows.ErrAssignmentExpired)
	}
	if rIssued.After(now.Add(contracts.EnvelopeMaxFutureSkewV1)) {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: result issued ahead of controller clock", workflows.ErrAssignmentInvalid)
	}
	if result.Sequence <= lastSequence {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: sequence %d <= durable mark %d", workflows.ErrAssignmentReplay, result.Sequence, lastSequence)
	}

	var startedAt sql.NullTime
	if result.StartedAt != nil {
		st, _ := time.Parse(time.RFC3339, *result.StartedAt)
		if rec.LeaseExpiresAt == nil || !st.Before(*rec.LeaseExpiresAt) {
			return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: probe started after its dispatch lease", workflows.ErrAssignmentInvalid)
		}
		startedAt = sql.NullTime{Time: st.UTC(), Valid: true}
	}
	finishedAt, _ := time.Parse(time.RFC3339, result.FinishedAt)
	var reasonSQL sql.NullString
	termReason := result.State
	if result.Reason != nil {
		reasonSQL = sql.NullString{String: *result.Reason, Valid: true}
		termReason = *result.Reason
	}
	evidenceJSON, err := json.Marshal(result.Evidence)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	envelopeJSON, err := json.Marshal(result)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_results (
			deployment_id, assignment_id, device_id, signing_key_id, sequence,
			assignment_sha256, request_sha256, boot_id, started_at, finished_at,
			issued_at, expires_at, state, reason, evidence, envelope, accepted_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		s.deploymentID, result.AssignmentID, result.DeviceID, result.SigningKeyID, result.Sequence,
		decodeRepositoryDigest(result.AssignmentSHA256), reqDigest, result.BootID, startedAt, finishedAt.UTC(),
		rIssued.UTC(), rExpires.UTC(), result.State, reasonSQL, string(evidenceJSON), string(envelopeJSON), now); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE diagnostic_assignments
		SET status=$3, terminal_reason=$4, terminal_at=$5
		WHERE deployment_id=$1 AND assignment_id=$2`,
		s.deploymentID, result.AssignmentID, result.State, termReason, now); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignment_events (
			deployment_id, assignment_id, from_status, to_status, reason, at
		) VALUES ($1,$2,$3,$4,$5,$6)`,
		s.deploymentID, result.AssignmentID, string(rec.Status), result.State, termReason, now); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_enrollments SET last_sequence=$3
		WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, result.DeviceID, result.Sequence); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}

	committed, _, err := s.readDiagnosticAssignmentTx(ctx, tx, result.AssignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	if err := repositoryCommit(tx); err != nil {
		return workflows.AssignmentRecord{}, false, err
	}
	return committed, true, nil
}

// DiagnosticAssignment reads one assignment (closing an overdue dispatch/reporting window
// first if non-terminal so callers always observe consistent lease expiry).
func (s *PostgresRepository) DiagnosticAssignment(ctx context.Context, assignmentID string) (workflows.AssignmentRecord, error) {
	if !repositoryIDPattern.MatchString(assignmentID) {
		return workflows.AssignmentRecord{}, workflows.ErrAssignmentNotFound
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	rec, found, err := s.readDiagnosticAssignmentOnce(ctx, assignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, err
	}
	if !found {
		return workflows.AssignmentRecord{}, workflows.ErrAssignmentNotFound
	}
	if !assignmentNeedsExpiry(rec, now) {
		return rec, nil
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return workflows.AssignmentRecord{}, err
	}
	defer tx.Rollback()
	locked, found, err := s.lockDiagnosticAssignmentTx(ctx, tx, assignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, err
	}
	if !found {
		return workflows.AssignmentRecord{}, workflows.ErrAssignmentNotFound
	}
	now = s.now().UTC().Truncate(time.Microsecond)
	if changed, err := s.expireAssignmentTx(ctx, tx, locked, now); err != nil {
		return workflows.AssignmentRecord{}, err
	} else if changed {
		if err := repositoryCommit(tx); err != nil {
			return workflows.AssignmentRecord{}, err
		}
	}
	refreshed, _, err := s.readDiagnosticAssignmentOnce(ctx, assignmentID)
	return refreshed, err
}

// ListDeviceDiagnosticAssignments returns a bounded cursor-paginated history of
// diagnostic assignments for one enrolled device.
func (s *PostgresRepository) ListDeviceDiagnosticAssignments(ctx context.Context, deviceID string, limit int, after string) (workflows.AssignmentListPage, error) {
	if !repositoryIDPattern.MatchString(deviceID) {
		return workflows.AssignmentListPage{}, ErrDeviceStateInvalid
	}
	if limit < 1 || limit > diagnosticPageMax {
		return workflows.AssignmentListPage{}, ErrDeviceStateInvalid
	}
	var cursorIssued time.Time
	var cursorSeq uint64
	hasCursor := false
	if after != "" {
		cMicros, cSeqText, ok := strings.Cut(after, ".")
		if !ok {
			return workflows.AssignmentListPage{}, ErrDeviceStateInvalid
		}
		m, err1 := strconv.ParseInt(cMicros, 10, 64)
		seq, err2 := strconv.ParseUint(cSeqText, 10, 64)
		c := strconv.FormatInt(m, 10) + "." + strconv.FormatUint(seq, 10)
		if err1 != nil || err2 != nil || seq < 1 || c != after {
			return workflows.AssignmentListPage{}, ErrDeviceStateInvalid
		}
		cursorIssued = time.UnixMicro(m).UTC()
		cursorSeq = seq
		hasCursor = true
	}

	// Expire overdue non-terminal assignments on this device before returning the page.
	if err := s.expireDeviceAssignmentsIfAny(ctx, deviceID); err != nil {
		return workflows.AssignmentListPage{}, err
	}

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return workflows.AssignmentListPage{}, repositoryUnavailable(err)
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, deviceID).Scan(&exists); err != nil {
		return workflows.AssignmentListPage{}, repositoryReadError(err)
	}

	var rows *sql.Rows
	if hasCursor {
		rows, err = tx.QueryContext(ctx, `SELECT assignment_id FROM diagnostic_assignments
			WHERE deployment_id=$1 AND device_id=$2 AND (issued_at, assignment_sequence) > ($3, $4)
			ORDER BY issued_at ASC, assignment_sequence ASC LIMIT $5`,
			s.deploymentID, deviceID, cursorIssued, cursorSeq, limit+1)
	} else {
		rows, err = tx.QueryContext(ctx, `SELECT assignment_id FROM diagnostic_assignments
			WHERE deployment_id=$1 AND device_id=$2
			ORDER BY issued_at ASC, assignment_sequence ASC LIMIT $3`,
			s.deploymentID, deviceID, limit+1)
	}
	if err != nil {
		return workflows.AssignmentListPage{}, repositoryUnavailable(err)
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return workflows.AssignmentListPage{}, repositoryUnavailable(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return workflows.AssignmentListPage{}, repositoryUnavailable(err)
	}
	rows.Close()

	var nextAfter *string
	if len(ids) > limit {
		ids = ids[:limit]
	}
	list := make([]workflows.AssignmentRecord, 0, len(ids))
	for _, id := range ids {
		rec, _, err := s.readDiagnosticAssignmentTx(ctx, tx, id)
		if err != nil {
			return workflows.AssignmentListPage{}, err
		}
		list = append(list, rec)
	}
	if len(list) == limit {
		// Re-check whether another row exists after the last returned item.
		last := list[len(list)-1]
		var more bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (
				SELECT 1 FROM diagnostic_assignments
				WHERE deployment_id=$1 AND device_id=$2 AND (issued_at, assignment_sequence) > ($3, $4)
			)`, s.deploymentID, deviceID, last.IssuedAt, last.AssignmentSequence).Scan(&more); err != nil {
			return workflows.AssignmentListPage{}, repositoryUnavailable(err)
		}
		if more {
			next := strconv.FormatInt(last.IssuedAt.UnixMicro(), 10) + "." + strconv.FormatUint(last.AssignmentSequence, 10)
			nextAfter = &next
		}
	}

	return workflows.AssignmentListPage{
		SchemaVersion: DiagnosticAssignmentListVersion,
		DeploymentID:  s.deploymentID,
		DeviceID:      deviceID,
		Assignments:   list,
		NextAfter:     nextAfter,
	}, nil
}

func (s *PostgresRepository) expireDeviceAssignmentsIfAny(ctx context.Context, deviceID string) error {
	now := s.now().UTC().Truncate(time.Microsecond)
	var needs bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS (
			SELECT 1 FROM diagnostic_assignments
			WHERE deployment_id=$1 AND device_id=$2 AND status IN ('pending','leased','cancel_requested')
				AND ((status='pending' AND (expires_at <= $3 OR ($3 + make_interval(secs => wall_seconds)) > expires_at))
					OR (status IN ('leased','cancel_requested') AND expires_at <= $4))
		)`, s.deploymentID, deviceID, now, now.Add(-workflows.DiagnosticReportingWindow)).Scan(&needs)
	if err != nil {
		return repositoryUnavailable(err)
	}
	if !needs {
		return nil
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.expireDeviceAssignmentsTx(ctx, tx, deviceID, now); err != nil {
		return err
	}
	return repositoryCommit(tx)
}

func (s *PostgresRepository) expireDeviceAssignmentsTx(ctx context.Context, tx *sql.Tx, deviceID string, now time.Time) error {
	rows, err := tx.QueryContext(ctx, `SELECT assignment_id FROM diagnostic_assignments
		WHERE deployment_id=$1 AND device_id=$2 AND status IN ('pending','leased','cancel_requested')
			AND ((status='pending' AND (expires_at <= $3 OR ($3 + make_interval(secs => wall_seconds)) > expires_at))
				OR (status IN ('leased','cancel_requested') AND expires_at <= $4))
		ORDER BY issued_at ASC, assignment_sequence ASC FOR UPDATE`,
		s.deploymentID, deviceID, now, now.Add(-workflows.DiagnosticReportingWindow))
	if err != nil {
		return repositoryUnavailable(err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return repositoryUnavailable(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return repositoryUnavailable(err)
	}
	rows.Close()

	for _, id := range ids {
		rec, found, err := s.readDiagnosticAssignmentTx(ctx, tx, id)
		if err != nil || !found {
			return err
		}
		if _, err := s.expireAssignmentTx(ctx, tx, rec, now); err != nil {
			return err
		}
	}
	return nil
}

func assignmentNeedsExpiry(rec workflows.AssignmentRecord, now time.Time) bool {
	if rec.Status.IsTerminal() {
		return false
	}
	if rec.Status == workflows.StatusPending {
		return !now.Before(rec.ExpiresAt) || now.Add(time.Duration(rec.SignedAssignment.Budget.WallSeconds)*time.Second).After(rec.ExpiresAt)
	}
	return !now.Before(rec.ExpiresAt.Add(workflows.DiagnosticReportingWindow))
}

func (s *PostgresRepository) expireAssignmentTx(ctx context.Context, tx *sql.Tx, rec workflows.AssignmentRecord, now time.Time) (bool, error) {
	if !assignmentNeedsExpiry(rec, now) {
		return false, nil
	}
	toStatus := "expired"
	reason := "deadline_exceeded"
	if rec.Status == workflows.StatusCancelRequested {
		toStatus = "cancelled"
		reason = "cancel_requested"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE diagnostic_assignments
		SET status=$3, terminal_reason=$4, terminal_at=$5
		WHERE deployment_id=$1 AND assignment_id=$2`,
		s.deploymentID, rec.AssignmentID, toStatus, reason, now); err != nil {
		return false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO diagnostic_assignment_events (
			deployment_id, assignment_id, from_status, to_status, reason, at
		) VALUES ($1,$2,$3,$4,$5,$6)`,
		s.deploymentID, rec.AssignmentID, string(rec.Status), toStatus, reason, now); err != nil {
		return false, repositoryUnavailable(err)
	}
	return true, nil
}

func (s *PostgresRepository) lockDiagnosticAssignmentTx(ctx context.Context, tx *sql.Tx, assignmentID string) (workflows.AssignmentRecord, bool, error) {
	var lockedID string
	err := tx.QueryRowContext(ctx, `SELECT assignment_id FROM diagnostic_assignments
		WHERE deployment_id=$1 AND assignment_id=$2 FOR UPDATE`,
		s.deploymentID, assignmentID).Scan(&lockedID)
	if errors.Is(err, sql.ErrNoRows) {
		return workflows.AssignmentRecord{}, false, nil
	}
	if err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	return s.readDiagnosticAssignmentTx(ctx, tx, lockedID)
}

func (s *PostgresRepository) readDiagnosticAssignmentOnce(ctx context.Context, assignmentID string) (workflows.AssignmentRecord, bool, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	defer tx.Rollback()
	return s.readDiagnosticAssignmentTx(ctx, tx, assignmentID)
}

func (s *PostgresRepository) readDiagnosticAssignmentTx(ctx context.Context, q dbQueryer, assignmentID string) (workflows.AssignmentRecord, bool, error) {
	var rec workflows.AssignmentRecord
	var status string
	var assignDigest, signedJSON []byte
	var firstDisp, lastDisp, leaseExp, cancelAt, termAt sql.NullTime
	var cancelIssuer, cancelSubject, termReason sql.NullString
	var deliveryCount int

	err := q.QueryRowContext(ctx, `SELECT assignment_id, device_id, assignment_sequence, assignment_sha256,
			probe_id, issued_at, expires_at, signed_assignment, status, delivery_count,
			first_dispatched_at, last_dispatched_at, lease_expires_at,
			cancel_requested_at, cancel_actor_issuer, cancel_actor_subject,
			terminal_reason, terminal_at, created_at, actor_issuer, actor_subject
		FROM diagnostic_assignments
		WHERE deployment_id=$1 AND assignment_id=$2`,
		s.deploymentID, assignmentID).Scan(
		&rec.AssignmentID, &rec.DeviceID, &rec.AssignmentSequence, &assignDigest,
		&rec.ProbeID, &rec.IssuedAt, &rec.ExpiresAt, &signedJSON, &status, &deliveryCount,
		&firstDisp, &lastDisp, &leaseExp,
		&cancelAt, &cancelIssuer, &cancelSubject,
		&termReason, &termAt, &rec.CreatedAt, &rec.RequestedBy.Issuer, &rec.RequestedBy.Subject,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return workflows.AssignmentRecord{}, false, nil
	}
	if err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}

	rec.SchemaVersion = DiagnosticAssignmentRecordVersion
	rec.DeploymentID = s.deploymentID
	rec.AssignmentSHA256 = hex.EncodeToString(assignDigest)
	rec.Status = workflows.AssignmentStatus(status)
	rec.IssuedAt = rec.IssuedAt.UTC()
	rec.ExpiresAt = rec.ExpiresAt.UTC()
	rec.CreatedAt = rec.CreatedAt.UTC()
	rec.DeliveryCount = uint32(deliveryCount)
	if firstDisp.Valid {
		t := firstDisp.Time.UTC()
		rec.FirstDispatchedAt = &t
	}
	if lastDisp.Valid {
		t := lastDisp.Time.UTC()
		rec.LastDispatchedAt = &t
	}
	if leaseExp.Valid {
		t := leaseExp.Time.UTC()
		rec.LeaseExpiresAt = &t
	}
	if cancelAt.Valid {
		t := cancelAt.Time.UTC()
		rec.CancelRequested = true
		rec.CancelRequestedAt = &t
		rec.CancelledBy = &workflows.Actor{Issuer: cancelIssuer.String, Subject: cancelSubject.String}
	}
	if termReason.Valid {
		r := termReason.String
		rec.TerminalReason = &r
	}
	if termAt.Valid {
		t := termAt.Time.UTC()
		rec.TerminalAt = &t
	}
	if err := json.Unmarshal(signedJSON, &rec.SignedAssignment); err != nil || rec.SignedAssignment.Validate() != nil {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: stored assignment invalid", workflows.ErrAssignmentCorrupt)
	}
	sb, err := rec.SignedAssignment.SigningBytes()
	if err != nil {
		return workflows.AssignmentRecord{}, false, workflows.ErrAssignmentCorrupt
	}
	sha, err := contracts.EnvelopeRequestSHA256V1(sb, rec.SignedAssignment.Signature)
	if err != nil || sha != rec.AssignmentSHA256 {
		return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: assignment digest mismatch", workflows.ErrAssignmentCorrupt)
	}

	var resReqDigest, resEnvJSON []byte
	var resAcceptedAt time.Time
	err = q.QueryRowContext(ctx, `SELECT request_sha256, envelope, accepted_at
		FROM diagnostic_results WHERE deployment_id=$1 AND assignment_id=$2`,
		s.deploymentID, assignmentID).Scan(&resReqDigest, &resEnvJSON, &resAcceptedAt)
	if err == nil {
		var res contracts.DiagnosticResultV1
		if json.Unmarshal(resEnvJSON, &res) != nil || res.CheckAssignment(rec.SignedAssignment) != nil {
			return workflows.AssignmentRecord{}, false, fmt.Errorf("%w: stored result invalid", workflows.ErrAssignmentCorrupt)
		}
		reqHex := hex.EncodeToString(resReqDigest)
		acc := resAcceptedAt.UTC()
		rec.Result = &res
		rec.ResultRequestSHA256 = &reqHex
		rec.ResultAcceptedAt = &acc
	} else if !errors.Is(err, sql.ErrNoRows) {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}

	evRows, err := q.QueryContext(ctx, `SELECT from_status, to_status, reason, at, actor_issuer, actor_subject
		FROM diagnostic_assignment_events
		WHERE deployment_id=$1 AND assignment_id=$2 ORDER BY id ASC`,
		s.deploymentID, assignmentID)
	if err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	defer evRows.Close()
	rec.Events = []workflows.AssignmentEvent{}
	for evRows.Next() {
		var ev workflows.AssignmentEvent
		var from, issuer, subject sql.NullString
		if err := evRows.Scan(&from, &ev.ToStatus, &ev.Reason, &ev.At, &issuer, &subject); err != nil {
			return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
		}
		ev.FromStatus = from.String
		ev.At = ev.At.UTC()
		if issuer.Valid {
			ev.By = &workflows.Actor{Issuer: issuer.String, Subject: subject.String}
		}
		rec.Events = append(rec.Events, ev)
	}
	if err := evRows.Err(); err != nil {
		return workflows.AssignmentRecord{}, false, repositoryUnavailable(err)
	}
	return rec, true, nil
}

func sameDiagnosticRequest(rec workflows.AssignmentRecord, req workflows.AssignmentRequest) bool {
	return rec.DeviceID == req.DeviceID &&
		rec.ProbeID == req.ProbeID &&
		reflect.DeepEqual(rec.SignedAssignment.Arguments, req.Arguments) &&
		rec.SignedAssignment.Budget == req.Budget &&
		rec.ExpiresAt.Equal(rec.IssuedAt.Add(time.Duration(req.ExpiresInSeconds)*time.Second))
}

func sameDiagnosticResult(a, b contracts.DiagnosticResultV1) bool {
	return reflect.DeepEqual(a, b)
}
