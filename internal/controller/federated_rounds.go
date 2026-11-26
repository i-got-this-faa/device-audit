package controller

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/jackc/pgx/v5/pgconn"
)

var _ federated.Coordinator = (*PostgresRepository)(nil)

// OpenRound records one round against a registered base artifact and the
// current enrollment of every participant. An identical request, even after the
// round closed, returns the stored lifecycle. A different round that reuses the
// round or candidate ID is ErrRoundConflict. Nothing is stored for a refusal.
func (s *PostgresRepository) OpenRound(ctx context.Context, round contracts.FederatedRoundV1, by federated.Actor) (federated.RoundRecord, bool, error) {
	if err := round.Validate(); err != nil {
		return federated.RoundRecord{}, false, err
	}
	if err := by.Validate(); err != nil {
		return federated.RoundRecord{}, false, err
	}
	if round.DeploymentID != s.deploymentID {
		return federated.RoundRecord{}, false, errors.New("round belongs to another deployment")
	}
	if record, found, err := s.repeatedRound(ctx, round); found || err != nil {
		return record, false, err
	}
	opened, deadline := mustParseRoundTime(round.OpenedAt), mustParseRoundTime(round.Deadline)
	now := s.now().UTC().Truncate(time.Microsecond)
	if opened.After(now) || !now.Before(deadline) {
		return federated.RoundRecord{}, false, fmt.Errorf("%w: round window does not include the controller clock", federated.ErrRoundNotOpen)
	}
	if err := s.checkRoundBase(ctx, round); err != nil {
		return federated.RoundRecord{}, false, err
	}
	encoded, err := json.Marshal(round)
	if err != nil {
		return federated.RoundRecord{}, false, err
	}
	baseDigest, _ := hex.DecodeString(round.BaseModelSHA256)
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return federated.RoundRecord{}, false, err
	}
	defer tx.Rollback()
	if err := s.checkRoundParticipants(ctx, tx, round); err != nil {
		if errors.Is(err, federated.ErrParticipantNotEligible) {
			// An identical request may have committed since the first lookup.
			tx.Rollback()
			if record, found, lookupErr := s.repeatedRound(ctx, round); found || lookupErr != nil {
				return record, false, lookupErr
			}
		}
		return federated.RoundRecord{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO federated_rounds (deployment_id, round_id, candidate_id, base_model_version,
		base_model_sha256, opened_at, deadline, record, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'open')`,
		s.deploymentID, round.RoundID, round.CandidateID, round.BaseModelVersion, baseDigest, opened, deadline, encoded); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == postgresUniqueViolationSQLState {
			// A concurrent request won, or the candidate belongs to another round.
			tx.Rollback()
			record, found, err := s.repeatedRound(ctx, round)
			if err == nil && !found {
				err = federated.ErrRoundConflict
			}
			return record, false, err
		}
		return federated.RoundRecord{}, false, repositoryUnavailable(err)
	}
	for _, p := range round.Participants {
		if _, err := tx.ExecContext(ctx, `INSERT INTO federated_round_participants (deployment_id, round_id, device_id, signing_key_id, eligibility, reason)
			VALUES ($1,$2,$3,$4,$5,$6)`, s.deploymentID, round.RoundID, p.DeviceID, p.SigningKeyID, p.Eligibility, p.Reason); err != nil {
			return federated.RoundRecord{}, false, repositoryUnavailable(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO federated_round_events (deployment_id, round_id, to_status, reason, at, actor_issuer, actor_subject)
		VALUES ($1,$2,'open','opened',$3,$4,$5)`, s.deploymentID, round.RoundID, now, by.Issuer, by.Subject); err != nil {
		return federated.RoundRecord{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.RoundRecord{}, false, err
	}
	record, err := s.loadRound(ctx, round.RoundID)
	return record, err == nil, err
}

// repeatedRound returns the stored round when round.RoundID exists: the same
// content is a repeat, anything else is ErrRoundConflict. It does not change state.
func (s *PostgresRepository) repeatedRound(ctx context.Context, round contracts.FederatedRoundV1) (federated.RoundRecord, bool, error) {
	record, err := s.loadRound(ctx, round.RoundID)
	if errors.Is(err, federated.ErrRoundNotFound) {
		return federated.RoundRecord{}, false, nil
	}
	if err != nil {
		return federated.RoundRecord{}, false, err
	}
	if !sameRound(record.Round, round) {
		return federated.RoundRecord{}, true, federated.ErrRoundConflict
	}
	return record, true, nil
}

// sameRound compares rounds as the participant set, not the list order.
func sameRound(a, b contracts.FederatedRoundV1) bool {
	byDevice := func(x, y contracts.FederatedParticipantV1) int {
		switch {
		case x.DeviceID < y.DeviceID:
			return -1
		case x.DeviceID > y.DeviceID:
			return 1
		}
		return 0
	}
	a.Participants, b.Participants = slices.SortedFunc(slices.Values(a.Participants), byDevice), slices.SortedFunc(slices.Values(b.Participants), byDevice)
	return reflect.DeepEqual(a, b)
}

// checkRoundBase requires the base to be the stored artifact the round names,
// declared for training, with the round's feature version and parameter count.
func (s *PostgresRepository) checkRoundBase(ctx context.Context, round contracts.FederatedRoundV1) error {
	stored, err := s.ModelArtifact(ctx, round.BaseModelVersion)
	if errors.Is(err, ErrRepositoryNotFound) {
		return fmt.Errorf("%w: version %s is not stored", federated.ErrBaseNotRegistered, round.BaseModelVersion)
	}
	if err != nil {
		return err
	}
	m := stored.Manifest
	if m.ArtifactSHA256 != round.BaseModelSHA256 || m.FeatureVersion != round.FeatureVersion || m.ParameterCount != round.ParameterCount ||
		!slices.Contains(m.Purposes, contracts.ModelPurposeTraining) {
		return fmt.Errorf("%w: digest, feature version, parameter count or training purpose differs", federated.ErrBaseNotRegistered)
	}
	return nil
}

// checkRoundParticipants share-locks each participant's enrollment, the lock
// RevokeDevice waits on, so a revocation is ordered before or after the open.
// A participant must be enrolled with the snapshot key; it cannot be marked
// eligible while revoked.
func (s *PostgresRepository) checkRoundParticipants(ctx context.Context, tx *sql.Tx, round contracts.FederatedRoundV1) error {
	for _, p := range round.Participants {
		var revokedAt *time.Time
		err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM device_enrollments
			WHERE deployment_id=$1 AND device_id=$2 AND signing_key_id=$3 FOR SHARE`, s.deploymentID, p.DeviceID, p.SigningKeyID).Scan(&revokedAt)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s is not enrolled with the snapshot key", federated.ErrParticipantNotEligible, p.DeviceID)
		}
		if err != nil {
			return repositoryUnavailable(err)
		}
		if revokedAt != nil && p.Eligibility == "eligible" {
			return fmt.Errorf("%w: %s is revoked", federated.ErrParticipantNotEligible, p.DeviceID)
		}
	}
	return nil
}

// Round returns one round. When its deadline has passed it first records the
// closing, so a restart or a late reader sees the same lifecycle.
func (s *PostgresRepository) Round(ctx context.Context, roundID string) (federated.RoundRecord, error) {
	record, err := s.loadRound(ctx, roundID)
	if err != nil || !s.roundExpired(record) {
		return record, err
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return federated.RoundRecord{}, err
	}
	defer tx.Rollback()
	if _, err := s.closeExpired(ctx, tx, roundID); err != nil {
		return federated.RoundRecord{}, err
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.RoundRecord{}, err
	}
	return s.loadRound(ctx, roundID)
}

func (s *PostgresRepository) roundExpired(record federated.RoundRecord) bool {
	return record.Status == federated.RoundOpen && !s.now().UTC().Before(mustParseRoundTime(record.Round.Deadline))
}

// CloseExpiredRounds closes every open round at or past its deadline, each with
// one recorded transition, and returns how many it closed.
func (s *PostgresRepository) CloseExpiredRounds(ctx context.Context) (int, error) {
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	closed, err := s.closeExpired(ctx, tx, "")
	if err != nil {
		return 0, err
	}
	return closed, repositoryCommit(tx)
}

// closeExpired closes the open rounds past their deadline: all of them, or
// only roundID. The UPDATE row-locks each round, so concurrent callers close
// and record a round once.
func (s *PostgresRepository) closeExpired(ctx context.Context, tx *sql.Tx, roundID string) (int, error) {
	result, err := tx.ExecContext(ctx, `WITH closed AS (
			UPDATE federated_rounds SET status='closed'
			WHERE deployment_id=$1 AND status='open' AND deadline <= $2 AND ($3 = '' OR round_id = $3)
			RETURNING deployment_id, round_id)
		INSERT INTO federated_round_events (deployment_id, round_id, from_status, to_status, reason, at)
		SELECT deployment_id, round_id, 'open', 'closed', 'deadline', $2 FROM closed`,
		s.deploymentID, s.now().UTC().Truncate(time.Microsecond), roundID)
	if err != nil {
		return 0, repositoryUnavailable(err)
	}
	closed, err := result.RowsAffected()
	if err != nil {
		return 0, repositoryUnavailable(err)
	}
	return int(closed), nil
}

// AcceptParticipant admits one participant to the round's training work. The
// device must be listed eligible with this key, still enrolled and unrevoked,
// and the round open before its deadline. It share-locks the enrollment, so a
// concurrent revocation is ordered before or after the admission. A repeat
// returns the stored admission, even after the round closed.
func (s *PostgresRepository) AcceptParticipant(ctx context.Context, roundID, deviceID, signingKeyID string) (federated.RoundRecord, bool, error) {
	if !repositoryIDPattern.MatchString(roundID) || !repositoryIDPattern.MatchString(deviceID) {
		return federated.RoundRecord{}, false, federated.ErrParticipantNotEligible
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return federated.RoundRecord{}, false, err
	}
	defer tx.Rollback()
	status, deadline, err := s.lockRound(ctx, tx, roundID)
	if err != nil {
		return federated.RoundRecord{}, false, err
	}
	var storedKey, eligibility string
	var acceptedAt *time.Time
	err = tx.QueryRowContext(ctx, `SELECT signing_key_id, eligibility, accepted_at FROM federated_round_participants
		WHERE deployment_id=$1 AND round_id=$2 AND device_id=$3 FOR UPDATE`, s.deploymentID, roundID, deviceID).Scan(&storedKey, &eligibility, &acceptedAt)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (storedKey != signingKeyID || eligibility != "eligible") {
		return federated.RoundRecord{}, false, fmt.Errorf("%w: %s is not an eligible participant with this key", federated.ErrParticipantNotEligible, deviceID)
	}
	if err != nil {
		return federated.RoundRecord{}, false, repositoryUnavailable(err)
	}
	if acceptedAt != nil {
		if status == federated.RoundOpen && !s.now().UTC().Before(deadline) {
			if _, err := s.closeExpired(ctx, tx, roundID); err != nil {
				return federated.RoundRecord{}, false, err
			}
			if err := repositoryCommit(tx); err != nil {
				return federated.RoundRecord{}, false, err
			}
		} else {
			tx.Rollback()
		}
		record, err := s.loadRound(ctx, roundID)
		return record, false, err
	}
	if status == federated.RoundOpen && !s.now().UTC().Before(deadline) {
		return s.refuseExpired(ctx, tx, roundID)
	}
	if status != federated.RoundOpen {
		return federated.RoundRecord{}, false, fmt.Errorf("%w: round is %s", federated.ErrRoundNotOpen, status)
	}
	var revokedAt *time.Time
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM device_enrollments
		WHERE deployment_id=$1 AND device_id=$2 AND signing_key_id=$3 FOR SHARE`, s.deploymentID, deviceID, signingKeyID).Scan(&revokedAt); err != nil {
		return federated.RoundRecord{}, false, repositoryReadError(err)
	}
	if revokedAt != nil {
		return federated.RoundRecord{}, false, fmt.Errorf("%w: %s is revoked", federated.ErrParticipantNotEligible, deviceID)
	}
	// The enrollment lock can wait on a revocation, so read the clock again.
	admittedAt := s.now().UTC().Truncate(time.Microsecond)
	if !admittedAt.Before(deadline) {
		return s.refuseExpired(ctx, tx, roundID)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE federated_round_participants SET accepted_at=$4
		WHERE deployment_id=$1 AND round_id=$2 AND device_id=$3`, s.deploymentID, roundID, deviceID, admittedAt); err != nil {
		return federated.RoundRecord{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.RoundRecord{}, false, err
	}
	record, err := s.loadRound(ctx, roundID)
	return record, err == nil, err
}

// refuseExpired records the closing of a round whose deadline passed, commits
// it so the refusal does not lose it, and answers ErrRoundNotOpen.
func (s *PostgresRepository) refuseExpired(ctx context.Context, tx *sql.Tx, roundID string) (federated.RoundRecord, bool, error) {
	if _, err := s.closeExpired(ctx, tx, roundID); err != nil {
		return federated.RoundRecord{}, false, err
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.RoundRecord{}, false, err
	}
	return federated.RoundRecord{}, false, fmt.Errorf("%w: the deadline passed", federated.ErrRoundNotOpen)
}

// CancelRound moves an open round to cancelled and records the actor. A repeat
// returns the cancelled round. A closed round, or one whose deadline has
// passed, stays closed and returns ErrRoundNotOpen.
func (s *PostgresRepository) CancelRound(ctx context.Context, roundID string, by federated.Actor) (federated.RoundRecord, error) {
	if err := by.Validate(); err != nil {
		return federated.RoundRecord{}, err
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return federated.RoundRecord{}, err
	}
	defer tx.Rollback()
	status, deadline, err := s.lockRound(ctx, tx, roundID)
	if err != nil {
		return federated.RoundRecord{}, err
	}
	switch {
	case status == federated.RoundCancelled:
		tx.Rollback()
		return s.loadRound(ctx, roundID)
	case status == federated.RoundOpen && !s.now().UTC().Before(deadline):
		_, _, err := s.refuseExpired(ctx, tx, roundID)
		return federated.RoundRecord{}, err
	case status != federated.RoundOpen:
		return federated.RoundRecord{}, fmt.Errorf("%w: round is %s", federated.ErrRoundNotOpen, status)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE federated_rounds SET status='cancelled' WHERE deployment_id=$1 AND round_id=$2`, s.deploymentID, roundID); err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO federated_round_events (deployment_id, round_id, from_status, to_status, reason, at, actor_issuer, actor_subject)
		VALUES ($1,$2,'open','cancelled','cancelled',$3,$4,$5)`, s.deploymentID, roundID, s.now().UTC().Truncate(time.Microsecond), by.Issuer, by.Subject); err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.RoundRecord{}, err
	}
	return s.loadRound(ctx, roundID)
}

// lockRound row-locks a round for the rest of the transaction.
func (s *PostgresRepository) lockRound(ctx context.Context, tx *sql.Tx, roundID string) (federated.RoundStatus, time.Time, error) {
	var status string
	var deadline time.Time
	err := tx.QueryRowContext(ctx, `SELECT status, deadline FROM federated_rounds WHERE deployment_id=$1 AND round_id=$2 FOR UPDATE`,
		s.deploymentID, roundID).Scan(&status, &deadline)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, federated.ErrRoundNotFound
	}
	if err != nil {
		return "", time.Time{}, repositoryUnavailable(err)
	}
	return federated.RoundStatus(status), deadline.UTC(), nil
}

// loadRound reads the stored round without changing it.
func (s *PostgresRepository) loadRound(ctx context.Context, roundID string) (federated.RoundRecord, error) {
	if !repositoryIDPattern.MatchString(roundID) {
		return federated.RoundRecord{}, federated.ErrRoundNotFound
	}
	// One read-only snapshot, so status, admissions and transitions agree.
	snapshot, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	defer snapshot.Rollback()
	var record federated.RoundRecord
	var encoded []byte
	var status string
	err = snapshot.QueryRowContext(ctx, `SELECT record, status FROM federated_rounds WHERE deployment_id=$1 AND round_id=$2`,
		s.deploymentID, roundID).Scan(&encoded, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return federated.RoundRecord{}, federated.ErrRoundNotFound
	}
	if err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	if err := json.Unmarshal(encoded, &record.Round); err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(fmt.Errorf("stored round %s: %w", roundID, err))
	}
	record.Status = federated.RoundStatus(status)

	accepted, err := snapshot.QueryContext(ctx, `SELECT device_id, signing_key_id, accepted_at FROM federated_round_participants
		WHERE deployment_id=$1 AND round_id=$2 AND accepted_at IS NOT NULL ORDER BY accepted_at, device_id`, s.deploymentID, roundID)
	if err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	defer accepted.Close()
	for accepted.Next() {
		var a federated.Acceptance
		if err := accepted.Scan(&a.DeviceID, &a.SigningKeyID, &a.AcceptedAt); err != nil {
			return federated.RoundRecord{}, repositoryUnavailable(err)
		}
		a.AcceptedAt = a.AcceptedAt.UTC()
		record.Accepted = append(record.Accepted, a)
	}
	if err := accepted.Err(); err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}

	events, err := snapshot.QueryContext(ctx, `SELECT from_status, to_status, reason, at, actor_issuer, actor_subject FROM federated_round_events
		WHERE deployment_id=$1 AND round_id=$2 ORDER BY id`, s.deploymentID, roundID)
	if err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	defer events.Close()
	for events.Next() {
		var t federated.Transition
		var from, issuer, subject sql.NullString
		if err := events.Scan(&from, &t.To, &t.Reason, &t.At, &issuer, &subject); err != nil {
			return federated.RoundRecord{}, repositoryUnavailable(err)
		}
		t.From, t.At = federated.RoundStatus(from.String), t.At.UTC()
		if issuer.Valid {
			t.By = &federated.Actor{Issuer: issuer.String, Subject: subject.String}
		}
		record.Transitions = append(record.Transitions, t)
	}
	if err := events.Err(); err != nil {
		return federated.RoundRecord{}, repositoryUnavailable(err)
	}
	return record, nil
}

// mustParseRoundTime parses a time that FederatedRoundV1.Validate or the
// database already accepted.
func mustParseRoundTime(value string) time.Time {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil {
		panic("unvalidated round time " + value)
	}
	return parsed
}
