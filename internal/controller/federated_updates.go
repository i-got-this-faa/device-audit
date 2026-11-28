package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
)

// AcceptUpdate validates, authenticates against device_enrollments, checks
// round and participant eligibility, prevents sequence replay, and durably
// stores one signed update in federated_updates before aggregation (FED09 #114).
func (s *PostgresRepository) AcceptUpdate(ctx context.Context, update contracts.FederatedUpdateV1) (federated.AcceptedUpdate, bool, error) {
	if err := update.Validate(); err != nil {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %v", federated.ErrUpdateInvalid, err)
	}
	if update.DeploymentID != s.deploymentID {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: update deployment %s mismatches %s", federated.ErrUpdateUnauthorized, update.DeploymentID, s.deploymentID)
	}
	weights, err := contracts.DecodeFederatedWeightsV1(update.WeightsBase64)
	if err != nil {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %v", federated.ErrUpdateInvalid, err)
	}
	signingBytes, err := update.SigningBytes()
	if err != nil {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %v", federated.ErrUpdateInvalid, err)
	}
	reqDigestHex, err := contracts.EnvelopeRequestSHA256V1(signingBytes, update.Signature)
	if err != nil {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %v", federated.ErrUpdateInvalid, err)
	}
	reqDigest := decodeRepositoryDigest(reqDigestHex)
	updateDigest := decodeRepositoryDigest(update.UpdateSHA256)
	baseDigest := decodeRepositoryDigest(update.BaseModelSHA256)
	weightsBytes := encodeBinary64Weights(weights)
	encodedEnvelope, err := json.Marshal(update)
	if err != nil {
		return federated.AcceptedUpdate{}, false, err
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return federated.AcceptedUpdate{}, false, err
	}
	defer tx.Rollback()

	// Lock order must stay federated_rounds -> federated_round_participants -> device_enrollments
	// to match AcceptParticipant and avoid deadlocks with RevokeDevice/AcceptEvidence.
	roundStatus, deadline, round, err := s.lockRoundWithRecord(ctx, tx, update.RoundID)
	if err != nil {
		return federated.AcceptedUpdate{}, false, err
	}

	var partKey, eligibility string
	var partAcceptedAt sql.NullTime
	partFound := true
	err = tx.QueryRowContext(ctx, `SELECT signing_key_id, eligibility, accepted_at FROM federated_round_participants
		WHERE deployment_id=$1 AND round_id=$2 AND device_id=$3 FOR UPDATE`,
		s.deploymentID, update.RoundID, update.DeviceID).Scan(&partKey, &eligibility, &partAcceptedAt)
	if errors.Is(err, sql.ErrNoRows) {
		partFound = false
	} else if err != nil {
		return federated.AcceptedUpdate{}, false, repositoryUnavailable(err)
	}

	var enrolledKey string
	var publicKeyBytes []byte
	var lastSequence uint64
	var revokedAt sql.NullTime
	err = tx.QueryRowContext(ctx, `SELECT signing_key_id, public_key, last_sequence, revoked_at FROM device_enrollments
		WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`, s.deploymentID, update.DeviceID).
		Scan(&enrolledKey, &publicKeyBytes, &lastSequence, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: unknown device %s", federated.ErrUpdateUnauthorized, update.DeviceID)
	}
	if err != nil {
		return federated.AcceptedUpdate{}, false, repositoryUnavailable(err)
	}
	if enrolledKey != update.SigningKeyID || len(publicKeyBytes) != ed25519.PublicKeySize {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: signing key mismatch", federated.ErrUpdateUnauthorized)
	}
	if revokedAt.Valid {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %w: device %s is revoked", federated.ErrUpdateUnauthorized, federated.ErrParticipantNotEligible, update.DeviceID)
	}
	if err := update.VerifySignature(ed25519.PublicKey(publicKeyBytes)); err != nil {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %v", federated.ErrUpdateUnauthorized, err)
	}

	// Authenticate before checking for an existing round update so unauthenticated callers
	// cannot probe stored submissions. Under the participant lock, at most one row exists.
	existing, storedReqDigest, found, err := s.readAcceptedUpdateTx(ctx, tx, update.RoundID, update.DeviceID)
	if err != nil {
		return federated.AcceptedUpdate{}, false, err
	}
	if found {
		if existing.Sequence != update.Sequence || !bytes.Equal(storedReqDigest, reqDigest) ||
			existing.UpdateSHA256 != update.UpdateSHA256 || !sameAcceptedEnvelope(existing.Envelope, update) {
			return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %s already submitted a different update for round %s", federated.ErrUpdateConflict, update.DeviceID, update.RoundID)
		}
		if roundStatus == federated.RoundOpen && !s.now().UTC().Before(deadline) {
			if _, err := s.closeExpired(ctx, tx, update.RoundID); err != nil {
				return federated.AcceptedUpdate{}, false, err
			}
			if err := repositoryCommit(tx); err != nil {
				return federated.AcceptedUpdate{}, false, err
			}
		} else {
			tx.Rollback()
		}
		return existing, false, nil
	}

	// Read controller clock after locks in case a lock wait crossed the deadline/expiry.
	now := s.now().UTC().Truncate(time.Microsecond)
	if roundStatus == federated.RoundOpen && !now.Before(deadline) {
		if _, err := s.closeExpired(ctx, tx, update.RoundID); err != nil {
			return federated.AcceptedUpdate{}, false, err
		}
		if err := repositoryCommit(tx); err != nil {
			return federated.AcceptedUpdate{}, false, err
		}
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %w: the deadline passed", federated.ErrUpdateExpired, federated.ErrRoundNotOpen)
	}
	if roundStatus != federated.RoundOpen {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %w: round is %s", federated.ErrUpdateExpired, federated.ErrRoundNotOpen, roundStatus)
	}
	if !partFound || partKey != update.SigningKeyID || eligibility != "eligible" {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %s is not an eligible participant with this key", federated.ErrParticipantNotEligible, update.DeviceID)
	}
	if update.CandidateID != round.CandidateID || update.BaseModelVersion != round.BaseModelVersion ||
		update.BaseModelSHA256 != round.BaseModelSHA256 || update.FeatureVersion != round.FeatureVersion ||
		uint32(len(weights)) != round.ParameterCount {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: incompatible round, base, candidate, feature version, or parameter count", federated.ErrUpdateIncompatible)
	}
	if update.Sequence <= lastSequence {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: sequence %d <= durable mark %d", federated.ErrUpdateReplay, update.Sequence, lastSequence)
	}
	opened := mustParseRoundTime(round.OpenedAt)
	issued := mustParseRoundTime(update.IssuedAt)
	expires := mustParseRoundTime(update.ExpiresAt)
	if now.Before(opened) || now.Before(issued) || !now.Before(expires) ||
		issued.Before(opened) || !issued.Before(deadline) || expires.After(deadline) {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: update outside round or freshness window", federated.ErrUpdateExpired)
	}
	if err := update.CheckRound(round, now); err != nil {
		return federated.AcceptedUpdate{}, false, fmt.Errorf("%w: %v", federated.ErrUpdateIncompatible, err)
	}

	if !partAcceptedAt.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE federated_round_participants SET accepted_at=$4
			WHERE deployment_id=$1 AND round_id=$2 AND device_id=$3`,
			s.deploymentID, update.RoundID, update.DeviceID, now); err != nil {
			return federated.AcceptedUpdate{}, false, repositoryUnavailable(err)
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO federated_updates (
			deployment_id, round_id, device_id, signing_key_id, sequence,
			candidate_id, base_model_version, base_model_sha256, feature_version,
			parameter_count, sample_count, weights_bytes, update_sha256, request_sha256,
			issued_at, expires_at, accepted_at, envelope
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		s.deploymentID, update.RoundID, update.DeviceID, update.SigningKeyID, update.Sequence,
		update.CandidateID, update.BaseModelVersion, baseDigest, update.FeatureVersion,
		round.ParameterCount, update.SampleCount, weightsBytes, updateDigest, reqDigest,
		issued, expires, now, string(encodedEnvelope)); err != nil {
		return federated.AcceptedUpdate{}, false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_enrollments SET last_sequence=$3
		WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, update.DeviceID, update.Sequence); err != nil {
		return federated.AcceptedUpdate{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.AcceptedUpdate{}, false, err
	}
	return federated.AcceptedUpdate{
		DeploymentID:     s.deploymentID,
		RoundID:          update.RoundID,
		DeviceID:         update.DeviceID,
		SigningKeyID:     update.SigningKeyID,
		Sequence:         update.Sequence,
		CandidateID:      update.CandidateID,
		BaseModelVersion: update.BaseModelVersion,
		BaseModelSHA256:  update.BaseModelSHA256,
		FeatureVersion:   update.FeatureVersion,
		ParameterCount:   round.ParameterCount,
		SampleCount:      update.SampleCount,
		Weights:          weights,
		UpdateSHA256:     update.UpdateSHA256,
		RequestSHA256:    reqDigestHex,
		IssuedAt:         issued,
		ExpiresAt:        expires,
		AcceptedAt:       now,
		Envelope:         update,
	}, true, nil
}

// AcceptedUpdates loads and integrity-verifies all durably accepted updates
// for roundID ordered by device_id inside one repeatable-read snapshot.
func (s *PostgresRepository) AcceptedUpdates(ctx context.Context, roundID string) ([]federated.AcceptedUpdate, error) {
	if !repositoryIDPattern.MatchString(roundID) {
		return nil, federated.ErrRoundNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, repositoryUnavailable(err)
	}
	defer tx.Rollback()

	var encodedRound []byte
	if err := tx.QueryRowContext(ctx, `SELECT record FROM federated_rounds WHERE deployment_id=$1 AND round_id=$2`,
		s.deploymentID, roundID).Scan(&encodedRound); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, federated.ErrRoundNotFound
		}
		return nil, repositoryUnavailable(err)
	}
	round, err := s.decodeStoredRound(roundID, encodedRound)
	if err != nil {
		return nil, err
	}

	return s.acceptedUpdatesTx(ctx, tx, round)
}

func (s *PostgresRepository) acceptedUpdatesTx(ctx context.Context, q dbQueryer, round contracts.FederatedRoundV1) ([]federated.AcceptedUpdate, error) {
	rows, err := q.QueryContext(ctx, `SELECT device_id, signing_key_id, sequence, candidate_id, base_model_version,
			base_model_sha256, feature_version, parameter_count, sample_count, weights_bytes,
			update_sha256, request_sha256, issued_at, expires_at, accepted_at, envelope
		FROM federated_updates
		WHERE deployment_id=$1 AND round_id=$2
		ORDER BY device_id ASC`, s.deploymentID, round.RoundID)
	if err != nil {
		return nil, repositoryUnavailable(err)
	}
	defer rows.Close()

	updates := []federated.AcceptedUpdate{}
	for rows.Next() {
		u, _, err := scanAcceptedUpdate(rows, s.deploymentID, round.RoundID)
		if err != nil {
			return nil, err
		}
		if u.CandidateID != round.CandidateID || u.BaseModelVersion != round.BaseModelVersion ||
			u.BaseModelSHA256 != round.BaseModelSHA256 || u.FeatureVersion != round.FeatureVersion ||
			u.ParameterCount != round.ParameterCount {
			return nil, fmt.Errorf("%w: stored update %s mismatches round %s", federated.ErrUpdateCorrupt, u.DeviceID, round.RoundID)
		}
		updates = append(updates, u)
	}
	if err := rows.Err(); err != nil {
		return nil, repositoryUnavailable(err)
	}
	return updates, nil
}

func (s *PostgresRepository) lockRoundWithRecord(ctx context.Context, tx *sql.Tx, roundID string) (federated.RoundStatus, time.Time, contracts.FederatedRoundV1, error) {
	if !repositoryIDPattern.MatchString(roundID) {
		return "", time.Time{}, contracts.FederatedRoundV1{}, federated.ErrRoundNotFound
	}
	var status string
	var deadline time.Time
	var encoded []byte
	err := tx.QueryRowContext(ctx, `SELECT status, deadline, record FROM federated_rounds WHERE deployment_id=$1 AND round_id=$2 FOR UPDATE`,
		s.deploymentID, roundID).Scan(&status, &deadline, &encoded)
	if errors.Is(err, sql.ErrNoRows) {
		return "", time.Time{}, contracts.FederatedRoundV1{}, federated.ErrRoundNotFound
	}
	if err != nil {
		return "", time.Time{}, contracts.FederatedRoundV1{}, repositoryUnavailable(err)
	}
	round, err := s.decodeStoredRound(roundID, encoded)
	if err != nil {
		return "", time.Time{}, contracts.FederatedRoundV1{}, err
	}
	return federated.RoundStatus(status), deadline.UTC(), round, nil
}

func (s *PostgresRepository) decodeStoredRound(roundID string, encoded []byte) (contracts.FederatedRoundV1, error) {
	var round contracts.FederatedRoundV1
	if err := json.Unmarshal(encoded, &round); err != nil || round.Validate() != nil ||
		round.DeploymentID != s.deploymentID || round.RoundID != roundID {
		return contracts.FederatedRoundV1{}, fmt.Errorf("%w: corrupt stored round %s", federated.ErrUpdateCorrupt, roundID)
	}
	return round, nil
}

func (s *PostgresRepository) readAcceptedUpdateTx(ctx context.Context, tx *sql.Tx, roundID, deviceID string) (federated.AcceptedUpdate, []byte, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT device_id, signing_key_id, sequence, candidate_id, base_model_version,
			base_model_sha256, feature_version, parameter_count, sample_count, weights_bytes,
			update_sha256, request_sha256, issued_at, expires_at, accepted_at, envelope
		FROM federated_updates
		WHERE deployment_id=$1 AND round_id=$2 AND device_id=$3`, s.deploymentID, roundID, deviceID)
	if err != nil {
		return federated.AcceptedUpdate{}, nil, false, repositoryUnavailable(err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return federated.AcceptedUpdate{}, nil, false, repositoryUnavailable(err)
		}
		return federated.AcceptedUpdate{}, nil, false, nil
	}
	u, reqDigest, err := scanAcceptedUpdate(rows, s.deploymentID, roundID)
	if err != nil {
		return federated.AcceptedUpdate{}, nil, false, err
	}
	return u, reqDigest, true, nil
}

func scanAcceptedUpdate(scanner interface{ Scan(dest ...any) error }, deploymentID, roundID string) (federated.AcceptedUpdate, []byte, error) {
	var u federated.AcceptedUpdate
	var baseDigest, weightsBytes, updateDigest, reqDigest, envelopeBytes []byte
	var sampleCount int64
	var paramCount int
	if err := scanner.Scan(
		&u.DeviceID, &u.SigningKeyID, &u.Sequence, &u.CandidateID, &u.BaseModelVersion,
		&baseDigest, &u.FeatureVersion, &paramCount, &sampleCount, &weightsBytes,
		&updateDigest, &reqDigest, &u.IssuedAt, &u.ExpiresAt, &u.AcceptedAt, &envelopeBytes,
	); err != nil {
		return federated.AcceptedUpdate{}, nil, repositoryUnavailable(err)
	}
	if paramCount < 1 || sampleCount < 1 {
		return federated.AcceptedUpdate{}, nil, federated.ErrUpdateCorrupt
	}
	u.DeploymentID = deploymentID
	u.RoundID = roundID
	u.ParameterCount = uint32(paramCount)
	u.SampleCount = uint32(sampleCount)
	u.BaseModelSHA256 = hex.EncodeToString(baseDigest)
	u.UpdateSHA256 = hex.EncodeToString(updateDigest)
	u.RequestSHA256 = hex.EncodeToString(reqDigest)
	u.IssuedAt = u.IssuedAt.UTC()
	u.ExpiresAt = u.ExpiresAt.UTC()
	u.AcceptedAt = u.AcceptedAt.UTC()

	sum := sha256.Sum256(weightsBytes)
	if !bytes.Equal(sum[:], updateDigest) {
		return federated.AcceptedUpdate{}, nil, fmt.Errorf("%w: update weights digest mismatch", federated.ErrUpdateCorrupt)
	}
	weights, err := decodeBinary64Weights(weightsBytes, u.ParameterCount)
	if err != nil {
		return federated.AcceptedUpdate{}, nil, fmt.Errorf("%w: %v", federated.ErrUpdateCorrupt, err)
	}
	u.Weights = weights

	if err := json.Unmarshal(envelopeBytes, &u.Envelope); err != nil || u.Envelope.Validate() != nil {
		return federated.AcceptedUpdate{}, nil, fmt.Errorf("%w: stored update envelope invalid", federated.ErrUpdateCorrupt)
	}
	envWeights, err := contracts.DecodeFederatedWeightsV1(u.Envelope.WeightsBase64)
	if err != nil || !equalFloat64Slice(weights, envWeights) {
		return federated.AcceptedUpdate{}, nil, fmt.Errorf("%w: stored update weights disagree with envelope", federated.ErrUpdateCorrupt)
	}
	signingBytes, err := u.Envelope.SigningBytes()
	if err != nil {
		return federated.AcceptedUpdate{}, nil, federated.ErrUpdateCorrupt
	}
	envReqHex, err := contracts.EnvelopeRequestSHA256V1(signingBytes, u.Envelope.Signature)
	if err != nil || envReqHex != u.RequestSHA256 {
		return federated.AcceptedUpdate{}, nil, fmt.Errorf("%w: stored update request digest mismatch", federated.ErrUpdateCorrupt)
	}
	if u.Envelope.DeploymentID != deploymentID || u.Envelope.RoundID != roundID || u.Envelope.DeviceID != u.DeviceID ||
		u.Envelope.SigningKeyID != u.SigningKeyID || u.Envelope.Sequence != u.Sequence ||
		u.Envelope.CandidateID != u.CandidateID || u.Envelope.BaseModelVersion != u.BaseModelVersion ||
		u.Envelope.BaseModelSHA256 != u.BaseModelSHA256 || u.Envelope.FeatureVersion != u.FeatureVersion ||
		u.Envelope.SampleCount != u.SampleCount || u.Envelope.UpdateSHA256 != u.UpdateSHA256 {
		return federated.AcceptedUpdate{}, nil, fmt.Errorf("%w: stored update envelope disagrees with columns", federated.ErrUpdateCorrupt)
	}
	return u, reqDigest, nil
}

func sameAcceptedEnvelope(a, b contracts.FederatedUpdateV1) bool {
	return a.SchemaVersion == b.SchemaVersion &&
		a.DeploymentID == b.DeploymentID &&
		a.DeviceID == b.DeviceID &&
		a.SigningKeyID == b.SigningKeyID &&
		a.Sequence == b.Sequence &&
		a.IssuedAt == b.IssuedAt &&
		a.ExpiresAt == b.ExpiresAt &&
		a.RoundID == b.RoundID &&
		a.BaseModelVersion == b.BaseModelVersion &&
		a.BaseModelSHA256 == b.BaseModelSHA256 &&
		a.CandidateID == b.CandidateID &&
		a.FeatureVersion == b.FeatureVersion &&
		a.SampleCount == b.SampleCount &&
		a.WeightsBase64 == b.WeightsBase64 &&
		a.UpdateSHA256 == b.UpdateSHA256 &&
		a.Signature == b.Signature
}

func encodeBinary64Weights(weights []float64) []byte {
	out := make([]byte, len(weights)*8)
	for i, w := range weights {
		binary.BigEndian.PutUint64(out[i*8:], math.Float64bits(w))
	}
	return out
}

func decodeBinary64Weights(raw []byte, expected uint32) ([]float64, error) {
	if len(raw) == 0 || len(raw)%8 != 0 || uint32(len(raw)/8) != expected {
		return nil, errors.New("unexpected weights byte length")
	}
	weights := make([]float64, len(raw)/8)
	for i := range weights {
		v := math.Float64frombits(binary.BigEndian.Uint64(raw[i*8:]))
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, errors.New("nonfinite weight")
		}
		weights[i] = v
	}
	return weights, nil
}

func equalFloat64Slice(a, b []float64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if math.Float64bits(a[i]) != math.Float64bits(b[i]) {
			return false
		}
	}
	return true
}
