package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
)

// AggregateRound aggregates only durably persisted accepted updates for a
// closed round under WeightingPolicySampleCountV1 and stores a reproducible
// signed candidate artifact in model_artifacts + model_references.candidate.
//
// No-update, insufficient-participant, cancelled-round, and aggregation-failure
// cases persist their failure state without modifying model_references.active.
// Retrying a completed aggregation preserves the candidate identity and digests.
func (s *PostgresRepository) AggregateRound(ctx context.Context, roundID string, signer ed25519.PrivateKey, by federated.Actor) (federated.AggregationRecord, bool, error) {
	if !repositoryIDPattern.MatchString(roundID) {
		return federated.AggregationRecord{}, false, federated.ErrRoundNotFound
	}
	if len(signer) != ed25519.PrivateKeySize {
		return federated.AggregationRecord{}, false, fmt.Errorf("%w: Ed25519 candidate signing key is required", federated.ErrAggregationInvalid)
	}
	if err := by.Validate(); err != nil {
		return federated.AggregationRecord{}, false, fmt.Errorf("%w: %v", federated.ErrAggregationInvalid, err)
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return federated.AggregationRecord{}, false, err
	}
	defer tx.Rollback()

	roundStatus, deadline, round, err := s.lockRoundWithRecord(ctx, tx, roundID)
	if err != nil {
		return federated.AggregationRecord{}, false, err
	}

	if existing, found, err := s.readAggregationTx(ctx, tx, round); err != nil {
		return federated.AggregationRecord{}, false, err
	} else if found {
		tx.Rollback()
		if existing.Status == federated.AggregationSucceeded {
			return existing, false, nil
		}
		return existing, false, aggregationFailureError(existing.FailureReason)
	}

	now := s.now().UTC().Truncate(time.Microsecond)
	if roundStatus == federated.RoundOpen {
		if now.Before(deadline) {
			return federated.AggregationRecord{}, false, fmt.Errorf("%w: round %s is still open until %s", federated.ErrRoundNotOpen, roundID, deadline.Format(time.RFC3339))
		}
		if _, err := s.closeExpired(ctx, tx, roundID); err != nil {
			return federated.AggregationRecord{}, false, err
		}
		roundStatus = federated.RoundClosed
	}

	updates, loadErr := s.acceptedUpdatesTx(ctx, tx, round)
	participants := make([]federated.AggregatedParticipant, 0, len(updates))
	for _, u := range updates {
		participants = append(participants, federated.AggregatedParticipant{
			DeviceID:      u.DeviceID,
			SigningKeyID:  u.SigningKeyID,
			Sequence:      u.Sequence,
			SampleCount:   u.SampleCount,
			UpdateSHA256:  u.UpdateSHA256,
			RequestSHA256: u.RequestSHA256,
		})
	}
	inputSHAHex, totalSamples, inputErr := federated.AggregationInputSHA256(round, federated.WeightingPolicySampleCountV1, participants)
	if inputErr != nil {
		return federated.AggregationRecord{}, false, inputErr
	}

	recordFailed := func(reason string, cause error) (federated.AggregationRecord, bool, error) {
		rec := federated.AggregationRecord{
			DeploymentID:     s.deploymentID,
			RoundID:          round.RoundID,
			CandidateID:      round.CandidateID,
			BaseModelVersion: round.BaseModelVersion,
			BaseModelSHA256:  round.BaseModelSHA256,
			FeatureVersion:   round.FeatureVersion,
			ParameterCount:   round.ParameterCount,
			WeightingPolicy:  federated.WeightingPolicySampleCountV1,
			Status:           federated.AggregationFailed,
			FailureReason:    reason,
			Participants:     participants,
			TotalSamples:     totalSamples,
			InputSHA256:      inputSHAHex,
			CreatedAt:        now,
			By:               by,
		}
		if err := s.insertAggregationTx(ctx, tx, rec, nil, nil, ""); err != nil {
			return federated.AggregationRecord{}, false, err
		}
		if err := repositoryCommit(tx); err != nil {
			return federated.AggregationRecord{}, false, err
		}
		return rec, true, cause
	}

	if roundStatus == federated.RoundCancelled {
		return recordFailed("cancelled", fmt.Errorf("%w: %w: round %s is cancelled", federated.ErrAggregationFailed, federated.ErrRoundNotOpen, roundID))
	}
	if loadErr != nil {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: %w", federated.ErrAggregationFailed, loadErr))
	}
	if len(updates) == 0 {
		return recordFailed("no_updates", fmt.Errorf("%w: %w", federated.ErrAggregationFailed, federated.ErrNoUpdates))
	}
	if uint32(len(updates)) < round.MinParticipants {
		return recordFailed("insufficient_participants", fmt.Errorf("%w: %w (%d < %d)", federated.ErrAggregationFailed, federated.ErrInsufficientParticipants, len(updates), round.MinParticipants))
	}

	weights, _, err := federated.WeightedAverage(round, updates)
	if err != nil {
		return recordFailed("aggregation_failed", err)
	}
	weightsBytes, err := federated.EncodeBinary64Weights(weights)
	if err != nil {
		return recordFailed("aggregation_failed", err)
	}
	weightsSum := sha256.Sum256(weightsBytes)
	weightsSHA := hex.EncodeToString(weightsSum[:])

	baseManifest, baseArtifact, err := s.modelArtifactBytes(ctx, tx, round.BaseModelVersion)
	if err != nil {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: base artifact: %v", federated.ErrAggregationFailed, err))
	}
	if baseManifest.ArtifactSHA256 != round.BaseModelSHA256 || baseManifest.FeatureVersion != round.FeatureVersion || baseManifest.ParameterCount != round.ParameterCount {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: base artifact metadata disagrees with round", federated.ErrAggregationFailed))
	}

	candArtifact, err := federated.BuildCandidateArtifact(round, baseManifest, baseArtifact, weights, weightsSHA, inputSHAHex, len(participants), totalSamples)
	if err != nil {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: %v", federated.ErrAggregationFailed, err))
	}
	if len(candArtifact) == 0 || len(candArtifact) > contracts.ModelArtifactMaxBytesV1 {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: candidate artifact exceeds budget", federated.ErrAggregationFailed))
	}
	candSum := sha256.Sum256(candArtifact)
	candSHA := hex.EncodeToString(candSum[:])

	pub := signer.Public().(ed25519.PublicKey)
	keyID, err := contracts.SigningKeyIDV1(pub)
	if err != nil {
		return federated.AggregationRecord{}, false, err
	}
	manifest := contracts.ModelManifestV1{
		SchemaVersion:  contracts.ModelManifestV1Version,
		ModelVersion:   round.CandidateID,
		ArtifactSHA256: candSHA,
		Architecture:   baseManifest.Architecture,
		ParameterCount: round.ParameterCount,
		RuntimeName:    baseManifest.RuntimeName,
		RuntimeVersion: baseManifest.RuntimeVersion,
		FeatureVersion: round.FeatureVersion,
		Features:       slices.Clone(baseManifest.Features),
		Purposes:       slices.Clone(baseManifest.Purposes),
		SigningKeyID:   keyID,
	}
	signingBytes, err := manifest.SigningBytes()
	if err != nil {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: candidate manifest: %v", federated.ErrAggregationFailed, err))
	}
	manifest.Signature = hex.EncodeToString(ed25519.Sign(signer, signingBytes))
	upload := contracts.ModelArtifactUploadV1{
		SchemaVersion:   contracts.ModelArtifactUploadV1Version,
		Manifest:        manifest,
		Artifact:        candArtifact,
		SourceReference: round.RoundID,
	}
	if err := upload.Verify(pub); err != nil {
		return recordFailed("aggregation_failed", fmt.Errorf("%w: verify candidate upload: %v", federated.ErrAggregationFailed, err))
	}

	existingArtifact, err := s.modelArtifact(ctx, tx, round.CandidateID)
	if err == nil {
		if existingArtifact.Approval != nil {
			return recordFailed("aggregation_failed", fmt.Errorf("%w: candidate version %s is already approved", federated.ErrAggregationFailed, round.CandidateID))
		}
		storedManifest, storedBytes, bytesErr := s.modelArtifactBytes(ctx, tx, round.CandidateID)
		if bytesErr != nil {
			if errors.Is(bytesErr, ErrModelArtifactCorrupt) {
				return recordFailed("aggregation_failed", fmt.Errorf("%w: existing candidate artifact %s failed integrity verification: %v", federated.ErrAggregationFailed, round.CandidateID, bytesErr))
			}
			return federated.AggregationRecord{}, false, bytesErr
		}
		if existingArtifact.Manifest.ArtifactSHA256 != candSHA || storedManifest.ArtifactSHA256 != candSHA || !bytes.Equal(storedBytes, candArtifact) {
			return recordFailed("aggregation_failed", fmt.Errorf("%w: candidate version %s already exists with a different digest", federated.ErrAggregationFailed, round.CandidateID))
		}
	} else if !errors.Is(err, ErrRepositoryNotFound) {
		return federated.AggregationRecord{}, false, err
	} else {
		manifestJSON, err := json.Marshal(manifest)
		if err != nil {
			return federated.AggregationRecord{}, false, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO model_artifacts (
				deployment_id, model_version, artifact_sha256, manifest, artifact,
				source_reference, uploaded_at, actor_issuer, actor_subject
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			s.deploymentID, manifest.ModelVersion, candSum[:], string(manifestJSON), candArtifact,
			round.RoundID, now, by.Issuer, by.Subject); err != nil {
			return federated.AggregationRecord{}, false, repositoryUnavailable(err)
		}
	}

	// Update candidate reference only; active slot is never touched by aggregation.
	if _, err := tx.ExecContext(ctx, `INSERT INTO model_references (deployment_id, slot, model_version, artifact_sha256, set_at, actor_issuer, actor_subject)
		VALUES ($1,'candidate',$2,$3,$4,$5,$6)
		ON CONFLICT (deployment_id, slot) DO UPDATE SET model_version=EXCLUDED.model_version,
		artifact_sha256=EXCLUDED.artifact_sha256, set_at=EXCLUDED.set_at, actor_issuer=EXCLUDED.actor_issuer, actor_subject=EXCLUDED.actor_subject`,
		s.deploymentID, manifest.ModelVersion, candSum[:], now, by.Issuer, by.Subject); err != nil {
		return federated.AggregationRecord{}, false, repositoryUnavailable(err)
	}

	rec := federated.AggregationRecord{
		DeploymentID:          s.deploymentID,
		RoundID:               round.RoundID,
		CandidateID:           round.CandidateID,
		BaseModelVersion:      round.BaseModelVersion,
		BaseModelSHA256:       round.BaseModelSHA256,
		FeatureVersion:        round.FeatureVersion,
		ParameterCount:        round.ParameterCount,
		WeightingPolicy:       federated.WeightingPolicySampleCountV1,
		Status:                federated.AggregationSucceeded,
		Participants:          participants,
		TotalSamples:          totalSamples,
		InputSHA256:           inputSHAHex,
		Weights:               weights,
		WeightsSHA256:         weightsSHA,
		CandidateModelVersion: manifest.ModelVersion,
		CandidateModelSHA256:  candSHA,
		CreatedAt:             now,
		By:                    by,
	}
	if err := s.insertAggregationTx(ctx, tx, rec, weightsBytes, weightsSum[:], candSHA); err != nil {
		return federated.AggregationRecord{}, false, err
	}
	if err := repositoryCommit(tx); err != nil {
		return federated.AggregationRecord{}, false, err
	}
	return rec, true, nil
}

// Aggregation reads one round's persisted aggregation record and verifies
// stored weight and candidate artifact digests.
func (s *PostgresRepository) Aggregation(ctx context.Context, roundID string) (federated.AggregationRecord, error) {
	if !repositoryIDPattern.MatchString(roundID) {
		return federated.AggregationRecord{}, federated.ErrRoundNotFound
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return federated.AggregationRecord{}, repositoryUnavailable(err)
	}
	defer tx.Rollback()

	var encodedRound []byte
	if err := tx.QueryRowContext(ctx, `SELECT record FROM federated_rounds WHERE deployment_id=$1 AND round_id=$2`,
		s.deploymentID, roundID).Scan(&encodedRound); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return federated.AggregationRecord{}, federated.ErrRoundNotFound
		}
		return federated.AggregationRecord{}, repositoryUnavailable(err)
	}
	round, err := s.decodeStoredRound(roundID, encodedRound)
	if err != nil {
		return federated.AggregationRecord{}, fmt.Errorf("%w: %v", federated.ErrAggregationCorrupt, err)
	}
	rec, found, err := s.readAggregationTx(ctx, tx, round)
	if err != nil {
		return federated.AggregationRecord{}, err
	}
	if !found {
		return federated.AggregationRecord{}, ErrRepositoryNotFound
	}
	return rec, nil
}

func (s *PostgresRepository) insertAggregationTx(ctx context.Context, tx *sql.Tx, rec federated.AggregationRecord, weightsBytes, weightsSum []byte, candSHA string) error {
	partJSON, err := json.Marshal(rec.Participants)
	if err != nil {
		return err
	}
	var failureReason sql.NullString
	if rec.FailureReason != "" {
		failureReason = sql.NullString{String: rec.FailureReason, Valid: true}
	}
	var candVersion sql.NullString
	var candDigest []byte
	if candSHA != "" {
		candVersion = sql.NullString{String: rec.CandidateModelVersion, Valid: true}
		candDigest = decodeRepositoryDigest(candSHA)
	}
	inputDigest := decodeRepositoryDigest(rec.InputSHA256)
	baseDigest := decodeRepositoryDigest(rec.BaseModelSHA256)

	if _, err := tx.ExecContext(ctx, `INSERT INTO federated_aggregations (
			deployment_id, round_id, candidate_id, base_model_version, base_model_sha256,
			feature_version, parameter_count, weighting_policy, status, failure_reason,
			participant_count, total_samples, input_sha256, participants,
			weights_bytes, weights_sha256, candidate_model_version, candidate_model_sha256,
			created_at, actor_issuer, actor_subject
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)`,
		s.deploymentID, rec.RoundID, rec.CandidateID, rec.BaseModelVersion, baseDigest,
		rec.FeatureVersion, rec.ParameterCount, rec.WeightingPolicy, string(rec.Status), failureReason,
		len(rec.Participants), rec.TotalSamples, inputDigest, string(partJSON),
		weightsBytes, weightsSum, candVersion, candDigest,
		rec.CreatedAt, rec.By.Issuer, rec.By.Subject); err != nil {
		return repositoryUnavailable(err)
	}
	return nil
}

func (s *PostgresRepository) readAggregationTx(ctx context.Context, q dbQueryer, round contracts.FederatedRoundV1) (federated.AggregationRecord, bool, error) {
	var rec federated.AggregationRecord
	var baseDigest, inputDigest, participantsJSON, weightsBytes, weightsDigest, candDigest []byte
	var status string
	var failureReason, candVersion sql.NullString
	var paramCount, partCount int
	var totalSamples int64

	err := q.QueryRowContext(ctx, `SELECT round_id, candidate_id, base_model_version, base_model_sha256,
			feature_version, parameter_count, weighting_policy, status, failure_reason,
			participant_count, total_samples, input_sha256, participants,
			weights_bytes, weights_sha256, candidate_model_version, candidate_model_sha256,
			created_at, actor_issuer, actor_subject
		FROM federated_aggregations
		WHERE deployment_id=$1 AND round_id=$2`, s.deploymentID, round.RoundID).Scan(
		&rec.RoundID, &rec.CandidateID, &rec.BaseModelVersion, &baseDigest,
		&rec.FeatureVersion, &paramCount, &rec.WeightingPolicy, &status, &failureReason,
		&partCount, &totalSamples, &inputDigest, &participantsJSON,
		&weightsBytes, &weightsDigest, &candVersion, &candDigest,
		&rec.CreatedAt, &rec.By.Issuer, &rec.By.Subject,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return federated.AggregationRecord{}, false, nil
	}
	if err != nil {
		return federated.AggregationRecord{}, false, repositoryUnavailable(err)
	}
	if paramCount < 1 || partCount < 0 || totalSamples < 0 {
		return federated.AggregationRecord{}, false, federated.ErrAggregationCorrupt
	}
	rec.DeploymentID = s.deploymentID
	rec.ParameterCount = uint32(paramCount)
	rec.BaseModelSHA256 = hex.EncodeToString(baseDigest)
	rec.Status = federated.AggregationStatus(status)
	rec.FailureReason = failureReason.String
	rec.TotalSamples = uint64(totalSamples)
	rec.InputSHA256 = hex.EncodeToString(inputDigest)
	rec.CreatedAt = rec.CreatedAt.UTC()
	if rec.RoundID != round.RoundID || rec.CandidateID != round.CandidateID ||
		rec.BaseModelVersion != round.BaseModelVersion || rec.BaseModelSHA256 != round.BaseModelSHA256 ||
		rec.FeatureVersion != round.FeatureVersion || rec.ParameterCount != round.ParameterCount ||
		rec.WeightingPolicy != federated.WeightingPolicySampleCountV1 {
		return federated.AggregationRecord{}, false, fmt.Errorf("%w: aggregation metadata mismatches round", federated.ErrAggregationCorrupt)
	}
	if err := json.Unmarshal(participantsJSON, &rec.Participants); err != nil || len(rec.Participants) != partCount {
		return federated.AggregationRecord{}, false, fmt.Errorf("%w: stored participant list invalid", federated.ErrAggregationCorrupt)
	}
	gotInputSHA, gotTotalSamples, err := federated.AggregationInputSHA256(round, rec.WeightingPolicy, rec.Participants)
	if err != nil || gotTotalSamples != rec.TotalSamples || gotInputSHA != rec.InputSHA256 {
		return federated.AggregationRecord{}, false, fmt.Errorf("%w: stored participant commitment mismatch", federated.ErrAggregationCorrupt)
	}

	if rec.Status == federated.AggregationSucceeded {
		if !candVersion.Valid || len(candDigest) != 32 || len(weightsDigest) != 32 {
			return federated.AggregationRecord{}, false, federated.ErrAggregationCorrupt
		}
		sum := sha256.Sum256(weightsBytes)
		if !bytes.Equal(sum[:], weightsDigest) {
			return federated.AggregationRecord{}, false, fmt.Errorf("%w: weights digest mismatch", federated.ErrAggregationCorrupt)
		}
		weights, err := federated.DecodeBinary64Weights(weightsBytes, rec.ParameterCount)
		if err != nil {
			return federated.AggregationRecord{}, false, err
		}
		rec.Weights = weights
		rec.WeightsSHA256 = hex.EncodeToString(weightsDigest)
		rec.CandidateModelVersion = candVersion.String
		rec.CandidateModelSHA256 = hex.EncodeToString(candDigest)

		// Re-verify stored candidate artifact bytes against candidate digest.
		storedManifest, _, err := s.modelArtifactBytes(ctx, q, rec.CandidateModelVersion)
		if err != nil {
			if errors.Is(err, ErrRepositoryNotFound) || errors.Is(err, ErrModelArtifactCorrupt) {
				return federated.AggregationRecord{}, false, fmt.Errorf("%w: candidate artifact verification failed: %v", federated.ErrAggregationCorrupt, err)
			}
			return federated.AggregationRecord{}, false, err
		}
		if storedManifest.ArtifactSHA256 != rec.CandidateModelSHA256 {
			return federated.AggregationRecord{}, false, fmt.Errorf("%w: candidate artifact digest mismatch", federated.ErrAggregationCorrupt)
		}
	}
	return rec, true, nil
}

func aggregationFailureError(reason string) error {
	switch reason {
	case "no_updates":
		return fmt.Errorf("%w: %w", federated.ErrAggregationFailed, federated.ErrNoUpdates)
	case "insufficient_participants":
		return fmt.Errorf("%w: %w", federated.ErrAggregationFailed, federated.ErrInsufficientParticipants)
	case "cancelled":
		return fmt.Errorf("%w: %w", federated.ErrAggregationFailed, federated.ErrRoundNotOpen)
	default:
		return federated.ErrAggregationFailed
	}
}
