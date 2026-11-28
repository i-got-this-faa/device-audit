package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

var (
	// ErrPredictionEvidenceBroken indicates a missing, cross-scope, or tampered
	// evidence or model reference for a prediction record.
	ErrPredictionEvidenceBroken = errors.New("prediction evidence or model reference failed integrity check")
	// ErrPredictionInvalid indicates malformed prediction evaluation inputs or
	// inconsistent provenance metadata.
	ErrPredictionInvalid = errors.New("invalid prediction record")
)

type predictionHistoryCursor struct {
	asOf time.Time
	id   uint64
}

func (c predictionHistoryCursor) String() string {
	return strconv.FormatInt(c.asOf.UnixMicro(), 10) + "." + strconv.FormatUint(c.id, 10)
}

func parsePredictionHistoryCursor(raw string) (predictionHistoryCursor, error) {
	micros, idText, ok := strings.Cut(raw, ".")
	if !ok {
		return predictionHistoryCursor{}, ErrDeviceStateInvalid
	}
	m, err1 := strconv.ParseInt(micros, 10, 64)
	id, err2 := strconv.ParseUint(idText, 10, 64)
	c := predictionHistoryCursor{asOf: time.UnixMicro(m).UTC(), id: id}
	if err1 != nil || err2 != nil || c.String() != raw || id < 1 {
		return predictionHistoryCursor{}, ErrDeviceStateInvalid
	}
	return c, nil
}

// EvaluateAndRecordDeviceHealth evaluates one enrolled device at asOf and
// persists the resulting prediction/health record and all provenance inside one
// repeatable-read snapshot transaction.
func (s *PostgresRepository) EvaluateAndRecordDeviceHealth(ctx context.Context, cfg HealthConfig, deviceID string, asOf time.Time) (contracts.PredictionHistoryRecordV1, error) {
	return s.evaluateAndRecordDeviceHealth(ctx, cfg, deviceID, asOf, func(r evidenceRef) health.SMARTReading {
		return health.SMARTReading{ObservedAt: r.CollectedAt}
	})
}

func (s *PostgresRepository) evaluateAndRecordDeviceHealth(ctx context.Context, cfg HealthConfig, deviceID string, asOf time.Time, readSMART func(evidenceRef) health.SMARTReading) (contracts.PredictionHistoryRecordV1, error) {
	if !repositoryIDPattern.MatchString(deviceID) || asOf.IsZero() || cfg.MaxEvidenceAge < 0 {
		return contracts.PredictionHistoryRecordV1{}, ErrDeviceStateInvalid
	}
	asOf = asOf.UTC().Truncate(time.Microsecond)

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, repositoryUnavailable(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		return contracts.PredictionHistoryRecordV1{}, repositoryUnavailable(err)
	}
	dh, err := s.evaluateDeviceHealthTx(ctx, tx, cfg, deviceID, asOf, readSMART)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	record, err := s.insertDevicePrediction(ctx, tx, dh)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	return record, nil
}

// RecordDeviceHealth validates and persists an evaluated DeviceHealth record
// after verifying its deployment scope, enrollment, evidence payload digest,
// and approved model reference inside a durable write transaction.
func (s *PostgresRepository) RecordDeviceHealth(ctx context.Context, dh DeviceHealth) (contracts.PredictionHistoryRecordV1, error) {
	if dh.DeploymentID == "" || dh.DeploymentID != s.deploymentID {
		return contracts.PredictionHistoryRecordV1{}, ErrDeviceStateScope
	}
	if !repositoryIDPattern.MatchString(dh.DeviceID) || dh.AsOf.IsZero() {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2 FOR KEY SHARE`,
		s.deploymentID, dh.DeviceID).Scan(&exists); err != nil {
		return contracts.PredictionHistoryRecordV1{}, repositoryReadError(err)
	}
	record, err := s.insertDevicePrediction(ctx, tx, dh)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	return record, nil
}

func (s *PostgresRepository) insertDevicePrediction(ctx context.Context, tx *sql.Tx, dh DeviceHealth) (contracts.PredictionHistoryRecordV1, error) {
	if dh.DeploymentID != s.deploymentID {
		return contracts.PredictionHistoryRecordV1{}, ErrDeviceStateScope
	}
	asOf := dh.AsOf.UTC().Truncate(time.Microsecond)
	if !repositoryIDPattern.MatchString(dh.DeviceID) || asOf.IsZero() ||
		dh.Assessment.RulesVersion == "" || dh.Assessment.RuleReason == "" ||
		dh.Assessment.DeviceID != dh.DeviceID || dh.Assessment.FaultObservationNote == "" {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
	}
	if err := dh.Features.Vector.Validate(); err != nil {
		return contracts.PredictionHistoryRecordV1{}, fmt.Errorf("%w: %v", ErrPredictionInvalid, err)
	}
	if dh.Features.SamplesRead < 0 {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
	}
	currentWin, baselineWin := dh.FaultHistory.History.Current, dh.FaultHistory.History.Baseline
	if currentWin.Days != health.FaultCurrentDays || baselineWin.Days != health.FaultBaselineDays ||
		!baselineWin.To.Equal(currentWin.From) || !baselineWin.From.Before(baselineWin.To) || !currentWin.From.Before(currentWin.To) ||
		dh.FaultHistory.SamplesRead < 0 {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
	}

	var predCopy *contracts.PredictionV2
	var expiresAt *time.Time
	var predictionJSON any
	if dh.LatestSample == nil {
		if dh.Assessment.Prediction != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
	} else {
		if dh.Assessment.Prediction == nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
		}
		p := *dh.Assessment.Prediction
		p.GeneratedAt = asOf
		p.ExpiresAt = p.ExpiresAt.UTC().Truncate(time.Microsecond)
		if !p.ExpiresAt.After(asOf) {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
		}
		if err := p.Validate(); err != nil {
			return contracts.PredictionHistoryRecordV1{}, fmt.Errorf("%w: %v", ErrPredictionInvalid, err)
		}
		if p.DeviceID != dh.DeviceID || p.Evidence.Digest != dh.LatestSample.PayloadSHA256 ||
			p.Evidence.TelemetrySchemaVersion != dh.LatestSample.TelemetrySchemaVersion {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		if err := verifyEvidenceReference(ctx, tx, s.deploymentID, dh.DeviceID, *dh.LatestSample); err != nil {
			return contracts.PredictionHistoryRecordV1{}, err
		}
		raw, err := json.Marshal(p)
		if err != nil {
			return contracts.PredictionHistoryRecordV1{}, err
		}
		exp := p.ExpiresAt
		expiresAt = &exp
		predCopy = &p
		predictionJSON = string(raw)
	}

	var modelProv *contracts.PredictionModelProvenanceV1
	var modelVersion, policyVersion sql.NullString
	var modelDigest, policyDigest, evalDigest []byte
	if dh.Model != nil || dh.Assessment.Model != nil {
		if dh.Model == nil || dh.Assessment.Model == nil || *dh.Model != *dh.Assessment.Model ||
			dh.Assessment.PolicyVersion == "" || dh.Assessment.PolicySHA256 == "" || dh.Assessment.EvaluationSHA256 == "" {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
		}
		if err := verifyModelApprovalReference(ctx, tx, s.deploymentID, dh.Model.Version, dh.Model.SHA256, dh.Assessment.EvaluationSHA256, dh.Assessment.PolicyVersion); err != nil {
			return contracts.PredictionHistoryRecordV1{}, err
		}
		modelProv = &contracts.PredictionModelProvenanceV1{
			Version:          dh.Model.Version,
			SHA256:           dh.Model.SHA256,
			PolicyVersion:    dh.Assessment.PolicyVersion,
			PolicySHA256:     dh.Assessment.PolicySHA256,
			EvaluationSHA256: dh.Assessment.EvaluationSHA256,
		}
		modelVersion = sql.NullString{String: modelProv.Version, Valid: true}
		policyVersion = sql.NullString{String: modelProv.PolicyVersion, Valid: true}
		var err error
		if modelDigest, err = decodeSHA256Hex(modelProv.SHA256); err != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
		}
		if policyDigest, err = decodeSHA256Hex(modelProv.PolicySHA256); err != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
		}
		if evalDigest, err = decodeSHA256Hex(modelProv.EvaluationSHA256); err != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
		}
	}

	if dh.Assessment.Health.Status != health.HealthStatusUnknown &&
		(dh.LatestSample == nil || dh.LatestSample.CollectedAt.After(asOf) || modelProv == nil || dh.Features.Vector.Status != contracts.FeatureStatusComplete) {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionInvalid
	}

	var evSeq sql.NullInt64
	var evCollected, evReceived sql.NullTime
	var evSource, evSchema sql.NullString
	var evPayloadDigest, evReqDigest []byte
	var evRef *contracts.PredictionEvidenceRefV1
	if dh.LatestSample != nil {
		var err error
		evSeq = sql.NullInt64{Int64: int64(dh.LatestSample.Sequence), Valid: true}
		evCollected = sql.NullTime{Time: dh.LatestSample.CollectedAt.UTC().Truncate(time.Microsecond), Valid: true}
		evReceived = sql.NullTime{Time: dh.LatestSample.ReceivedAt.UTC().Truncate(time.Microsecond), Valid: true}
		evSource = sql.NullString{String: dh.LatestSample.Source, Valid: true}
		evSchema = sql.NullString{String: dh.LatestSample.TelemetrySchemaVersion, Valid: true}
		if evPayloadDigest, err = decodeSHA256Hex(dh.LatestSample.PayloadSHA256); err != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		if evReqDigest, err = decodeSHA256Hex(dh.LatestSample.RequestSHA256); err != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		evRef = &contracts.PredictionEvidenceRefV1{
			Sequence:               dh.LatestSample.Sequence,
			CollectedAt:            evCollected.Time,
			ReceivedAt:             evReceived.Time,
			PayloadSHA256:          dh.LatestSample.PayloadSHA256,
			RequestSHA256:          dh.LatestSample.RequestSHA256,
			Source:                 dh.LatestSample.Source,
			TelemetrySchemaVersion: dh.LatestSample.TelemetrySchemaVersion,
		}
	}

	featureJSON, err := json.Marshal(dh.Features.Vector)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}
	faultSummaryJSON, err := json.Marshal(dh.Assessment.FaultSummary)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, err
	}

	var unknownReason sql.NullString
	if dh.Assessment.Health.UnknownReason != "" {
		unknownReason = sql.NullString{String: dh.Assessment.Health.UnknownReason, Valid: true}
	}
	var prob sql.NullFloat64
	if dh.Assessment.Health.Probability != nil {
		prob = sql.NullFloat64{Float64: *dh.Assessment.Health.Probability, Valid: true}
	}
	var horizon sql.NullInt64
	if dh.Assessment.Health.HorizonHours != nil {
		horizon = sql.NullInt64{Int64: int64(*dh.Assessment.Health.HorizonHours), Valid: true}
	}
	modelStatus := dh.ModelStatus
	if modelStatus == "" {
		modelStatus = dh.Assessment.ModelStatus
	}
	recordedAt := s.now().UTC().Truncate(time.Microsecond)

	var id uint64
	err = tx.QueryRowContext(ctx, `INSERT INTO device_predictions (
			deployment_id, device_id, as_of, expires_at, recorded_at,
			rules_version, rule_reason,
			health_status, probability, probability_unit, horizon_hours, unknown_reason,
			model_status, model_error, model_version, model_sha256, policy_version, policy_sha256, evaluation_sha256,
			evidence_sequence, evidence_collected_at, evidence_received_at, evidence_payload_sha256,
			evidence_request_sha256, evidence_source, evidence_telemetry_schema_version,
			feature_version, feature_window_start, feature_window_end, feature_status,
			feature_count, feature_samples_read, feature_last_sequence, feature_vector,
			fault_current_from, fault_current_to, fault_current_days, fault_current_sampled_days, fault_current_sufficient,
			fault_baseline_from, fault_baseline_to, fault_baseline_days, fault_baseline_sampled_days, fault_baseline_sufficient,
			fault_observation_note, fault_summary, fault_samples_read, fault_last_sequence,
			prediction
		) VALUES (
			$1,$2,$3,$4,$5,
			$6,$7,
			$8,$9,$10,$11,$12,
			$13,$14,$15,$16,$17,$18,$19,
			$20,$21,$22,$23,
			$24,$25,$26,
			$27,$28,$29,$30,
			$31,$32,$33,$34,
			$35,$36,$37,$38,$39,
			$40,$41,$42,$43,$44,
			$45,$46,$47,$48,
			$49
		) RETURNING id`,
		s.deploymentID, dh.DeviceID, asOf, expiresAt, recordedAt,
		dh.Assessment.RulesVersion, dh.Assessment.RuleReason,
		dh.Assessment.Health.Status, prob, dh.Assessment.Health.ProbabilityUnit, horizon, unknownReason,
		modelStatus, dh.ModelError, modelVersion, modelDigest, policyVersion, policyDigest, evalDigest,
		evSeq, evCollected, evReceived, evPayloadDigest,
		evReqDigest, evSource, evSchema,
		dh.Features.Vector.FeatureVersion, dh.Features.Vector.WindowStart, dh.Features.Vector.WindowEnd, dh.Features.Vector.Status,
		len(dh.Features.Vector.Features), dh.Features.SamplesRead, int64(dh.Features.LastSequence), string(featureJSON),
		currentWin.From.UTC().Truncate(time.Microsecond), currentWin.To.UTC().Truncate(time.Microsecond), currentWin.Days, currentWin.SampledDays, currentWin.Sufficient,
		baselineWin.From.UTC().Truncate(time.Microsecond), baselineWin.To.UTC().Truncate(time.Microsecond), baselineWin.Days, baselineWin.SampledDays, baselineWin.Sufficient,
		dh.Assessment.FaultObservationNote, string(faultSummaryJSON), dh.FaultHistory.SamplesRead, int64(dh.FaultHistory.LastSequence),
		predictionJSON,
	).Scan(&id)
	if err != nil {
		return contracts.PredictionHistoryRecordV1{}, repositoryUnavailable(err)
	}

	now := s.now().UTC()
	stale := dh.Assessment.Health.UnknownReason == health.UnknownReasonStaleEvidence || (expiresAt != nil && !now.Before(*expiresAt))
	rec := contracts.PredictionHistoryRecordV1{
		ID:              id,
		AsOf:            asOf,
		RecordedAt:      recordedAt,
		ExpiresAt:       expiresAt,
		Stale:           stale,
		RulesVersion:    dh.Assessment.RulesVersion,
		RuleReason:      dh.Assessment.RuleReason,
		ModelStatus:     modelStatus,
		ModelError:      dh.ModelError,
		ModelProvenance: modelProv,
		Evidence:        evRef,
		Features: contracts.PredictionFeatureRefV1{
			FeatureVersion: dh.Features.Vector.FeatureVersion,
			WindowStart:    dh.Features.Vector.WindowStart,
			WindowEnd:      dh.Features.Vector.WindowEnd,
			Status:         dh.Features.Vector.Status,
			FeatureCount:   len(dh.Features.Vector.Features),
			SamplesRead:    dh.Features.SamplesRead,
			LastSequence:   dh.Features.LastSequence,
		},
		FaultBaseline: contracts.PredictionFaultBaselineRefV1{
			Current: contracts.PredictionFaultWindowRefV1{
				From:        currentWin.From.UTC().Truncate(time.Microsecond),
				To:          currentWin.To.UTC().Truncate(time.Microsecond),
				Days:        currentWin.Days,
				SampledDays: currentWin.SampledDays,
				Sufficient:  currentWin.Sufficient,
			},
			Baseline: contracts.PredictionFaultWindowRefV1{
				From:        baselineWin.From.UTC().Truncate(time.Microsecond),
				To:          baselineWin.To.UTC().Truncate(time.Microsecond),
				Days:        baselineWin.Days,
				SampledDays: baselineWin.SampledDays,
				Sufficient:  baselineWin.Sufficient,
			},
			ObservationNote:          dh.Assessment.FaultObservationNote,
			TotalTypes:               dh.Assessment.FaultSummary.TotalTypes,
			RecurrentTypes:           dh.Assessment.FaultSummary.RecurrentTypes,
			IsolatedTypes:            dh.Assessment.FaultSummary.IsolatedTypes,
			BaselineOnlyTypes:        dh.Assessment.FaultSummary.BaselineOnlyTypes,
			InsufficientHistoryTypes: dh.Assessment.FaultSummary.InsufficientHistoryTypes,
			CurrentReports:           dh.Assessment.FaultSummary.CurrentReports,
			BaselineReports:          dh.Assessment.FaultSummary.BaselineReports,
			DuplicateReports:         dh.Assessment.FaultSummary.DuplicateReports,
			SamplesRead:              dh.FaultHistory.SamplesRead,
			LastSequence:             dh.FaultHistory.LastSequence,
		},
		Health:     dh.Assessment.Health,
		Prediction: predCopy,
	}
	if err := rec.Validate(dh.DeviceID); err != nil {
		return contracts.PredictionHistoryRecordV1{}, fmt.Errorf("%w: %v", ErrPredictionInvalid, err)
	}
	return rec, nil
}

func verifyEvidenceReference(ctx context.Context, q dbQueryer, deploymentID, deviceID string, ev DeviceEvidenceSummary) error {
	var payload, reqDigest []byte
	var collectedAt, receivedAt time.Time
	err := q.QueryRowContext(ctx, `SELECT payload_bytes, request_sha256, collected_at, received_at
		FROM device_evidence WHERE deployment_id=$1 AND device_id=$2 AND sequence=$3 FOR KEY SHARE`,
		deploymentID, deviceID, int64(ev.Sequence)).Scan(&payload, &reqDigest, &collectedAt, &receivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPredictionEvidenceBroken
	}
	if err != nil {
		return repositoryUnavailable(err)
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != ev.PayloadSHA256 ||
		hex.EncodeToString(reqDigest) != ev.RequestSHA256 ||
		!collectedAt.UTC().Equal(ev.CollectedAt.UTC().Truncate(time.Microsecond)) ||
		!receivedAt.UTC().Equal(ev.ReceivedAt.UTC().Truncate(time.Microsecond)) {
		return ErrPredictionEvidenceBroken
	}
	var telemetry contracts.TelemetryV2
	if err := json.Unmarshal(payload, &telemetry); err != nil ||
		telemetry.SchemaVersion != ev.TelemetrySchemaVersion ||
		telemetry.DeviceID != deviceID ||
		telemetry.Source != ev.Source {
		return ErrPredictionEvidenceBroken
	}
	return nil
}

func verifyModelApprovalReference(ctx context.Context, q dbQueryer, deploymentID, version, artifactSHA256, evalSHA256, policyVersion string) error {
	var storedEval []byte
	var storedPolicy string
	digestBytes, err := decodeSHA256Hex(artifactSHA256)
	if err != nil {
		return ErrPredictionInvalid
	}
	err = q.QueryRowContext(ctx, `SELECT evaluation_sha256, policy_version FROM model_approvals
		WHERE deployment_id=$1 AND model_version=$2 AND artifact_sha256=$3 FOR KEY SHARE`,
		deploymentID, version, digestBytes).Scan(&storedEval, &storedPolicy)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrPredictionEvidenceBroken
	}
	if err != nil {
		return repositoryUnavailable(err)
	}
	if hex.EncodeToString(storedEval) != evalSHA256 || storedPolicy != policyVersion {
		return ErrPredictionEvidenceBroken
	}
	return nil
}

const predictionHistorySelect = `SELECT
	p.id, p.deployment_id, p.device_id, p.as_of, p.expires_at, p.recorded_at,
	p.rules_version, p.rule_reason,
	p.health_status, p.probability, p.probability_unit, p.horizon_hours, p.unknown_reason,
	p.model_status, p.model_error, p.model_version, p.model_sha256, p.policy_version, p.policy_sha256, p.evaluation_sha256,
	p.evidence_sequence, p.evidence_collected_at, p.evidence_received_at, p.evidence_payload_sha256,
	p.evidence_request_sha256, p.evidence_source, p.evidence_telemetry_schema_version,
	p.feature_version, p.feature_window_start, p.feature_window_end, p.feature_status,
	p.feature_count, p.feature_samples_read, p.feature_last_sequence,
	p.fault_current_from, p.fault_current_to, p.fault_current_days, p.fault_current_sampled_days, p.fault_current_sufficient,
	p.fault_baseline_from, p.fault_baseline_to, p.fault_baseline_days, p.fault_baseline_sampled_days, p.fault_baseline_sufficient,
	p.fault_observation_note, p.fault_summary, p.fault_samples_read, p.fault_last_sequence,
	p.prediction,
	e.payload_bytes, e.request_sha256, e.collected_at, e.received_at,
	a.artifact_sha256, a.evaluation_sha256, a.policy_version
FROM device_predictions p
LEFT JOIN device_evidence e
	ON e.deployment_id = p.deployment_id AND e.device_id = p.device_id AND e.sequence = p.evidence_sequence
LEFT JOIN model_approvals a
	ON a.deployment_id = p.deployment_id AND a.model_version = p.model_version AND a.artifact_sha256 = p.model_sha256`

type predictionRowScanner interface{ Scan(...any) error }

func (s *PostgresRepository) scanPredictionRecord(row predictionRowScanner, deviceID string, now time.Time) (contracts.PredictionHistoryRecordV1, error) {
	var rec contracts.PredictionHistoryRecordV1
	var rowDeploymentID, rowDeviceID string
	var expiresAt sql.NullTime
	var prob sql.NullFloat64
	var horizon sql.NullInt64
	var unknownReason sql.NullString
	var modelVersion, policyVersion sql.NullString
	var modelDigest, policyDigest, evalDigest []byte
	var evSeq sql.NullInt64
	var evCollected, evReceived sql.NullTime
	var evPayloadDigest, evReqDigest []byte
	var evSource, evSchema sql.NullString
	var faultSummaryRaw, predictionRaw []byte
	var joinedPayload, joinedReqDigest []byte
	var joinedCollected, joinedReceived sql.NullTime
	var joinedArtifactDigest, joinedEvalDigest []byte
	var joinedPolicy sql.NullString

	if err := row.Scan(
		&rec.ID, &rowDeploymentID, &rowDeviceID, &rec.AsOf, &expiresAt, &rec.RecordedAt,
		&rec.RulesVersion, &rec.RuleReason,
		&rec.Health.Status, &prob, &rec.Health.ProbabilityUnit, &horizon, &unknownReason,
		&rec.ModelStatus, &rec.ModelError, &modelVersion, &modelDigest, &policyVersion, &policyDigest, &evalDigest,
		&evSeq, &evCollected, &evReceived, &evPayloadDigest,
		&evReqDigest, &evSource, &evSchema,
		&rec.Features.FeatureVersion, &rec.Features.WindowStart, &rec.Features.WindowEnd, &rec.Features.Status,
		&rec.Features.FeatureCount, &rec.Features.SamplesRead, &rec.Features.LastSequence,
		&rec.FaultBaseline.Current.From, &rec.FaultBaseline.Current.To, &rec.FaultBaseline.Current.Days, &rec.FaultBaseline.Current.SampledDays, &rec.FaultBaseline.Current.Sufficient,
		&rec.FaultBaseline.Baseline.From, &rec.FaultBaseline.Baseline.To, &rec.FaultBaseline.Baseline.Days, &rec.FaultBaseline.Baseline.SampledDays, &rec.FaultBaseline.Baseline.Sufficient,
		&rec.FaultBaseline.ObservationNote, &faultSummaryRaw, &rec.FaultBaseline.SamplesRead, &rec.FaultBaseline.LastSequence,
		&predictionRaw,
		&joinedPayload, &joinedReqDigest, &joinedCollected, &joinedReceived,
		&joinedArtifactDigest, &joinedEvalDigest, &joinedPolicy,
	); err != nil {
		return contracts.PredictionHistoryRecordV1{}, repositoryReadError(err)
	}
	if rowDeploymentID != s.deploymentID || rowDeviceID != deviceID {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
	}
	rec.AsOf = rec.AsOf.UTC()
	rec.RecordedAt = rec.RecordedAt.UTC()
	rec.FaultBaseline.Current.From = rec.FaultBaseline.Current.From.UTC()
	rec.FaultBaseline.Current.To = rec.FaultBaseline.Current.To.UTC()
	rec.FaultBaseline.Baseline.From = rec.FaultBaseline.Baseline.From.UTC()
	rec.FaultBaseline.Baseline.To = rec.FaultBaseline.Baseline.To.UTC()
	if expiresAt.Valid {
		exp := expiresAt.Time.UTC()
		rec.ExpiresAt = &exp
	}
	if prob.Valid {
		v := prob.Float64
		rec.Health.Probability = &v
	}
	if horizon.Valid {
		h := uint32(horizon.Int64)
		rec.Health.HorizonHours = &h
	}
	if unknownReason.Valid {
		rec.Health.UnknownReason = unknownReason.String
	}

	var faultSummary health.FaultSummary
	if err := json.Unmarshal(faultSummaryRaw, &faultSummary); err != nil {
		return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
	}
	rec.FaultBaseline.TotalTypes = faultSummary.TotalTypes
	rec.FaultBaseline.RecurrentTypes = faultSummary.RecurrentTypes
	rec.FaultBaseline.IsolatedTypes = faultSummary.IsolatedTypes
	rec.FaultBaseline.BaselineOnlyTypes = faultSummary.BaselineOnlyTypes
	rec.FaultBaseline.InsufficientHistoryTypes = faultSummary.InsufficientHistoryTypes
	rec.FaultBaseline.CurrentReports = faultSummary.CurrentReports
	rec.FaultBaseline.BaselineReports = faultSummary.BaselineReports
	rec.FaultBaseline.DuplicateReports = faultSummary.DuplicateReports

	if modelVersion.Valid {
		if len(modelDigest) != 32 || len(policyDigest) != 32 || len(evalDigest) != 32 || !policyVersion.Valid ||
			len(joinedArtifactDigest) != 32 || len(joinedEvalDigest) != 32 || !joinedPolicy.Valid {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		if hex.EncodeToString(joinedArtifactDigest) != hex.EncodeToString(modelDigest) ||
			hex.EncodeToString(joinedEvalDigest) != hex.EncodeToString(evalDigest) ||
			joinedPolicy.String != policyVersion.String {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		rec.ModelProvenance = &contracts.PredictionModelProvenanceV1{
			Version:          modelVersion.String,
			SHA256:           hex.EncodeToString(modelDigest),
			PolicyVersion:    policyVersion.String,
			PolicySHA256:     hex.EncodeToString(policyDigest),
			EvaluationSHA256: hex.EncodeToString(evalDigest),
		}
	}

	if evSeq.Valid {
		if !evCollected.Valid || !evReceived.Valid || len(evPayloadDigest) != 32 || len(evReqDigest) != 32 ||
			!evSource.Valid || !evSchema.Valid || len(joinedPayload) == 0 || len(joinedReqDigest) != 32 ||
			!joinedCollected.Valid || !joinedReceived.Valid {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		sum := sha256.Sum256(joinedPayload)
		payloadSHA := hex.EncodeToString(sum[:])
		reqSHA := hex.EncodeToString(joinedReqDigest)
		if payloadSHA != hex.EncodeToString(evPayloadDigest) ||
			reqSHA != hex.EncodeToString(evReqDigest) ||
			!joinedCollected.Time.UTC().Equal(evCollected.Time.UTC()) ||
			!joinedReceived.Time.UTC().Equal(evReceived.Time.UTC()) {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		var telemetry contracts.TelemetryV2
		if err := json.Unmarshal(joinedPayload, &telemetry); err != nil ||
			telemetry.DeviceID != deviceID ||
			telemetry.SchemaVersion != evSchema.String ||
			telemetry.Source != evSource.String {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		rec.Evidence = &contracts.PredictionEvidenceRefV1{
			Sequence:               uint64(evSeq.Int64),
			CollectedAt:            evCollected.Time.UTC(),
			ReceivedAt:             evReceived.Time.UTC(),
			PayloadSHA256:          payloadSHA,
			RequestSHA256:          reqSHA,
			Source:                 evSource.String,
			TelemetrySchemaVersion: evSchema.String,
		}
	}

	if len(predictionRaw) > 0 {
		var p contracts.PredictionV2
		if err := json.Unmarshal(predictionRaw, &p); err != nil {
			return contracts.PredictionHistoryRecordV1{}, ErrPredictionEvidenceBroken
		}
		rec.Prediction = &p
	}

	if err := rec.Validate(deviceID); err != nil {
		return contracts.PredictionHistoryRecordV1{}, fmt.Errorf("%w: %v", ErrPredictionEvidenceBroken, err)
	}
	rec.Stale = rec.Health.UnknownReason == health.UnknownReasonStaleEvidence || (rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt))
	return rec, nil
}

// PredictionHistory returns up to limit persisted prediction/health records of
// one enrolled device with from <= as_of < to, after the cursor.
func (s *PostgresRepository) PredictionHistory(ctx context.Context, deviceID string, from, to time.Time, after *predictionHistoryCursor, limit int) (contracts.PredictionHistoryV1, error) {
	from, to = from.UTC().Truncate(time.Microsecond), to.UTC().Truncate(time.Microsecond)
	if !repositoryIDPattern.MatchString(deviceID) || limit < 1 || limit > contracts.PredictionHistoryPageMaxV1 ||
		!from.Before(to) || to.Sub(from) > contracts.PredictionHistoryWindowMaxV1 {
		return contracts.PredictionHistoryV1{}, ErrDeviceStateInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return contracts.PredictionHistoryV1{}, repositoryUnavailable(err)
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, deviceID).Scan(&exists); err != nil {
		return contracts.PredictionHistoryV1{}, repositoryReadError(err)
	}
	cursor := predictionHistoryCursor{asOf: from}
	if after != nil {
		if after.asOf.Before(from) || !after.asOf.Before(to) {
			return contracts.PredictionHistoryV1{}, ErrDeviceStateInvalid
		}
		cursor = *after
	}
	rows, err := tx.QueryContext(ctx, predictionHistorySelect+`
		WHERE p.deployment_id=$1 AND p.device_id=$2 AND p.as_of >= $3 AND p.as_of < $4 AND (p.as_of, p.id) > ($5, $6)
		ORDER BY p.as_of, p.id LIMIT $7`,
		s.deploymentID, deviceID, from, to, cursor.asOf, int64(cursor.id), limit+1)
	if err != nil {
		return contracts.PredictionHistoryV1{}, repositoryUnavailable(err)
	}
	defer rows.Close()

	now := s.now().UTC()
	page := contracts.PredictionHistoryV1{
		SchemaVersion: contracts.PredictionHistoryV1Version,
		DeploymentID:  s.deploymentID,
		DeviceID:      deviceID,
		From:          from,
		To:            to,
		Records:       []contracts.PredictionHistoryRecordV1{},
	}
	for rows.Next() {
		rec, err := s.scanPredictionRecord(rows, deviceID, now)
		if err != nil {
			return contracts.PredictionHistoryV1{}, err
		}
		page.Records = append(page.Records, rec)
	}
	if err := rows.Err(); err != nil {
		return contracts.PredictionHistoryV1{}, repositoryUnavailable(err)
	}
	if len(page.Records) > limit {
		page.Records = page.Records[:limit]
		last := page.Records[limit-1]
		next := predictionHistoryCursor{asOf: last.AsOf, id: last.ID}.String()
		page.NextAfter = &next
	}
	return page, nil
}

// LatestDevicePrediction returns the newest persisted prediction/health record
// for one enrolled device, failing closed to unknown (stale_evidence) without
// a current numeric risk value once the prediction expires.
func (s *PostgresRepository) LatestDevicePrediction(ctx context.Context, deviceID string) (contracts.LatestPredictionV1, error) {
	if !repositoryIDPattern.MatchString(deviceID) {
		return contracts.LatestPredictionV1{}, ErrDeviceStateInvalid
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return contracts.LatestPredictionV1{}, repositoryUnavailable(err)
	}
	defer tx.Rollback()

	var exists bool
	if err := tx.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, deviceID).Scan(&exists); err != nil {
		return contracts.LatestPredictionV1{}, repositoryReadError(err)
	}
	now := s.now().UTC()
	rec, err := s.scanPredictionRecord(tx.QueryRowContext(ctx, predictionHistorySelect+`
		WHERE p.deployment_id=$1 AND p.device_id=$2
		ORDER BY p.as_of DESC, p.id DESC LIMIT 1`, s.deploymentID, deviceID), deviceID, now)
	if err != nil {
		return contracts.LatestPredictionV1{}, err
	}
	current := rec.Health
	if rec.Stale && current.Status != health.HealthStatusUnknown {
		current = contracts.HealthV2{
			Status:          health.HealthStatusUnknown,
			ProbabilityUnit: "probability",
			UnknownReason:   health.UnknownReasonStaleEvidence,
		}
	}
	return contracts.LatestPredictionV1{
		SchemaVersion: contracts.PredictionLatestV1Version,
		DeploymentID:  s.deploymentID,
		DeviceID:      deviceID,
		EvaluatedAt:   now,
		Stale:         rec.Stale,
		CurrentHealth: current,
		Record:        rec,
	}, nil
}

func (s *DeviceStateService) predictions(w http.ResponseWriter, r *http.Request) {
	query, err := s.parseQuery(r, "deployment_id", "from", "to", "limit", "after")
	if err != nil {
		deviceStateError(w, err)
		return
	}
	var window [2]time.Time
	for i, key := range []string{"from", "to"} {
		values, ok := query[key]
		if !ok {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
		if window[i], err = time.Parse(time.RFC3339Nano, values[0]); err != nil {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
	}
	limit := contracts.PredictionHistoryPageDefaultV1
	if values, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > contracts.PredictionHistoryPageMaxV1 || values[0] != strconv.Itoa(limit) {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
	}
	var after *predictionHistoryCursor
	if values, ok := query["after"]; ok {
		cursor, err := parsePredictionHistoryCursor(values[0])
		if err != nil {
			deviceStateError(w, err)
			return
		}
		after = &cursor
	}
	page, err := s.repository.PredictionHistory(r.Context(), r.PathValue("id"), window[0], window[1], after, limit)
	if err != nil {
		deviceStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *DeviceStateService) latestPrediction(w http.ResponseWriter, r *http.Request) {
	if _, err := s.parseQuery(r, "deployment_id"); err != nil {
		deviceStateError(w, err)
		return
	}
	latest, err := s.repository.LatestDevicePrediction(r.Context(), r.PathValue("id"))
	if err != nil {
		deviceStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, latest)
}

func decodeSHA256Hex(value string) ([]byte, error) {
	if len(value) != 64 {
		return nil, ErrPredictionInvalid
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != value {
		return nil, ErrPredictionInvalid
	}
	return decoded, nil
}
