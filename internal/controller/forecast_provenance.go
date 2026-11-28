package controller

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// ForecastSourceForModel says whether one model version may back forecasts.
// Eligibility is read from stored records only: a passing held-out evaluation
// that the approval cites, an approval, and no rejecting promotion decision.
// A federated aggregate is never eligible just because it was built.
func (s *PostgresRepository) ForecastSourceForModel(ctx context.Context, version string) (contracts.ForecastSourceV1, error) {
	return s.forecastSource(ctx, s.db, version, "")
}

// ForecastSourceForRound answers the same question for a federated round's
// candidate. A failed or not yet aggregated round is unavailable with a stable
// reason and no model.
func (s *PostgresRepository) ForecastSourceForRound(ctx context.Context, roundID string) (contracts.ForecastSourceV1, error) {
	record, err := s.Aggregation(ctx, roundID)
	switch {
	case errors.Is(err, federated.ErrRoundNotFound):
		return contracts.ForecastSourceV1{}, ErrRepositoryNotFound
	case errors.Is(err, ErrRepositoryNotFound):
		// The round exists; nothing has been aggregated from it.
		return s.unavailableSource(roundID, "", contracts.ForecastReasonRoundNotAggregated, ""), nil
	case err != nil:
		return contracts.ForecastSourceV1{}, err
	case record.Status != federated.AggregationSucceeded:
		return s.unavailableSource(roundID, "", contracts.ForecastReasonRoundFailed, record.FailureReason), nil
	}
	return s.forecastSource(ctx, s.db, record.CandidateModelVersion, roundID)
}

func (s *PostgresRepository) unavailableSource(roundID, version string, reason contracts.ForecastReasonV1, failure string) contracts.ForecastSourceV1 {
	return contracts.ForecastSourceV1{SchemaVersion: contracts.ForecastSourceV1Version, DeploymentID: s.deploymentID,
		RoundID: roundID, ModelVersion: version, Status: contracts.ForecastUnavailable, Reason: reason, FailureReason: failure}
}

func (s *PostgresRepository) forecastSource(ctx context.Context, q dbQueryer, version, roundID string) (contracts.ForecastSourceV1, error) {
	artifact, err := s.modelArtifact(ctx, q, version)
	if err != nil {
		return contracts.ForecastSourceV1{}, err
	}
	source := s.unavailableSource(roundID, version, contracts.ForecastReasonCandidateUnevaluated, "")
	model := &contracts.ForecastModelV1{Version: version, ArtifactSHA256: artifact.Manifest.ArtifactSHA256, FeatureVersion: artifact.Manifest.FeatureVersion}

	var evalDigest []byte
	var evalPolicy, verdict string
	err = q.QueryRowContext(ctx, `SELECT evaluation_sha256, policy_version, verdict FROM model_evaluations
		WHERE deployment_id=$1 AND model_version=$2 AND artifact_sha256=decode($3,'hex')`,
		s.deploymentID, version, artifact.Manifest.ArtifactSHA256).Scan(&evalDigest, &evalPolicy, &verdict)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return source, nil
	case err != nil:
		return contracts.ForecastSourceV1{}, repositoryUnavailable(err)
	}
	model.EvaluationSHA256, model.EvaluationPolicy, model.EvaluationVerdict = hex.EncodeToString(evalDigest), evalPolicy, verdict

	var promotionPolicy, outcome string
	var decidedAt time.Time
	rejected := false
	err = q.QueryRowContext(ctx, `SELECT promotion_policy_version, outcome, decided_at FROM model_promotions
		WHERE deployment_id=$1 AND model_version=$2 AND artifact_sha256=decode($3,'hex') AND evaluation_sha256=$4`,
		s.deploymentID, version, artifact.Manifest.ArtifactSHA256, evalDigest).Scan(&promotionPolicy, &outcome, &decidedAt)
	switch {
	case err == nil:
		model.PromotionPolicyVersion = promotionPolicy
		rejected = outcome == string(contracts.ModelPromotionRejected)
		if !rejected {
			at := decidedAt.UTC()
			model.PromotedAt = &at
		}
	case !errors.Is(err, sql.ErrNoRows):
		return contracts.ForecastSourceV1{}, repositoryUnavailable(err)
	}
	approved := artifact.Approval != nil && artifact.Approval.EvaluationSHA256 == model.EvaluationSHA256
	if approved && model.PromotedAt == nil && !rejected {
		// An approval with no promotion row is the pre-FED10 path. It still
		// needs the stored passing evaluation checked here.
		at := artifact.Approval.ApprovedAt
		model.PromotedAt, model.PromotionPolicyVersion = &at, artifact.Approval.PolicyVersion
	}
	source.Model = model
	switch {
	case rejected:
		source.Reason = contracts.ForecastReasonCandidateRejected
	case verdict != "pass":
		source.Reason = contracts.ForecastReasonEvaluationNotPassing
	case !approved || model.PromotedAt == nil:
		source.Reason = contracts.ForecastReasonNotPromoted
	default:
		source.Status, source.Reason = contracts.ForecastAvailable, contracts.ForecastReasonNone
	}
	if source.Status != contracts.ForecastAvailable {
		return source, nil
	}
	refs, err := s.modelReferences(ctx, q)
	if err != nil {
		return contracts.ForecastSourceV1{}, err
	}
	model.Active = refs.Active != nil && refs.Active.ModelVersion == version && refs.Active.ArtifactSHA256 == model.ArtifactSHA256
	if model.Origin, err = s.forecastOrigin(ctx, q, version); err != nil {
		return contracts.ForecastSourceV1{}, err
	}
	if model.Origin != nil {
		source.RoundID = model.Origin.RoundID
	}
	return source, nil
}

func (s *PostgresRepository) forecastOrigin(ctx context.Context, q dbQueryer, version string) (*contracts.ForecastOriginV1, error) {
	origin := contracts.ForecastOriginV1{}
	var inputDigest, weightsDigest []byte
	var participants int
	var samples int64
	err := q.QueryRowContext(ctx, `SELECT round_id, candidate_id, weighting_policy, participant_count, total_samples, input_sha256, weights_sha256
		FROM federated_aggregations WHERE deployment_id=$1 AND candidate_model_version=$2 AND status='succeeded'`,
		s.deploymentID, version).Scan(&origin.RoundID, &origin.CandidateID, &origin.WeightingPolicy, &participants, &samples, &inputDigest, &weightsDigest)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, repositoryUnavailable(err)
	}
	origin.ParticipantCount, origin.TotalSamples = participants, uint64(samples)
	origin.InputSHA256, origin.WeightsSHA256 = hex.EncodeToString(inputDigest), hex.EncodeToString(weightsDigest)
	return &origin, nil
}

// DeviceForecast returns the newest persisted forecast of one device with its
// provenance and freshness, judged at the controller clock. Forecasts are
// returned only when the prediction is fresh and its model is an evaluated,
// promoted, still active model. Every other case is stale or unavailable with
// a stable reason and no forecasts, including after a restart: nothing is
// cached, and an aggregate that was not evaluated is never an approved source.
func (s *PostgresRepository) DeviceForecast(ctx context.Context, deviceID string) (contracts.DeviceForecastV1, error) {
	if !repositoryIDPattern.MatchString(deviceID) {
		return contracts.DeviceForecastV1{}, ErrDeviceStateInvalid
	}
	now := s.now().UTC()
	out := contracts.DeviceForecastV1{SchemaVersion: contracts.ForecastProvenanceV1Version, DeploymentID: s.deploymentID, DeviceID: deviceID,
		EvaluatedAt: now, Status: contracts.ForecastUnavailable, Forecasts: []contracts.FaultForecastV2{}}
	latest, err := s.LatestDevicePrediction(ctx, deviceID)
	if errors.Is(err, ErrRepositoryNotFound) {
		var enrolled bool
		if err := s.db.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`,
			s.deploymentID, deviceID).Scan(&enrolled); err != nil {
			return contracts.DeviceForecastV1{}, repositoryReadError(err)
		}
		out.Reason = contracts.ForecastReasonNoPrediction
		return out, nil
	}
	if err != nil {
		return contracts.DeviceForecastV1{}, err
	}
	rec := latest.Record
	asOf := rec.AsOf
	out.AsOf, out.ExpiresAt, out.Evidence = &asOf, rec.ExpiresAt, rec.Evidence
	out.Health = &contracts.HealthV2{Status: latest.CurrentHealth.Status, ProbabilityUnit: latest.CurrentHealth.ProbabilityUnit,
		UnknownReason: latest.CurrentHealth.UnknownReason}
	out.Window = &contracts.ForecastWindowV1{FeatureVersion: rec.Features.FeatureVersion, Start: rec.Features.WindowStart,
		End: rec.Features.WindowEnd, Status: rec.Features.Status, SamplesRead: rec.Features.SamplesRead}

	if rec.Health.Status == health.HealthStatusUnknown {
		switch rec.Health.UnknownReason {
		case health.UnknownReasonStaleEvidence:
			out.Status, out.Reason = contracts.ForecastStale, contracts.ForecastReasonStaleEvidence
		case health.UnknownReasonModelUnavailable:
			out.Reason = contracts.ForecastReasonModelUnavailable
		default:
			out.Reason = contracts.ForecastReasonInsufficientEvidence
		}
		return out, nil
	}
	// A known assessment: the model must be a verified, evaluated one.
	if rec.ModelProvenance == nil || rec.Prediction == nil {
		out.Reason = contracts.ForecastReasonModelUnavailable
		return out, nil
	}
	horizon := rec.Health.HorizonHours
	out.HorizonHours = horizon
	source, err := s.ForecastSourceForModel(ctx, rec.ModelProvenance.Version)
	if err != nil {
		return contracts.DeviceForecastV1{}, err
	}
	out.Model = source.Model
	if source.Model != nil && source.Model.ArtifactSHA256 != rec.ModelProvenance.SHA256 ||
		source.Model != nil && source.Model.EvaluationSHA256 != rec.ModelProvenance.EvaluationSHA256 {
		return contracts.DeviceForecastV1{}, ErrPredictionEvidenceBroken
	}
	switch {
	case source.Status != contracts.ForecastAvailable:
		out.Reason = source.Reason
	case latest.Stale:
		out.Status, out.Reason = contracts.ForecastStale, contracts.ForecastReasonPredictionExpired
	case !source.Model.Active:
		out.Status, out.Reason = contracts.ForecastStale, contracts.ForecastReasonModelSuperseded
	default:
		out.Status, out.Reason = contracts.ForecastAvailable, contracts.ForecastReasonNone
		out.Health = &rec.Health
		out.Forecasts = append(out.Forecasts, rec.Prediction.Forecasts...)
	}
	return out, nil
}

func (s *DeviceStateService) forecast(w http.ResponseWriter, r *http.Request) {
	if _, err := s.parseQuery(r, "deployment_id"); err != nil {
		deviceStateError(w, err)
		return
	}
	forecast, err := s.repository.DeviceForecast(r.Context(), r.PathValue("id"))
	if err != nil {
		deviceStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, forecast)
}

func (s *ModelRegistryService) forecastSource(w http.ResponseWriter, r *http.Request) {
	source, err := s.repository.ForecastSourceForModel(r.Context(), r.PathValue("version"))
	writeModelResult(w, source, false, err)
}
