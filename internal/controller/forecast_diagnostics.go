package controller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

const forecastTraceDefault = 50

func (s *PostgresRepository) forecastMinProbability() float64 {
	if s.forecastDiagnosticMinProbability > 0 {
		return s.forecastDiagnosticMinProbability
	}
	return workflows.ForecastDiagnosticMinProbability
}

// forecastAssignmentID names the job one forecast launches for one category. It
// is derived from the forecast, so repeated delivery of the same forecast
// names the same job and an identical retry returns the stored assignment.
func (s *PostgresRepository) forecastAssignmentID(deviceID string, asOf time.Time, category string) string {
	sum := sha256.Sum256([]byte(s.deploymentID + "\x00" + deviceID + "\x00" + asOf.UTC().Format(time.RFC3339Nano) + "\x00" + category))
	return "forecast-" + hex.EncodeToString(sum[:20])
}

// TriggerForecastDiagnostics launches bounded, read-only diagnostics from one
// device's newest forecast. Work starts only when the forecast is available:
// fresh, from a promoted and evaluated model that is still active (FED13). A
// stale, expired, superseded or unavailable forecast launches nothing and
// reports the stable reason. Each forecast launches at most one job per
// category, and a category whose probe still has an unfinished
// forecast-triggered job is skipped, so repeated delivery keeps one job.
func (s *PostgresRepository) TriggerForecastDiagnostics(ctx context.Context, deviceID string, signer ed25519.PrivateKey, by workflows.Actor) (contracts.ForecastDiagnosticsV1, error) {
	forecast, err := s.DeviceForecast(ctx, deviceID)
	if err != nil {
		return contracts.ForecastDiagnosticsV1{}, err
	}
	out := contracts.ForecastDiagnosticsV1{SchemaVersion: contracts.ForecastDiagnosticsV1Version, DeploymentID: s.deploymentID,
		DeviceID: deviceID, EvaluatedAt: forecast.EvaluatedAt, PolicyVersion: workflows.ForecastDiagnosticPolicyVersion,
		ForecastStatus: forecast.Status, ForecastReason: forecast.Reason, AsOf: forecast.AsOf, Decisions: []contracts.ForecastDiagnosticDecisionV1{}}
	if forecast.Status != contracts.ForecastAvailable || forecast.AsOf == nil || forecast.Model == nil {
		return out, nil
	}
	if err := s.expireDeviceAssignmentsIfAny(ctx, deviceID); err != nil {
		return contracts.ForecastDiagnosticsV1{}, err
	}
	asOf := forecast.AsOf.UTC().Truncate(time.Microsecond)
	for _, plan := range workflows.PlanForecastDiagnostics(forecast.Health, forecast.Model.FeatureVersion, forecast.Forecasts, s.forecastMinProbability()) {
		decision := contracts.ForecastDiagnosticDecisionV1{Category: plan.Category, Probability: plan.Probability,
			HorizonHours: plan.HorizonHours, ProbeID: plan.ProbeID}

		var launched string
		err := s.db.QueryRowContext(ctx, `SELECT assignment_id FROM forecast_diagnostic_triggers
			WHERE deployment_id=$1 AND device_id=$2 AND as_of=$3 AND category=$4`, s.deploymentID, deviceID, asOf, plan.Category).Scan(&launched)
		switch {
		case err == nil:
			decision.Outcome, decision.AssignmentID = contracts.ForecastDiagnosticDeduplicated, launched
			if decision.AssignmentStatus, err = s.assignmentStatus(ctx, launched); err != nil {
				return contracts.ForecastDiagnosticsV1{}, err
			}
			out.Decisions = append(out.Decisions, decision)
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return contracts.ForecastDiagnosticsV1{}, repositoryUnavailable(err)
		}

		var inFlight, inFlightStatus string
		err = s.db.QueryRowContext(ctx, `SELECT a.assignment_id, a.status FROM forecast_diagnostic_triggers t
			JOIN diagnostic_assignments a ON a.deployment_id=t.deployment_id AND a.assignment_id=t.assignment_id
			WHERE t.deployment_id=$1 AND t.device_id=$2 AND t.probe_id=$3 AND a.status IN ('pending','leased','cancel_requested')
			ORDER BY t.as_of DESC LIMIT 1`, s.deploymentID, deviceID, plan.ProbeID).Scan(&inFlight, &inFlightStatus)
		switch {
		case err == nil:
			decision.Outcome, decision.Reason = contracts.ForecastDiagnosticSkipped, contracts.ForecastDiagnosticReasonJobInFlight
			decision.AssignmentID, decision.AssignmentStatus = inFlight, inFlightStatus
			out.Decisions = append(out.Decisions, decision)
			continue
		case !errors.Is(err, sql.ErrNoRows):
			return contracts.ForecastDiagnosticsV1{}, repositoryUnavailable(err)
		}

		assignmentID := s.forecastAssignmentID(deviceID, asOf, plan.Category)
		rec, created, err := s.CreateDiagnosticAssignment(ctx, workflows.AssignmentRequest{AssignmentID: assignmentID, DeviceID: deviceID,
			ProbeID: plan.ProbeID, Arguments: plan.Arguments, Budget: plan.Budget, ExpiresInSeconds: plan.ExpiresInSeconds}, signer, by)
		if err != nil {
			return contracts.ForecastDiagnosticsV1{}, err
		}
		if err := s.insertForecastTrigger(ctx, forecast, asOf, plan, assignmentID, by); err != nil {
			return contracts.ForecastDiagnosticsV1{}, err
		}
		decision.AssignmentID, decision.AssignmentStatus = assignmentID, string(rec.Status)
		decision.Outcome = contracts.ForecastDiagnosticLaunched
		if !created {
			// An earlier attempt queued the job but stopped before linking it.
			decision.Outcome = contracts.ForecastDiagnosticDeduplicated
		}
		out.Decisions = append(out.Decisions, decision)
	}
	return out, nil
}

func (s *PostgresRepository) assignmentStatus(ctx context.Context, assignmentID string) (string, error) {
	rec, err := s.DiagnosticAssignment(ctx, assignmentID)
	if err != nil {
		return "", err
	}
	return string(rec.Status), nil
}

func (s *PostgresRepository) insertForecastTrigger(ctx context.Context, forecast contracts.DeviceForecastV1, asOf time.Time, plan workflows.ForecastDiagnosticPlan, assignmentID string, by workflows.Actor) error {
	m := forecast.Model
	var sequence any
	if forecast.Evidence != nil {
		sequence = int64(forecast.Evidence.Sequence)
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO forecast_diagnostic_triggers (
			deployment_id, device_id, as_of, category, assignment_id, probe_id, policy_version, probability, horizon_hours,
			model_version, artifact_sha256, evaluation_sha256, evidence_sequence, created_at, actor_issuer, actor_subject
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,decode($11,'hex'),decode($12,'hex'),$13,$14,$15,$16)
		ON CONFLICT (deployment_id, device_id, as_of, category) DO NOTHING`,
		s.deploymentID, forecast.DeviceID, asOf, plan.Category, assignmentID, plan.ProbeID, workflows.ForecastDiagnosticPolicyVersion,
		plan.Probability, int64(plan.HorizonHours), m.Version, m.ArtifactSHA256, m.EvaluationSHA256, sequence,
		s.now().UTC().Truncate(time.Microsecond), by.Issuer, by.Subject); err != nil {
		return repositoryUnavailable(err)
	}
	return repositoryCommit(tx)
}

// ForecastDiagnosticTrace lists the jobs a device's forecasts launched, newest
// forecast first, with each job's status and, once it finished, the evidence
// references of its device-signed result.
func (s *PostgresRepository) ForecastDiagnosticTrace(ctx context.Context, deviceID string, limit int) (contracts.ForecastDiagnosticTraceV1, error) {
	if !repositoryIDPattern.MatchString(deviceID) {
		return contracts.ForecastDiagnosticTraceV1{}, ErrDeviceStateInvalid
	}
	var enrolled bool
	if err := s.db.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, deviceID).Scan(&enrolled); err != nil {
		return contracts.ForecastDiagnosticTraceV1{}, repositoryReadError(err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT as_of, category, assignment_id, probe_id, policy_version, probability, horizon_hours,
			model_version, artifact_sha256, evaluation_sha256, evidence_sequence, created_at, actor_issuer, actor_subject
		FROM forecast_diagnostic_triggers WHERE deployment_id=$1 AND device_id=$2
		ORDER BY as_of DESC, category ASC LIMIT $3`, s.deploymentID, deviceID, limit)
	if err != nil {
		return contracts.ForecastDiagnosticTraceV1{}, repositoryUnavailable(err)
	}
	defer rows.Close()
	out := contracts.ForecastDiagnosticTraceV1{SchemaVersion: contracts.ForecastDiagnosticTraceV1Version, DeploymentID: s.deploymentID,
		DeviceID: deviceID, Links: []contracts.ForecastDiagnosticLinkV1{}}
	for rows.Next() {
		var link contracts.ForecastDiagnosticLinkV1
		var artifact, evaluation []byte
		var horizon int64
		var sequence sql.NullInt64
		if err := rows.Scan(&link.AsOf, &link.Category, &link.AssignmentID, &link.ProbeID, &link.PolicyVersion, &link.Probability, &horizon,
			&link.ModelVersion, &artifact, &evaluation, &sequence, &link.TriggeredAt, &link.TriggeredBy.Issuer, &link.TriggeredBy.Subject); err != nil {
			return contracts.ForecastDiagnosticTraceV1{}, repositoryUnavailable(err)
		}
		link.AsOf, link.TriggeredAt, link.HorizonHours = link.AsOf.UTC(), link.TriggeredAt.UTC(), uint32(horizon)
		link.ArtifactSHA256, link.EvaluationSHA256 = hex.EncodeToString(artifact), hex.EncodeToString(evaluation)
		if sequence.Valid {
			seq := uint64(sequence.Int64)
			link.EvidenceSequence = &seq
		}
		link.Evidence = []contracts.DiagnosticEvidenceV1{}
		out.Links = append(out.Links, link)
	}
	if err := rows.Err(); err != nil {
		return contracts.ForecastDiagnosticTraceV1{}, repositoryUnavailable(err)
	}
	rows.Close()
	for i := range out.Links {
		rec, err := s.DiagnosticAssignment(ctx, out.Links[i].AssignmentID)
		if err != nil {
			return contracts.ForecastDiagnosticTraceV1{}, err
		}
		out.Links[i].AssignmentStatus = string(rec.Status)
		if rec.Result != nil {
			state, reason := rec.Result.State, rec.Result.Reason
			out.Links[i].ResultState, out.Links[i].ResultReason = &state, reason
			out.Links[i].Evidence = append(out.Links[i].Evidence, rec.Result.Evidence...)
		}
	}
	return out, nil
}

func (s *DiagnosticService) triggerForecast(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "unexpected query parameters", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	if body, err := io.ReadAll(r.Body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	} else if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && string(trimmed) != "{}" {
		http.Error(w, "forecast diagnostics accepts only an empty body or {}", http.StatusBadRequest)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	result, err := s.forecasts.TriggerForecastDiagnostics(r.Context(), r.PathValue("id"), s.signer, workflows.Actor(actor))
	if err != nil {
		writeDiagnosticResult(w, nil, false, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, result)
}

func (s *DiagnosticService) forecastTrace(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, vals := range q {
		if (k != "deployment_id" && k != "limit") || len(vals) != 1 {
			http.Error(w, "invalid query parameters", http.StatusBadRequest)
			return
		}
	}
	dep := q.Get("deployment_id")
	if !repositoryIDPattern.MatchString(dep) {
		http.Error(w, "valid deployment_id is required", http.StatusBadRequest)
		return
	}
	if dep != s.deployment {
		http.Error(w, "forbidden deployment scope", http.StatusForbidden)
		return
	}
	limit := forecastTraceDefault
	if raw := q.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(parsed) != raw || parsed < 1 || parsed > diagnosticPageMax {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	trace, err := s.forecasts.ForecastDiagnosticTrace(r.Context(), r.PathValue("id"), limit)
	writeDiagnosticResult(w, trace, false, err)
}
