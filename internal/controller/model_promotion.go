package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/federated"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// FED10 #115. A candidate model becomes active only through PromoteModel,
// which reads a stored held-out evaluation, applies the frozen ML05 and FED10
// gates against the active model, and records one immutable decision. Every
// other outcome leaves the active slot exactly as it was.

// lockModelPromotions serializes everything that can change the active slot
// for this deployment until the transaction ends.
func (s *PostgresRepository) lockModelPromotions(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('model-promotion:' || $1, 0))`, s.deploymentID); err != nil {
		return repositoryUnavailable(err)
	}
	return nil
}

// PutModelEvaluation stores the one held-out evaluation a candidate gets. The
// controller reads the report itself; it never trusts the verdict inside it.
// created is false for a repeat of the stored report. A different report for
// the same version is a version_conflict, because the held-out partition is
// scored once per candidate. A report naming another model is refused and
// stores nothing.
func (s *PostgresRepository) PutModelEvaluation(ctx context.Context, submission contracts.ModelEvaluationSubmissionV1, publisherKey ed25519.PublicKey, actor contracts.ModelActorV1) (contracts.ModelEvaluationV1, bool, error) {
	if err := submission.Verify(publisherKey); err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	if err := actor.Validate(); err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	record, err := s.ModelArtifact(ctx, submission.ModelVersion)
	if err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	if record.Manifest.ArtifactSHA256 != submission.ArtifactSHA256 || record.Manifest.SigningKeyID != submission.SigningKeyID {
		return contracts.ModelEvaluationV1{}, false, contracts.ModelRejectionReferenceMismatch
	}
	assessment := health.AssessEvaluationReport(submission.Report, record.Manifest)
	if assessment.ModelVersion != submission.ModelVersion || assessment.ModelSHA256 != submission.ArtifactSHA256 {
		return contracts.ModelEvaluationV1{}, false, contracts.ModelRejectionReferenceMismatch
	}
	reasons, err := json.Marshal(nonNilStrings(assessment.Reasons))
	if err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	artifactDigest, _ := hex.DecodeString(submission.ArtifactSHA256)
	reportDigest, _ := hex.DecodeString(assessment.EvaluationSHA256)
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO model_evaluations (deployment_id, model_version, artifact_sha256, evaluation_sha256,
		report, policy_version, verdict, reasons, submitted_at, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT DO NOTHING`, s.deploymentID, submission.ModelVersion, artifactDigest, reportDigest, submission.Report,
		health.ML05PolicyVersion, string(assessment.Verdict), reasons, s.now().UTC().Truncate(time.Microsecond), actor.Issuer, actor.Subject)
	if err != nil {
		return contracts.ModelEvaluationV1{}, false, repositoryUnavailable(err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return contracts.ModelEvaluationV1{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	stored, err := s.ModelEvaluation(ctx, submission.ModelVersion)
	if err != nil {
		return contracts.ModelEvaluationV1{}, false, err
	}
	if inserted == 0 && stored.EvaluationSHA256 != assessment.EvaluationSHA256 {
		return contracts.ModelEvaluationV1{}, false, contracts.ModelRejectionVersionConflict
	}
	return stored, inserted == 1, nil
}

// ModelEvaluation returns the stored evaluation of one version.
func (s *PostgresRepository) ModelEvaluation(ctx context.Context, version string) (contracts.ModelEvaluationV1, error) {
	return s.modelEvaluation(ctx, s.db, version)
}

func (s *PostgresRepository) modelEvaluation(ctx context.Context, q dbQueryer, version string) (contracts.ModelEvaluationV1, error) {
	if !repositoryIDPattern.MatchString(version) {
		return contracts.ModelEvaluationV1{}, ErrRepositoryNotFound
	}
	record := contracts.ModelEvaluationV1{SchemaVersion: contracts.ModelEvaluationV1Version, DeploymentID: s.deploymentID, ModelVersion: version}
	var artifactDigest, reportDigest, report, reasons []byte
	var verdict string
	err := q.QueryRowContext(ctx, `SELECT artifact_sha256, evaluation_sha256, report, policy_version, verdict, reasons, submitted_at, actor_issuer, actor_subject
		FROM model_evaluations WHERE deployment_id=$1 AND model_version=$2`, s.deploymentID, version).
		Scan(&artifactDigest, &reportDigest, &report, &record.PolicyVersion, &verdict, &reasons, &record.SubmittedAt, &record.SubmittedBy.Issuer, &record.SubmittedBy.Subject)
	if err != nil {
		return contracts.ModelEvaluationV1{}, repositoryReadError(err)
	}
	record.ArtifactSHA256, record.EvaluationSHA256 = hex.EncodeToString(artifactDigest), hex.EncodeToString(reportDigest)
	record.Verdict, record.SubmittedAt = contracts.ModelEvaluationVerdictV1(verdict), record.SubmittedAt.UTC()
	if err := json.Unmarshal(reasons, &record.Reasons); err != nil {
		return contracts.ModelEvaluationV1{}, repositoryUnavailable(fmt.Errorf("stored evaluation reasons %s: %w", version, err))
	}
	if sum := sha256.Sum256(report); hex.EncodeToString(sum[:]) != record.EvaluationSHA256 {
		return contracts.ModelEvaluationV1{}, ErrModelArtifactCorrupt
	}
	manifest, err := s.storedManifest(ctx, q, version)
	if err != nil {
		return contracts.ModelEvaluationV1{}, err
	}
	// Metrics are read from the stored report. They are null when the report
	// was too incomplete to read, never zero.
	if assessment := health.AssessEvaluationReport(report, manifest); assessment.Metrics != nil {
		record.Metrics = make(map[string]contracts.ModelMetricV1, len(assessment.Metrics))
		for name, interval := range assessment.Metrics {
			record.Metrics[name] = contracts.ModelMetricV1(interval)
		}
	}
	return record, nil
}

func (s *PostgresRepository) storedManifest(ctx context.Context, q dbQueryer, version string) (contracts.ModelManifestV1, error) {
	var manifestJSON []byte
	if err := q.QueryRowContext(ctx, `SELECT manifest FROM model_artifacts WHERE deployment_id=$1 AND model_version=$2`,
		s.deploymentID, version).Scan(&manifestJSON); err != nil {
		return contracts.ModelManifestV1{}, repositoryReadError(err)
	}
	var manifest contracts.ModelManifestV1
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return contracts.ModelManifestV1{}, repositoryUnavailable(fmt.Errorf("stored manifest %s: %w", version, err))
	}
	return manifest, nil
}

// EvaluationReport returns the stored report bytes for one digest, so the
// controller's health path can reload exactly what a promotion judged. It
// satisfies EvaluationReportStore.
func (s *PostgresRepository) EvaluationReport(ctx context.Context, evaluationSHA256 string) ([]byte, error) {
	digest, err := hex.DecodeString(evaluationSHA256)
	if err != nil || len(digest) != sha256.Size {
		return nil, ErrRepositoryNotFound
	}
	var report []byte
	if err := s.db.QueryRowContext(ctx, `SELECT report FROM model_evaluations WHERE deployment_id=$1 AND evaluation_sha256=$2`,
		s.deploymentID, digest).Scan(&report); err != nil {
		return nil, repositoryReadError(err)
	}
	if sum := sha256.Sum256(report); hex.EncodeToString(sum[:]) != evaluationSHA256 {
		return nil, ErrModelArtifactCorrupt
	}
	return report, nil
}

// PromoteModel decides the candidate once. It applies the ML05 gates to the
// candidate's stored evaluation and the FED10 regression gates against the
// model that is active now, then either activates it with an approval or
// records why not. A rejection, a failed or blocked evaluation and a missing
// baseline all leave the active slot unchanged. created is false when the
// identical decision is already stored; a request that cites other evidence
// after a decision is a version_conflict.
func (s *PostgresRepository) PromoteModel(ctx context.Context, request contracts.ModelPromotionRequestV1, actor contracts.ModelActorV1) (contracts.ModelPromotionV1, bool, error) {
	if err := request.Validate(); err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	if err := actor.Validate(); err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	defer tx.Rollback()
	if err := s.lockModelPromotions(ctx, tx); err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	if stored, err := s.modelPromotion(ctx, tx, request.ModelVersion); err == nil {
		if stored.ArtifactSHA256 == request.ArtifactSHA256 && stored.EvaluationSHA256 == request.EvaluationSHA256 {
			return stored, false, nil
		}
		return contracts.ModelPromotionV1{}, false, contracts.ModelRejectionVersionConflict
	} else if !errors.Is(err, ErrRepositoryNotFound) {
		return contracts.ModelPromotionV1{}, false, err
	}

	candidate, err := s.modelArtifact(ctx, tx, request.ModelVersion)
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	evaluation, err := s.modelEvaluation(ctx, tx, request.ModelVersion)
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	if candidate.Manifest.ArtifactSHA256 != request.ArtifactSHA256 || evaluation.EvaluationSHA256 != request.EvaluationSHA256 {
		return contracts.ModelPromotionV1{}, false, contracts.ModelRejectionReferenceMismatch
	}
	refs, err := s.modelReferences(ctx, tx)
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	if refs.Candidate == nil || refs.Candidate.ModelVersion != request.ModelVersion || refs.Candidate.ArtifactSHA256 != request.ArtifactSHA256 {
		return contracts.ModelPromotionV1{}, false, contracts.ModelRejectionNotCandidate
	}

	report, err := s.evaluationReportBytes(ctx, tx, request.ModelVersion)
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	assessment := health.AssessEvaluationReport(report, candidate.Manifest)
	baseline, activeAssessment, err := s.activeBaseline(ctx, tx, refs.Active)
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	decision := federated.Decide(assessment, activeAssessment)
	if decision.Outcome == contracts.ModelPromotionPromoted && !slices.Contains(candidate.Manifest.Purposes, contracts.ModelPurposeInference) {
		decision = federated.Decision{Outcome: contracts.ModelPromotionRejected, Reasons: []string{"purpose_unsupported"}}
	}

	digest, _ := hex.DecodeString(request.ArtifactSHA256)
	evaluationDigest, _ := hex.DecodeString(request.EvaluationSHA256)
	decidedAt := s.now().UTC().Truncate(time.Microsecond)
	if decision.Outcome == contracts.ModelPromotionPromoted {
		if _, err := tx.ExecContext(ctx, `INSERT INTO model_approvals (deployment_id, model_version, artifact_sha256, evaluation_sha256,
			policy_version, approved_at, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			s.deploymentID, request.ModelVersion, digest, evaluationDigest, health.ML05PolicyVersion, decidedAt, actor.Issuer, actor.Subject); err != nil {
			return contracts.ModelPromotionV1{}, false, repositoryUnavailable(err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO model_references (deployment_id, slot, model_version, artifact_sha256, set_at, actor_issuer, actor_subject)
			VALUES ($1,'active',$2,$3,$4,$5,$6) ON CONFLICT (deployment_id, slot) DO UPDATE SET model_version=EXCLUDED.model_version,
			artifact_sha256=EXCLUDED.artifact_sha256, set_at=EXCLUDED.set_at, actor_issuer=EXCLUDED.actor_issuer, actor_subject=EXCLUDED.actor_subject`,
			s.deploymentID, request.ModelVersion, digest, decidedAt, actor.Issuer, actor.Subject); err != nil {
			return contracts.ModelPromotionV1{}, false, repositoryUnavailable(err)
		}
	}
	// A decided candidate leaves the candidate slot either way.
	if _, err := tx.ExecContext(ctx, `DELETE FROM model_references WHERE deployment_id=$1 AND slot='candidate' AND model_version=$2`,
		s.deploymentID, request.ModelVersion); err != nil {
		return contracts.ModelPromotionV1{}, false, repositoryUnavailable(err)
	}
	reasons, err := json.Marshal(nonNilStrings(decision.Reasons))
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	checks, err := json.Marshal(nonNilChecks(decision.Checks))
	if err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	var baselineVersion sql.NullString
	var baselineDigest, baselineEvaluation []byte
	if baseline != nil {
		baselineVersion = sql.NullString{String: baseline.ModelVersion, Valid: true}
		baselineDigest, _ = hex.DecodeString(baseline.ArtifactSHA256)
		baselineEvaluation, _ = hex.DecodeString(baseline.EvaluationSHA256)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO model_promotions (deployment_id, model_version, artifact_sha256, evaluation_sha256,
		promotion_policy_version, outcome, reasons, baseline_version, baseline_artifact_sha256, baseline_evaluation_sha256, checks,
		decided_at, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		s.deploymentID, request.ModelVersion, digest, evaluationDigest, federated.PromotionPolicyVersion, string(decision.Outcome), reasons,
		baselineVersion, baselineDigest, baselineEvaluation, checks, decidedAt, actor.Issuer, actor.Subject); err != nil {
		return contracts.ModelPromotionV1{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.ModelPromotionV1{}, false, err
	}
	stored, err := s.ModelPromotion(ctx, request.ModelVersion)
	return stored, err == nil, err
}

// activeBaseline reads the evaluation the active model was promoted on. With
// no active model it returns nil and the ML05 gates alone apply. An active
// model without a stored evaluation, such as one approved before FED10, is
// reported as blocked so the candidate cannot be compared with it.
func (s *PostgresRepository) activeBaseline(ctx context.Context, q dbQueryer, active *contracts.ModelReferenceV1) (*contracts.ModelBaselineV1, *health.EvaluationAssessment, error) {
	if active == nil {
		return nil, nil, nil
	}
	record, err := s.modelArtifact(ctx, q, active.ModelVersion)
	if err != nil {
		return nil, nil, err
	}
	baseline := &contracts.ModelBaselineV1{ModelVersion: active.ModelVersion, ArtifactSHA256: active.ArtifactSHA256}
	if record.Approval != nil {
		baseline.EvaluationSHA256 = record.Approval.EvaluationSHA256
	}
	unavailable := &health.EvaluationAssessment{Verdict: health.EvaluationBlocked, Reasons: []string{"active_baseline_unavailable"}}
	report, err := s.evaluationReportBytes(ctx, q, active.ModelVersion)
	if errors.Is(err, ErrRepositoryNotFound) {
		return baseline, unavailable, nil
	}
	if err != nil {
		return nil, nil, err
	}
	assessment := health.AssessEvaluationReport(report, record.Manifest)
	if assessment.EvaluationSHA256 != baseline.EvaluationSHA256 {
		return baseline, unavailable, nil
	}
	return baseline, &assessment, nil
}

func (s *PostgresRepository) evaluationReportBytes(ctx context.Context, q dbQueryer, version string) ([]byte, error) {
	var report, digest []byte
	if err := q.QueryRowContext(ctx, `SELECT report, evaluation_sha256 FROM model_evaluations WHERE deployment_id=$1 AND model_version=$2`,
		s.deploymentID, version).Scan(&report, &digest); err != nil {
		return nil, repositoryReadError(err)
	}
	if sum := sha256.Sum256(report); hex.EncodeToString(sum[:]) != hex.EncodeToString(digest) {
		return nil, ErrModelArtifactCorrupt
	}
	return report, nil
}

// ModelPromotion returns the stored decision for one version.
func (s *PostgresRepository) ModelPromotion(ctx context.Context, version string) (contracts.ModelPromotionV1, error) {
	return s.modelPromotion(ctx, s.db, version)
}

func (s *PostgresRepository) modelPromotion(ctx context.Context, q dbQueryer, version string) (contracts.ModelPromotionV1, error) {
	if !repositoryIDPattern.MatchString(version) {
		return contracts.ModelPromotionV1{}, ErrRepositoryNotFound
	}
	record := contracts.ModelPromotionV1{SchemaVersion: contracts.ModelPromotionV1Version, DeploymentID: s.deploymentID, ModelVersion: version}
	var artifactDigest, evaluationDigest, baselineDigest, baselineEvaluation, reasons, checks []byte
	var outcome string
	var baselineVersion sql.NullString
	err := q.QueryRowContext(ctx, `SELECT artifact_sha256, evaluation_sha256, promotion_policy_version, outcome, reasons,
		baseline_version, baseline_artifact_sha256, baseline_evaluation_sha256, checks, decided_at, actor_issuer, actor_subject
		FROM model_promotions WHERE deployment_id=$1 AND model_version=$2`, s.deploymentID, version).
		Scan(&artifactDigest, &evaluationDigest, &record.PromotionPolicyVersion, &outcome, &reasons, &baselineVersion, &baselineDigest,
			&baselineEvaluation, &checks, &record.DecidedAt, &record.DecidedBy.Issuer, &record.DecidedBy.Subject)
	if err != nil {
		return contracts.ModelPromotionV1{}, repositoryReadError(err)
	}
	record.ArtifactSHA256, record.EvaluationSHA256 = hex.EncodeToString(artifactDigest), hex.EncodeToString(evaluationDigest)
	record.Outcome, record.DecidedAt = contracts.ModelPromotionOutcomeV1(outcome), record.DecidedAt.UTC()
	if baselineVersion.Valid {
		record.Baseline = &contracts.ModelBaselineV1{ModelVersion: baselineVersion.String,
			ArtifactSHA256: hex.EncodeToString(baselineDigest), EvaluationSHA256: hex.EncodeToString(baselineEvaluation)}
	}
	if err := json.Unmarshal(reasons, &record.Reasons); err != nil {
		return contracts.ModelPromotionV1{}, repositoryUnavailable(fmt.Errorf("stored promotion reasons %s: %w", version, err))
	}
	if err := json.Unmarshal(checks, &record.Checks); err != nil {
		return contracts.ModelPromotionV1{}, repositoryUnavailable(fmt.Errorf("stored promotion checks %s: %w", version, err))
	}
	return record, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilChecks(values []contracts.ModelRegressionCheckV1) []contracts.ModelRegressionCheckV1 {
	if values == nil {
		return []contracts.ModelRegressionCheckV1{}
	}
	return values
}

func (s *ModelRegistryService) submitEvaluation(w http.ResponseWriter, r *http.Request) {
	var submission contracts.ModelEvaluationSubmissionV1
	if !decodeModelRequest(w, r, contracts.ModelEvaluationMaxBytesV1/3*4+4<<10, &submission) {
		return
	}
	if submission.ModelVersion != r.PathValue("version") {
		http.Error(w, string(contracts.ModelRejectionInvalidRequest), http.StatusBadRequest)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	record, created, err := s.repository.PutModelEvaluation(r.Context(), submission, s.publisherKey, actor)
	writeModelResult(w, record, created, err)
}

func (s *ModelRegistryService) evaluation(w http.ResponseWriter, r *http.Request) {
	record, err := s.repository.ModelEvaluation(r.Context(), r.PathValue("version"))
	writeModelResult(w, record, false, err)
}

func (s *ModelRegistryService) promote(w http.ResponseWriter, r *http.Request) {
	var request contracts.ModelPromotionRequestV1
	if !decodeModelRequest(w, r, 16<<10, &request) {
		return
	}
	if request.ModelVersion != r.PathValue("version") {
		http.Error(w, string(contracts.ModelRejectionInvalidRequest), http.StatusBadRequest)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	record, created, err := s.repository.PromoteModel(r.Context(), request, actor)
	writeModelResult(w, record, created, err)
}

func (s *ModelRegistryService) promotion(w http.ResponseWriter, r *http.Request) {
	record, err := s.repository.ModelPromotion(r.Context(), r.PathValue("version"))
	writeModelResult(w, record, false, err)
}
