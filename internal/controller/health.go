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
	"io"
	"os"
	"regexp"
	"syscall"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

var evaluationSHA256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// EvaluationReportStore loads the raw evaluation report bytes identified by
// SHA-256 digest. Callers verify the digest and ML05 gates after loading.
type EvaluationReportStore interface {
	EvaluationReport(ctx context.Context, evaluationSHA256 string) ([]byte, error)
}

// EvaluationReportFunc adapts a lookup function to EvaluationReportStore.
type EvaluationReportFunc func(ctx context.Context, evaluationSHA256 string) ([]byte, error)

func (f EvaluationReportFunc) EvaluationReport(ctx context.Context, evaluationSHA256 string) ([]byte, error) {
	if f == nil {
		return nil, errors.New("evaluation report lookup is unavailable")
	}
	return f(ctx, evaluationSHA256)
}

// EvaluationReportDir reads SHA-256-named JSON evaluation reports
// (<sha256>.json) inside one directory, rejecting path traversal and symlinks
// escaping the directory.
type EvaluationReportDir string

func (d EvaluationReportDir) EvaluationReport(_ context.Context, evaluationSHA256 string) ([]byte, error) {
	if d == "" || !evaluationSHA256Pattern.MatchString(evaluationSHA256) {
		return nil, errors.New("valid evaluation directory and SHA-256 digest are required")
	}
	root, err := os.OpenRoot(string(d))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	f, err := root.OpenFile(evaluationSHA256+".json", os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > health.MaxEvaluationReportBytes {
		return nil, errors.New("evaluation report must be a bounded regular file")
	}
	data, err := io.ReadAll(io.LimitReader(f, health.MaxEvaluationReportBytes+1))
	if err != nil || len(data) > health.MaxEvaluationReportBytes {
		return nil, errors.New("evaluation report exceeds size bound")
	}
	return data, nil
}

// HealthConfig supplies the trust root and evaluation report store required to
// load and verify the active model from the controller registry.
type HealthConfig struct {
	PublisherKey      ed25519.PublicKey
	EvaluationReports EvaluationReportStore
	// MaxEvidenceAge bounds latest telemetry freshness; zero uses health.MaxEvidenceAge (1h).
	MaxEvidenceAge time.Duration
}

// DeviceEvidenceSummary describes the latest persisted sample at or before AsOf.
type DeviceEvidenceSummary struct {
	Sequence               uint64
	CollectedAt            time.Time
	ReceivedAt             time.Time
	PayloadSHA256          string
	RequestSHA256          string
	Source                 string
	TelemetrySchemaVersion string
}

// DeviceHealth is the controller's attributable health evaluation for one
// enrolled device at AsOf, uniting the evaluated active model, CT03 features,
// ML10 fault history comparison, and latest telemetry evidence.
type DeviceHealth struct {
	DeploymentID string
	DeviceID     string
	AsOf         time.Time
	RevokedAt    *time.Time
	LatestSample *DeviceEvidenceSummary
	Features     DeviceFeatures
	FaultHistory DeviceFaultHistory
	Model        *contracts.ModelReferenceV2
	ModelStatus  string
	ModelError   string
	Assessment   health.Assessment
}

// EvaluateDeviceHealth loads the active evaluated compatible model from the
// durable registry, extracts CT03 features and compares ML10 fault history from
// persisted evidence up to asOf inside one repeatable-read database snapshot,
// and assigns evidence-backed health under health-rules.v1.
//
// Unknown devices return ErrRepositoryNotFound and invalid queries return
// ErrDeviceStateInvalid. Real telemetry v2 carries no SMART counter, so
// a ready model with fresh telemetry yields unknown (insufficient_evidence)
// rather than inventing a numerical failure risk.
func (s *PostgresRepository) EvaluateDeviceHealth(ctx context.Context, cfg HealthConfig, deviceID string, asOf time.Time) (DeviceHealth, error) {
	return s.evaluateDeviceHealth(ctx, cfg, deviceID, asOf, func(r evidenceRef) health.SMARTReading {
		return health.SMARTReading{ObservedAt: r.CollectedAt}
	})
}

func (s *PostgresRepository) evaluateDeviceHealth(ctx context.Context, cfg HealthConfig, deviceID string, asOf time.Time, readSMART func(evidenceRef) health.SMARTReading) (DeviceHealth, error) {
	if !repositoryIDPattern.MatchString(deviceID) || asOf.IsZero() || cfg.MaxEvidenceAge < 0 {
		return DeviceHealth{}, ErrDeviceStateInvalid
	}
	asOf = asOf.UTC()
	to := asOf.Truncate(time.Microsecond).Add(time.Microsecond)

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return DeviceHealth{}, repositoryUnavailable(err)
	}
	defer tx.Rollback()

	var revokedAt sql.NullTime
	if err := tx.QueryRowContext(ctx, `SELECT revoked_at FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`,
		s.deploymentID, deviceID).Scan(&revokedAt); err != nil {
		return DeviceHealth{}, repositoryReadError(err)
	}
	out := DeviceHealth{
		DeploymentID: s.deploymentID,
		DeviceID:     deviceID,
		AsOf:         asOf,
	}
	if revokedAt.Valid {
		revoked := revokedAt.Time.UTC()
		out.RevokedAt = &revoked
	}

	latest, err := s.latestDeviceEvidence(ctx, tx, deviceID, to)
	if err != nil {
		return DeviceHealth{}, err
	}
	out.LatestSample = latest

	model, modelStatus, modelErrCode, modelErr := s.loadActiveEvaluatedModel(ctx, tx, cfg)
	if modelErr != nil && (errors.Is(modelErr, ErrRepositoryUnavailable) || ctx.Err() != nil) {
		return DeviceHealth{}, modelErr
	}
	out.ModelStatus = modelStatus
	out.ModelError = modelErrCode

	features, err := buildDeviceFeatures(ctx, txFeatureEvidence{repo: s, q: tx}, deviceID, asOf, readSMART)
	if err != nil {
		return DeviceHealth{}, err
	}
	out.Features = features

	faultHistory, err := s.deviceFaultHistory(ctx, tx, deviceID, asOf)
	if err != nil {
		return DeviceHealth{}, err
	}
	out.FaultHistory = faultHistory

	var summary *health.EvidenceSummary
	if latest != nil {
		summary = &health.EvidenceSummary{
			Sequence:               latest.Sequence,
			CollectedAt:            latest.CollectedAt,
			PayloadSHA256:          latest.PayloadSHA256,
			TelemetrySchemaVersion: latest.TelemetrySchemaVersion,
		}
	}
	assessment, err := health.AssessHealth(health.AssessmentInput{
		DeviceID:       deviceID,
		AsOf:           asOf,
		MaxEvidenceAge: cfg.MaxEvidenceAge,
		Model:          model,
		ModelFailure:   modelErr,
		LatestEvidence: summary,
		Features:       &features.Vector,
		FaultHistory:   &faultHistory.History,
	})
	if err != nil {
		return DeviceHealth{}, err
	}
	out.Assessment = assessment
	out.Model = assessment.Model
	if assessment.RuleReason == "model_inference_failed" && out.ModelStatus == "ready" {
		out.ModelStatus = "unavailable"
		out.ModelError = "model_inference_failed"
	}
	return out, nil
}

func (s *PostgresRepository) latestDeviceEvidence(ctx context.Context, q dbQueryer, deviceID string, to time.Time) (*DeviceEvidenceSummary, error) {
	var seq uint64
	var payload, reqDigest []byte
	var collectedAt, receivedAt time.Time
	err := q.QueryRowContext(ctx, `SELECT sequence, payload_bytes, request_sha256, collected_at, received_at
		FROM device_evidence
		WHERE deployment_id=$1 AND device_id=$2 AND collected_at < $3
		ORDER BY collected_at DESC, sequence DESC
		LIMIT 1`, s.deploymentID, deviceID, to).
		Scan(&seq, &payload, &reqDigest, &collectedAt, &receivedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, repositoryUnavailable(err)
	}
	var telemetry contracts.TelemetryV2
	if err := json.Unmarshal(payload, &telemetry); err != nil ||
		telemetry.SchemaVersion != contracts.TelemetryV2Version ||
		telemetry.DeviceID != deviceID {
		return nil, repositoryUnavailable(fmt.Errorf("stored sample %d: invalid telemetry payload", seq))
	}
	sum := sha256.Sum256(payload)
	return &DeviceEvidenceSummary{
		Sequence:               seq,
		CollectedAt:            collectedAt.UTC(),
		ReceivedAt:             receivedAt.UTC(),
		PayloadSHA256:          hex.EncodeToString(sum[:]),
		RequestSHA256:          hex.EncodeToString(reqDigest),
		Source:                 telemetry.Source,
		TelemetrySchemaVersion: telemetry.SchemaVersion,
	}, nil
}

func (s *PostgresRepository) loadActiveEvaluatedModel(ctx context.Context, q dbQueryer, cfg HealthConfig) (*health.EvaluatedModel, string, string, error) {
	refs, err := s.modelReferences(ctx, q)
	if err != nil {
		return nil, "unavailable", "registry_unavailable", err
	}
	if refs.Active == nil {
		return nil, "unavailable", "no_active_model", errors.New("no active model configured")
	}
	record, err := s.modelArtifact(ctx, q, refs.Active.ModelVersion)
	if err != nil {
		if errors.Is(err, ErrRepositoryNotFound) {
			return nil, "unavailable", "active_model_not_found", err
		}
		return nil, "unavailable", "registry_unavailable", err
	}
	if record.Approval == nil {
		return nil, "unavailable", "not_approved", contracts.ModelRejectionNotApproved
	}
	if record.Manifest.ArtifactSHA256 != refs.Active.ArtifactSHA256 {
		return nil, "unavailable", "reference_mismatch", contracts.ModelRejectionReferenceMismatch
	}
	if record.Approval.PolicyVersion != health.ML05PolicyVersion {
		return nil, "unavailable", "unsupported_policy_version", health.ErrEvaluationRejected
	}
	manifest, artifact, err := s.modelArtifactBytes(ctx, q, refs.Active.ModelVersion)
	if err != nil {
		if errors.Is(err, ErrModelArtifactCorrupt) {
			return nil, "unavailable", "stored_artifact_corrupt", err
		}
		if errors.Is(err, ErrRepositoryNotFound) {
			return nil, "unavailable", "active_model_not_found", err
		}
		return nil, "unavailable", "registry_unavailable", err
	}
	if cfg.EvaluationReports == nil {
		return nil, "unavailable", "evaluation_store_unconfigured", health.ErrEvaluationRejected
	}
	evalReport, err := cfg.EvaluationReports.EvaluationReport(ctx, record.Approval.EvaluationSHA256)
	if err != nil {
		if ctx.Err() != nil {
			return nil, "unavailable", "evaluation_unavailable", ctx.Err()
		}
		return nil, "unavailable", "evaluation_report_unavailable", fmt.Errorf("%w: %w", health.ErrEvaluationRejected, err)
	}
	model, err := health.LoadControllerModel(manifest, artifact, cfg.PublisherKey, evalReport, record.Approval.EvaluationSHA256)
	if err != nil {
		var rejection contracts.ModelRejection
		switch {
		case errors.As(err, &rejection):
			return nil, "unavailable", string(rejection), err
		case errors.Is(err, health.ErrEvaluationRejected):
			return nil, "unavailable", "evaluation_rejected", err
		default:
			return nil, "unavailable", "model_artifact_invalid", err
		}
	}
	return model, "ready", "", nil
}
