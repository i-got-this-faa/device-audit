package controller

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// auditSource is one durable record snapshotted as evidence.
type auditSource struct {
	schemaVersion string
	reference     string
	content       []byte
}

func (s *PostgresRepository) auditEvidenceLimit() int {
	if s.auditEvidenceMaxBytes > 0 {
		return s.auditEvidenceMaxBytes
	}
	return contracts.AuditEvidenceMaxBytesV1
}

// StoreAuditEvidence snapshots one telemetry envelope, prediction or diagnostic
// result into bounded, immutable off-chain evidence. The controller reads the
// source itself, re-verifies the device signature digest it was accepted
// under, and stores the exact bytes it will serve. A repeat of the identical
// request returns the stored record with created=false.
func (s *PostgresRepository) StoreAuditEvidence(ctx context.Context, request contracts.AuditEvidenceStoreRequestV1, actor contracts.ModelActorV1) (contracts.AuditEvidenceV1, bool, error) {
	request.RetentionExpiresAt = request.RetentionExpiresAt.UTC().Truncate(time.Microsecond)
	if err := request.Validate(s.now().UTC()); err != nil {
		return contracts.AuditEvidenceV1{}, false, contracts.AuditEvidenceRejectionInvalidRequest
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.AuditEvidenceV1{}, false, err
	}
	defer tx.Rollback()

	source, err := s.readAuditSource(ctx, tx, request)
	if err != nil {
		return contracts.AuditEvidenceV1{}, false, err
	}
	if len(source.content) > s.auditEvidenceLimit() {
		return contracts.AuditEvidenceV1{}, false, contracts.AuditEvidenceRejectionTooLarge
	}
	sum := sha256.Sum256(source.content)
	if existing, found, err := s.sameAuditEvidence(ctx, tx, request, source, sum[:]); err != nil || found {
		return existing, false, err
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_evidence (deployment_id, evidence_id, kind, schema_version, device_id, source_ref,
		content, sha256, stored_at, retention_expires_at, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		s.deploymentID, request.EvidenceID, string(request.Kind), source.schemaVersion, request.DeviceID, source.reference,
		source.content, sum[:], now, request.RetentionExpiresAt, actor.Issuer, actor.Subject); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == postgresUniqueViolationSQLState {
			// A concurrent request, or another ID for this source, won.
			tx.Rollback()
			existing, found, rerr := s.sameAuditEvidence(ctx, s.db, request, source, sum[:])
			if rerr != nil {
				return contracts.AuditEvidenceV1{}, false, rerr
			}
			if found {
				return existing, false, nil
			}
			return contracts.AuditEvidenceV1{}, false, contracts.AuditEvidenceRejectionConflict
		}
		return contracts.AuditEvidenceV1{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.AuditEvidenceV1{}, false, err
	}
	meta, _, err := s.auditEvidence(ctx, s.db, request.EvidenceID, false)
	return meta, true, err
}

// sameAuditEvidence returns the stored record when the request repeats it
// exactly, and a conflict when the ID or the source is already used differently.
func (s *PostgresRepository) sameAuditEvidence(ctx context.Context, q dbQueryer, request contracts.AuditEvidenceStoreRequestV1, source auditSource, digest []byte) (contracts.AuditEvidenceV1, bool, error) {
	var storedID string
	err := q.QueryRowContext(ctx, `SELECT evidence_id FROM audit_evidence WHERE deployment_id=$1 AND (evidence_id=$2 OR (kind=$3 AND source_ref=$4)) LIMIT 1`,
		s.deploymentID, request.EvidenceID, string(request.Kind), source.reference).Scan(&storedID)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AuditEvidenceV1{}, false, nil
	}
	if err != nil {
		return contracts.AuditEvidenceV1{}, false, repositoryUnavailable(err)
	}
	meta, _, err := s.auditEvidence(ctx, q, storedID, false)
	if err != nil {
		return contracts.AuditEvidenceV1{}, false, err
	}
	if storedID != request.EvidenceID || meta.Kind != request.Kind || meta.SourceReference != source.reference || meta.DeviceID != request.DeviceID ||
		meta.SHA256 != hex.EncodeToString(digest) || !meta.RetentionExpiresAt.Equal(request.RetentionExpiresAt) {
		return contracts.AuditEvidenceV1{}, false, contracts.AuditEvidenceRejectionConflict
	}
	return meta, true, nil
}

// AuditEvidenceMetadata returns one record's metadata, never its bytes.
func (s *PostgresRepository) AuditEvidenceMetadata(ctx context.Context, evidenceID string) (contracts.AuditEvidenceV1, error) {
	meta, _, err := s.auditEvidence(ctx, s.db, evidenceID, false)
	return meta, err
}

// AuditEvidenceContent returns the exact stored bytes. scopeDeviceID, when not
// empty, is the device the caller is entitled to; evidence owned by another
// device is refused without revealing its bytes or owner. Bytes that no longer
// match their digest are never served, and nothing is served after retention.
func (s *PostgresRepository) AuditEvidenceContent(ctx context.Context, evidenceID, scopeDeviceID string) (contracts.AuditEvidenceV1, []byte, error) {
	meta, content, err := s.auditEvidence(ctx, s.db, evidenceID, true)
	if err != nil {
		return contracts.AuditEvidenceV1{}, nil, err
	}
	if scopeDeviceID != "" && scopeDeviceID != meta.DeviceID {
		return contracts.AuditEvidenceV1{}, nil, contracts.AuditEvidenceRejectionWrongScope
	}
	if !s.now().UTC().Before(meta.RetentionExpiresAt) {
		return contracts.AuditEvidenceV1{}, nil, contracts.AuditEvidenceRejectionExpired
	}
	return meta, content, nil
}

func (s *PostgresRepository) auditEvidence(ctx context.Context, q dbQueryer, evidenceID string, withContent bool) (contracts.AuditEvidenceV1, []byte, error) {
	if !repositoryIDPattern.MatchString(evidenceID) {
		return contracts.AuditEvidenceV1{}, nil, contracts.AuditEvidenceRejectionNotFound
	}
	meta := contracts.AuditEvidenceV1{SchemaVersion: contracts.AuditEvidenceV1Version, DeploymentID: s.deploymentID, EvidenceID: evidenceID}
	var kind string
	var digest, content []byte
	var size int
	err := q.QueryRowContext(ctx, `SELECT kind, schema_version, device_id, source_ref, sha256, octet_length(content), content,
		stored_at, retention_expires_at, actor_issuer, actor_subject
		FROM audit_evidence WHERE deployment_id=$1 AND evidence_id=$2`, s.deploymentID, evidenceID).
		Scan(&kind, &meta.EvidenceSchemaVersion, &meta.DeviceID, &meta.SourceReference, &digest, &size, &content,
			&meta.StoredAt, &meta.RetentionExpiresAt, &meta.StoredBy.Issuer, &meta.StoredBy.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AuditEvidenceV1{}, nil, contracts.AuditEvidenceRejectionNotFound
	}
	if err != nil {
		return contracts.AuditEvidenceV1{}, nil, repositoryUnavailable(err)
	}
	// Bytes changed at rest are refused rather than served.
	if sum := sha256.Sum256(content); size != len(content) || hex.EncodeToString(sum[:]) != hex.EncodeToString(digest) {
		return contracts.AuditEvidenceV1{}, nil, contracts.AuditEvidenceRejectionUnavailable
	}
	meta.Kind, meta.SHA256, meta.SizeBytes = contracts.AuditEvidenceKindV1(kind), hex.EncodeToString(digest), uint32(size)
	meta.StoredAt, meta.RetentionExpiresAt = meta.StoredAt.UTC(), meta.RetentionExpiresAt.UTC()
	if !withContent {
		content = nil
	}
	return meta, content, nil
}

func (s *PostgresRepository) readAuditSource(ctx context.Context, q dbQueryer, request contracts.AuditEvidenceStoreRequestV1) (auditSource, error) {
	switch request.Kind {
	case contracts.AuditEvidenceTelemetry:
		return s.telemetryAuditSource(ctx, q, request)
	case contracts.AuditEvidencePrediction:
		return s.predictionAuditSource(ctx, q, request)
	default:
		return s.diagnosticAuditSource(ctx, q, request)
	}
}

func sourceReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, ErrRepositoryNotFound) {
		return contracts.AuditEvidenceRejectionSourceNotFound
	}
	return repositoryUnavailable(err)
}

func (s *PostgresRepository) telemetryAuditSource(ctx context.Context, q dbQueryer, request contracts.AuditEvidenceStoreRequestV1) (auditSource, error) {
	var stored, digest []byte
	if err := q.QueryRowContext(ctx, `SELECT envelope, request_sha256 FROM device_evidence WHERE deployment_id=$1 AND device_id=$2 AND sequence=$3`,
		s.deploymentID, request.DeviceID, int64(request.Sequence)).Scan(&stored, &digest); err != nil {
		return auditSource{}, sourceReadError(err)
	}
	var envelope contracts.EvidenceEnvelopeV1
	if err := json.Unmarshal(stored, &envelope); err != nil || envelope.DeviceID != request.DeviceID || envelope.Sequence != request.Sequence {
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	}
	signing, err := envelope.SigningBytes()
	if err != nil {
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	}
	if got, err := contracts.EnvelopeRequestSHA256V1(signing, envelope.Signature); err != nil || got != hex.EncodeToString(digest) {
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	}
	content, err := json.Marshal(envelope)
	if err != nil {
		return auditSource{}, repositoryUnavailable(err)
	}
	return auditSource{schemaVersion: contracts.EvidenceEnvelopeV1Version, reference: "telemetry:" + strconv.FormatUint(request.Sequence, 10), content: content}, nil
}

func (s *PostgresRepository) predictionAuditSource(ctx context.Context, q dbQueryer, request contracts.AuditEvidenceStoreRequestV1) (auditSource, error) {
	record, err := s.scanPredictionRecord(q.QueryRowContext(ctx, predictionHistorySelect+` WHERE p.deployment_id=$1 AND p.device_id=$2 AND p.id=$3`,
		s.deploymentID, request.DeviceID, int64(request.PredictionID)), request.DeviceID, s.now().UTC())
	switch {
	case errors.Is(err, ErrPredictionEvidenceBroken):
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	case err != nil:
		return auditSource{}, sourceReadError(err)
	case record.Prediction == nil:
		// An assessment made without telemetry has no prediction payload to keep.
		return auditSource{}, contracts.AuditEvidenceRejectionSourceNotFound
	}
	content, err := json.Marshal(record.Prediction)
	if err != nil {
		return auditSource{}, repositoryUnavailable(err)
	}
	return auditSource{schemaVersion: contracts.PredictionV2Version, reference: "prediction:" + strconv.FormatUint(request.PredictionID, 10), content: content}, nil
}

func (s *PostgresRepository) diagnosticAuditSource(ctx context.Context, q dbQueryer, request contracts.AuditEvidenceStoreRequestV1) (auditSource, error) {
	var stored, digest []byte
	if err := q.QueryRowContext(ctx, `SELECT envelope, request_sha256 FROM diagnostic_results WHERE deployment_id=$1 AND assignment_id=$2 AND device_id=$3`,
		s.deploymentID, request.AssignmentID, request.DeviceID).Scan(&stored, &digest); err != nil {
		return auditSource{}, sourceReadError(err)
	}
	var result contracts.DiagnosticResultV1
	if err := json.Unmarshal(stored, &result); err != nil || result.DeviceID != request.DeviceID || result.AssignmentID != request.AssignmentID {
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	}
	signing, err := result.SigningBytes()
	if err != nil {
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	}
	if got, err := contracts.EnvelopeRequestSHA256V1(signing, result.Signature); err != nil || got != hex.EncodeToString(digest) {
		return auditSource{}, contracts.AuditEvidenceRejectionUnavailable
	}
	content, err := json.Marshal(result)
	if err != nil {
		return auditSource{}, repositoryUnavailable(err)
	}
	return auditSource{schemaVersion: contracts.DiagnosticResultV1Version, reference: "diagnostic:" + request.AssignmentID, content: content}, nil
}

func auditEvidenceStatus(err error) (int, string) {
	var rejection contracts.AuditEvidenceRejection
	if !errors.As(err, &rejection) {
		return http.StatusServiceUnavailable, "audit evidence unavailable; repeat the request to confirm the outcome"
	}
	switch rejection {
	case contracts.AuditEvidenceRejectionNotFound, contracts.AuditEvidenceRejectionSourceNotFound:
		return http.StatusNotFound, string(rejection)
	case contracts.AuditEvidenceRejectionWrongScope:
		return http.StatusForbidden, string(rejection)
	case contracts.AuditEvidenceRejectionTooLarge:
		return http.StatusRequestEntityTooLarge, string(rejection)
	case contracts.AuditEvidenceRejectionConflict:
		return http.StatusConflict, string(rejection)
	case contracts.AuditEvidenceRejectionExpired:
		return http.StatusGone, string(rejection)
	case contracts.AuditEvidenceRejectionUnavailable:
		return http.StatusInternalServerError, string(rejection)
	}
	return http.StatusBadRequest, string(rejection)
}

func writeAuditEvidenceError(w http.ResponseWriter, err error) {
	status, text := auditEvidenceStatus(err)
	http.Error(w, text, status)
}

func (s *DeviceStateService) storeEvidence(w http.ResponseWriter, r *http.Request) {
	var request contracts.AuditEvidenceStoreRequestV1
	if !decodeAuditEvidenceRequest(w, r, &request) {
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	meta, created, err := s.repository.StoreAuditEvidence(r.Context(), request, actor)
	if err != nil {
		writeAuditEvidenceError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, meta)
}

func (s *DeviceStateService) evidenceMetadata(w http.ResponseWriter, r *http.Request) {
	meta, err := s.repository.AuditEvidenceMetadata(r.Context(), r.PathValue("id"))
	if err != nil {
		writeAuditEvidenceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (s *DeviceStateService) evidenceContent(w http.ResponseWriter, r *http.Request) {
	scope := ""
	for key, values := range r.URL.Query() {
		if key != "device_id" || len(values) != 1 {
			http.Error(w, string(contracts.AuditEvidenceRejectionInvalidRequest), http.StatusBadRequest)
			return
		}
		scope = values[0]
	}
	meta, content, err := s.repository.AuditEvidenceContent(r.Context(), r.PathValue("id"), scope)
	if err != nil {
		writeAuditEvidenceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Repr-Digest", fmt.Sprintf("sha-256=:%s:", digestBase64(meta.SHA256)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func digestBase64(hexDigest string) string {
	digest, _ := hex.DecodeString(hexDigest)
	return base64.StdEncoding.EncodeToString(digest)
}

// decodeAuditEvidenceRequest reads exactly one small JSON object.
func decodeAuditEvidenceRequest(w http.ResponseWriter, r *http.Request, target *contracts.AuditEvidenceStoreRequestV1) bool {
	invalid := func() bool {
		http.Error(w, string(contracts.AuditEvidenceRejectionInvalidRequest), http.StatusBadRequest)
		return false
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return invalid()
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, string(contracts.AuditEvidenceRejectionTooLarge), http.StatusRequestEntityTooLarge)
			return false
		}
		return invalid()
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return invalid()
	}
	return true
}
