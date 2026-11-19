package controller

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

var (
	ErrRevocationInvalid = errors.New("invalid device revocation")
	// ErrRevocationUnrecorded marks a device revoked outside RevokeDevice, for
	// example by hand before migration 006. No actor is invented for it.
	ErrRevocationUnrecorded = errors.New("device is revoked without a revocation record")
)

// RevokeDevice permanently stops admitting one enrollment and appends its audit
// record in the same transaction. It locks the device row that AcceptEvidence
// locks, so a sample either commits before revoked_at or is rejected after it.
// The actor must come from the authenticated session. created is false when the
// device was already revoked; the original record is returned and none is added.
func (s *PostgresRepository) RevokeDevice(ctx context.Context, request contracts.DeviceRevocationRequestV1, issuer, subject string) (record contracts.DeviceRevocationV1, created bool, err error) {
	if err := request.Validate(); err != nil {
		return contracts.DeviceRevocationV1{}, false, ErrRevocationInvalid
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.DeviceRevocationV1{}, false, err
	}
	defer tx.Rollback()
	var digest []byte
	var revokedAt *time.Time
	err = tx.QueryRowContext(ctx, `SELECT request_sha256, revoked_at FROM device_enrollments
		WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`, s.deploymentID, request.DeviceID).Scan(&digest, &revokedAt)
	if err != nil {
		return contracts.DeviceRevocationV1{}, false, repositoryReadError(err)
	}
	if revokedAt != nil {
		record, err := s.revocationRecord(ctx, tx, request.DeviceID)
		if errors.Is(err, ErrRepositoryNotFound) {
			err = ErrRevocationUnrecorded
		}
		return record, false, err
	}
	// Read the clock after locking: a sample that held the lock is ordered first.
	record = contracts.DeviceRevocationV1{
		SchemaVersion: contracts.DeviceRevocationV1Version, DeploymentID: s.deploymentID, DeviceID: request.DeviceID,
		RevokedAt: s.now().UTC().Truncate(time.Microsecond), ReasonReference: request.ReasonReference,
		EnrollmentSHA256: hex.EncodeToString(digest), ActorIssuer: issuer, ActorSubject: subject,
	}
	if err := record.Validate(); err != nil {
		return contracts.DeviceRevocationV1{}, false, ErrRevocationInvalid
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_enrollments SET revoked_at=$3
		WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, record.DeviceID, record.RevokedAt); err != nil {
		return contracts.DeviceRevocationV1{}, false, repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO device_revocation_events
		(deployment_id, device_id, revoked_at, reason_reference, enrollment_sha256, actor_issuer, actor_subject)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`, record.DeploymentID, record.DeviceID, record.RevokedAt,
		record.ReasonReference, digest, issuer, subject); err != nil {
		return contracts.DeviceRevocationV1{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.DeviceRevocationV1{}, false, err
	}
	return record, true, nil
}

func (s *PostgresRepository) revocationRecord(ctx context.Context, tx *sql.Tx, deviceID string) (contracts.DeviceRevocationV1, error) {
	record := contracts.DeviceRevocationV1{SchemaVersion: contracts.DeviceRevocationV1Version}
	var digest []byte
	err := tx.QueryRowContext(ctx, `SELECT deployment_id, device_id, revoked_at, reason_reference,
		enrollment_sha256, actor_issuer, actor_subject FROM device_revocation_events
		WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, deviceID).
		Scan(&record.DeploymentID, &record.DeviceID, &record.RevokedAt, &record.ReasonReference, &digest, &record.ActorIssuer, &record.ActorSubject)
	if err != nil {
		return contracts.DeviceRevocationV1{}, repositoryReadError(err)
	}
	record.RevokedAt = record.RevokedAt.UTC()
	record.EnrollmentSHA256 = hex.EncodeToString(digest)
	return record, nil
}

// RevocationService exposes device revocation to fresh console administrators.
type RevocationService struct {
	repository *PostgresRepository
	auth       *auth.Service
}

func NewRevocationService(repository *PostgresRepository, consoleAuth *auth.Service) (*RevocationService, error) {
	if repository == nil || consoleAuth == nil {
		return nil, errors.New("revocation requires a durable repository and console authentication")
	}
	return &RevocationService{repository: repository, auth: consoleAuth}, nil
}

func (s *RevocationService) Register(mux *http.ServeMux) {
	mux.Handle("POST /console/api/devices/{id}/revocation", s.auth.RequireFreshAdmin(http.HandlerFunc(s.revoke)))
}

func (s *RevocationService) revoke(w http.ResponseWriter, r *http.Request) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "expected revocation JSON without query parameters", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	var request contracts.DeviceRevocationRequestV1
	if decoder.Decode(&request) != nil || decoder.Decode(&struct{}{}) != io.EOF || request.DeviceID != r.PathValue("id") {
		http.Error(w, "invalid device revocation", http.StatusBadRequest)
		return
	}
	issuer, subject, ok := auth.SessionIdentity(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	record, created, err := s.repository.RevokeDevice(r.Context(), request, issuer, subject)
	switch {
	case err == nil && created:
		writeJSON(w, http.StatusCreated, record)
	case err == nil:
		writeJSON(w, http.StatusOK, record)
	case errors.Is(err, ErrRepositoryNotFound):
		http.Error(w, "enrolled device not found", http.StatusNotFound)
	case errors.Is(err, ErrRevocationInvalid):
		http.Error(w, "invalid device revocation", http.StatusBadRequest)
	case errors.Is(err, ErrRevocationUnrecorded):
		http.Error(w, "device is revoked without a revocation record", http.StatusConflict)
	default:
		// Includes an uncertain COMMIT: repeat the request to learn the outcome.
		http.Error(w, "revocation unavailable; repeat the request to confirm the outcome", http.StatusServiceUnavailable)
	}
}
