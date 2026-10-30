package controller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

var ErrInventoryConflict = errors.New("inventory revision conflict")
var ErrInventoryInvalid = errors.New("invalid inventory update")
var ErrInventoryRevoked = errors.New("device is revoked")

// UpdateInventory requires caller authorization. The actor must come from that
// authenticated session; inventory metadata is not signed endpoint evidence.
func (s *PostgresRepository) UpdateInventory(ctx context.Context, update contracts.InventoryUpdateV1, issuer, subject string) (contracts.InventoryRecordV1, error) {
	if err := update.Validate(); err != nil {
		return contracts.InventoryRecordV1{}, ErrInventoryInvalid
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.InventoryRecordV1{}, err
	}
	defer tx.Rollback()
	var digest []byte
	var revokedAt *time.Time
	err = tx.QueryRowContext(ctx, `SELECT request_sha256, revoked_at FROM device_enrollments
		WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`, s.deploymentID, update.DeviceID).Scan(&digest, &revokedAt)
	if err != nil {
		return contracts.InventoryRecordV1{}, repositoryReadError(err)
	}
	if revokedAt != nil {
		return contracts.InventoryRecordV1{}, ErrInventoryRevoked
	}
	var revision uint64
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0) FROM inventory_revisions
		WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, update.DeviceID).Scan(&revision); err != nil {
		return contracts.InventoryRecordV1{}, repositoryUnavailable(err)
	}
	if revision != update.ExpectedRevision {
		return contracts.InventoryRecordV1{}, ErrInventoryConflict
	}
	now := s.now().UTC()
	if update.ObservedAt.After(now) {
		return contracts.InventoryRecordV1{}, ErrInventoryInvalid
	}
	record := contracts.InventoryRecordV1{
		SchemaVersion: contracts.InventoryRecordV1Version, DeploymentID: s.deploymentID, DeviceID: update.DeviceID,
		Revision: revision + 1, ObservedAt: update.ObservedAt.UTC().Truncate(time.Microsecond), RecordedAt: now.Truncate(time.Microsecond),
		SourceReference: update.SourceReference, EnrollmentSHA256: hex.EncodeToString(digest),
		ActorIssuer: issuer, ActorSubject: subject, Inventory: update.Inventory,
	}
	if err := record.Validate(); err != nil {
		return contracts.InventoryRecordV1{}, ErrInventoryInvalid
	}
	encoded, err := json.Marshal(record.Inventory)
	if err != nil {
		return contracts.InventoryRecordV1{}, ErrInventoryInvalid
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO inventory_revisions
		(deployment_id, device_id, revision, schema_version, observed_at, recorded_at, source_reference,
		 enrollment_sha256, actor_issuer, actor_subject, inventory)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, record.DeploymentID, record.DeviceID, record.Revision,
		record.SchemaVersion, record.ObservedAt, record.RecordedAt, record.SourceReference, digest, issuer, subject, string(encoded))
	if err != nil {
		return contracts.InventoryRecordV1{}, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.InventoryRecordV1{}, err
	}
	return record, nil
}

// Inventory returns the latest revision when revision is zero, or an exact
// historical revision. It never returns candidate or fixture device metadata.
func (s *PostgresRepository) Inventory(ctx context.Context, deviceID string, revision uint64) (contracts.InventoryRecordV1, error) {
	if !repositoryIDPattern.MatchString(deviceID) || revision > contracts.MaxInventoryRevisionV1 {
		return contracts.InventoryRecordV1{}, ErrInventoryInvalid
	}
	var record contracts.InventoryRecordV1
	var digest, encoded []byte
	err := s.db.QueryRowContext(ctx, `SELECT schema_version, deployment_id, device_id, revision,
		observed_at, recorded_at, source_reference, enrollment_sha256, actor_issuer, actor_subject, inventory
		FROM inventory_revisions WHERE deployment_id=$1 AND device_id=$2 AND ($3=0 OR revision=$3)
		ORDER BY revision DESC LIMIT 1`, s.deploymentID, deviceID, revision).
		Scan(&record.SchemaVersion, &record.DeploymentID, &record.DeviceID, &record.Revision, &record.ObservedAt,
			&record.RecordedAt, &record.SourceReference, &digest, &record.ActorIssuer, &record.ActorSubject, &encoded)
	if err != nil {
		return contracts.InventoryRecordV1{}, repositoryReadError(err)
	}
	record.EnrollmentSHA256 = hex.EncodeToString(digest)
	record.ObservedAt = record.ObservedAt.UTC()
	record.RecordedAt = record.RecordedAt.UTC()
	if err := json.Unmarshal(encoded, &record.Inventory); err != nil {
		return contracts.InventoryRecordV1{}, repositoryUnavailable(err)
	}
	if err := record.Validate(); err != nil {
		return contracts.InventoryRecordV1{}, repositoryUnavailable(err)
	}
	return record, nil
}
