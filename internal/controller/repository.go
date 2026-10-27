package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	enrollmentChallengeEntropyBytes = 32
	postgresUniqueViolationSQLState = "23505"
)

var (
	ErrRepositoryUnavailable = errors.New("device repository unavailable")
	ErrRepositoryNotFound    = errors.New("device repository record not found")
	repositoryIDPattern      = regexp.MustCompile(contracts.OpaqueIDPattern)
)

// RepositoryRejection is a storage/contract outcome, not a wire acknowledgement.
// Admission handlers must apply their authorization and disclosure policy first.
type RepositoryRejection struct {
	Reason       string
	LastSequence *uint64
}

func (r *RepositoryRejection) Error() string { return r.Reason }

// RepositoryConfig is trusted operator configuration, never request metadata.
type RepositoryConfig struct {
	DeploymentID string
	Now          func() time.Time
}

type PostgresRepository struct {
	db           *sql.DB
	deploymentID string
	now          func() time.Time
}

type EnrollmentChallenge struct {
	ID                     string
	DeviceID               string
	SigningKeyID           string
	AuthorizationReference string
	CreatedAt              time.Time
	ExpiresAt              time.Time
	ConsumedAt             *time.Time
}

type EnrolledDevice struct {
	Envelope      contracts.EnrollmentEnvelopeV1
	RequestSHA256 string
	EnrolledAt    time.Time
	LastSequence  uint64
	RevokedAt     *time.Time
}

type StoredEvidence struct {
	Envelope      contracts.EvidenceEnvelopeV1
	PayloadBytes  []byte
	RequestSHA256 string
	CollectedAt   time.Time
	ReceivedAt    time.Time
}

// NewPostgresRepository binds one database to one deployment. It never imports
// candidate rows, resets sequence state, or falls back to volatile storage.
func NewPostgresRepository(ctx context.Context, db *sql.DB, cfg RepositoryConfig) (*PostgresRepository, error) {
	if db == nil || !repositoryIDPattern.MatchString(cfg.DeploymentID) {
		return nil, errors.New("database and valid configured deployment ID are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO controller_deployments (deployment_id)
		VALUES ($1) ON CONFLICT (singleton) DO NOTHING`, cfg.DeploymentID); err != nil {
		return nil, repositoryUnavailable(err)
	}
	var deploymentID string
	if err := db.QueryRowContext(ctx, `SELECT deployment_id FROM controller_deployments WHERE singleton`).Scan(&deploymentID); err != nil {
		return nil, repositoryUnavailable(err)
	}
	if deploymentID != cfg.DeploymentID {
		return nil, errors.New("database is bound to another deployment")
	}
	return &PostgresRepository{db: db, deploymentID: cfg.DeploymentID, now: cfg.Now}, nil
}

// CreateEnrollmentChallenge must be called only after bootstrap authorization.
// The reference identifies that off-chain authorization record, never its secret.
// Authorization and challenge delivery belong to the admission service.
func (s *PostgresRepository) CreateEnrollmentChallenge(ctx context.Context, deviceID string, publicKey ed25519.PublicKey, authorizationReference string) (EnrollmentChallenge, error) {
	keyID, err := contracts.SigningKeyIDV1(publicKey)
	if err != nil || !repositoryIDPattern.MatchString(deviceID) || !repositoryIDPattern.MatchString(authorizationReference) {
		return EnrollmentChallenge{}, errors.New("valid device, signing key and authorization reference are required")
	}
	now := s.now().UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return EnrollmentChallenge{}, errors.New("receiver clock is required")
	}
	var random [enrollmentChallengeEntropyBytes]byte
	if _, err := rand.Read(random[:]); err != nil {
		return EnrollmentChallenge{}, fmt.Errorf("generate enrollment challenge: %w", err)
	}
	challenge := EnrollmentChallenge{
		ID: hex.EncodeToString(random[:]), DeviceID: deviceID, SigningKeyID: keyID,
		AuthorizationReference: authorizationReference, CreatedAt: now, ExpiresAt: now.Add(contracts.EnrollmentMaxLifetimeV1),
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return EnrollmentChallenge{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO enrollment_challenges
		(deployment_id, id, device_id, signing_key_id, authorization_reference, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`, s.deploymentID, challenge.ID, deviceID, keyID, authorizationReference, now, challenge.ExpiresAt)
	if err != nil {
		return EnrollmentChallenge{}, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return EnrollmentChallenge{}, err
	}
	return challenge, nil
}

func (s *PostgresRepository) Enroll(ctx context.Context, envelope contracts.EnrollmentEnvelopeV1) error {
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := s.enrollInTransaction(ctx, tx, envelope); err != nil {
		return err
	}
	return repositoryCommit(tx)
}

func (s *PostgresRepository) enrollInTransaction(ctx context.Context, tx *sql.Tx, envelope contracts.EnrollmentEnvelopeV1) error {
	if envelope.DeploymentID != s.deploymentID {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionDeploymentMismatch}
	}
	if err := envelope.Validate(); err != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	publicKey, err := hex.DecodeString(envelope.PublicKey)
	if err != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	if err := envelope.VerifySignature(publicKey); err != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidSignature}
	}
	var challenge EnrollmentChallenge
	err = tx.QueryRowContext(ctx, `SELECT device_id, signing_key_id, created_at, expires_at, consumed_at
		FROM enrollment_challenges WHERE deployment_id=$1 AND id=$2 FOR UPDATE`,
		s.deploymentID, envelope.ChallengeID).Scan(&challenge.DeviceID, &challenge.SigningKeyID, &challenge.CreatedAt, &challenge.ExpiresAt, &challenge.ConsumedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	if err != nil {
		return repositoryUnavailable(err)
	}
	if challenge.DeviceID != envelope.DeviceID || challenge.SigningKeyID != envelope.SigningKeyID {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	if challenge.ConsumedAt != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionChallengeReused}
	}
	now := s.now().UTC()
	if !now.Before(challenge.ExpiresAt) {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionChallengeExpired}
	}
	if now.Before(challenge.CreatedAt) {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	if reason, err := envelope.EnvelopeHeaderV1.FreshnessRejection(now, contracts.UnenrolledSequenceV1); err != nil {
		return err
	} else if reason != "" {
		return &RepositoryRejection{Reason: reason}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	signingBytes, _ := envelope.SigningBytes()
	requestDigest, _ := contracts.EnvelopeRequestSHA256V1(signingBytes, envelope.Signature)
	_, err = tx.ExecContext(ctx, `INSERT INTO device_enrollments
		(deployment_id, device_id, signing_key_id, public_key, challenge_id, envelope, request_sha256, enrolled_at, last_sequence)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`, s.deploymentID, envelope.DeviceID, envelope.SigningKeyID, publicKey,
		envelope.ChallengeID, string(encoded), decodeRepositoryDigest(requestDigest), now, contracts.EnrollmentSequenceV1)
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == postgresUniqueViolationSQLState {
			return &RepositoryRejection{Reason: contracts.EnvelopeRejectionEnrollmentConflict}
		}
		return repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_challenges SET consumed_at=$3
		WHERE deployment_id=$1 AND id=$2`, s.deploymentID, envelope.ChallengeID, now); err != nil {
		return repositoryUnavailable(err)
	}
	return nil
}

// AcceptEvidence verifies against the locked enrolled key, then commits the
// exact payload and shared device high-water mark in the same transaction.
// Callers must authorize the authenticated peer before invoking this method.
func (s *PostgresRepository) AcceptEvidence(ctx context.Context, envelope contracts.EvidenceEnvelopeV1) error {
	if envelope.DeploymentID != s.deploymentID {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionDeploymentMismatch}
	}
	if err := envelope.Validate(); err != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var publicKey []byte
	var lastSequence uint64
	var revokedAt *time.Time
	err = tx.QueryRowContext(ctx, `SELECT public_key, last_sequence, revoked_at FROM device_enrollments
		WHERE deployment_id=$1 AND device_id=$2 FOR UPDATE`, s.deploymentID, envelope.DeviceID).Scan(&publicKey, &lastSequence, &revokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionUnknownDevice}
	}
	if err != nil {
		return repositoryUnavailable(err)
	}
	if revokedAt != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionRevokedKey}
	}
	if err := envelope.VerifySignature(publicKey); err != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidSignature}
	}
	// Read the clock after acquiring the lock: a waiter may have expired.
	now := s.now().UTC()
	if reason, err := envelope.EnvelopeHeaderV1.FreshnessRejection(now, lastSequence); err != nil {
		return err
	} else if reason != "" {
		return &RepositoryRejection{Reason: reason, LastSequence: &lastSequence}
	}
	payload, _ := base64.StdEncoding.Strict().DecodeString(envelope.PayloadBase64)
	var telemetry contracts.TelemetryV2
	if err := json.Unmarshal(payload, &telemetry); err != nil {
		return &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	signingBytes, _ := envelope.SigningBytes()
	requestDigest, _ := contracts.EnvelopeRequestSHA256V1(signingBytes, envelope.Signature)
	_, err = tx.ExecContext(ctx, `INSERT INTO device_evidence
		(deployment_id, device_id, sequence, envelope, payload_bytes, request_sha256, collected_at, received_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, s.deploymentID, envelope.DeviceID, envelope.Sequence,
		string(encoded), payload, decodeRepositoryDigest(requestDigest), telemetry.CollectedAt, now)
	if err != nil {
		return repositoryUnavailable(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE device_enrollments SET last_sequence=$3
		WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, envelope.DeviceID, envelope.Sequence); err != nil {
		return repositoryUnavailable(err)
	}
	return repositoryCommit(tx)
}

func (s *PostgresRepository) Device(ctx context.Context, deviceID string) (EnrolledDevice, error) {
	var device EnrolledDevice
	var encoded, digest []byte
	err := s.db.QueryRowContext(ctx, `SELECT envelope, request_sha256, enrolled_at, last_sequence, revoked_at
		FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, deviceID).
		Scan(&encoded, &digest, &device.EnrolledAt, &device.LastSequence, &device.RevokedAt)
	if err != nil {
		return EnrolledDevice{}, repositoryReadError(err)
	}
	if err := json.Unmarshal(encoded, &device.Envelope); err != nil {
		return EnrolledDevice{}, repositoryUnavailable(err)
	}
	device.RequestSHA256 = hex.EncodeToString(digest)
	return device, nil
}

func (s *PostgresRepository) Evidence(ctx context.Context, deviceID string, sequence uint64) (StoredEvidence, error) {
	var evidence StoredEvidence
	var encoded, digest []byte
	err := s.db.QueryRowContext(ctx, `SELECT envelope, payload_bytes, request_sha256, collected_at, received_at
		FROM device_evidence WHERE deployment_id=$1 AND device_id=$2 AND sequence=$3`, s.deploymentID, deviceID, sequence).
		Scan(&encoded, &evidence.PayloadBytes, &digest, &evidence.CollectedAt, &evidence.ReceivedAt)
	if err != nil {
		return StoredEvidence{}, repositoryReadError(err)
	}
	if err := json.Unmarshal(encoded, &evidence.Envelope); err != nil {
		return StoredEvidence{}, repositoryUnavailable(err)
	}
	evidence.RequestSHA256 = hex.EncodeToString(digest)
	return evidence, nil
}

func repositoryUnavailable(err error) error {
	return fmt.Errorf("%w: %w", ErrRepositoryUnavailable, err)
}

func (s *PostgresRepository) beginWrite(ctx context.Context) (*sql.Tx, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, repositoryUnavailable(err)
	}
	// Do not inherit a session's asynchronous-commit setting for accepted state.
	if _, err := tx.ExecContext(ctx, `SET LOCAL synchronous_commit = on`); err != nil {
		tx.Rollback()
		return nil, repositoryUnavailable(err)
	}
	return tx, nil
}

func repositoryReadError(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrRepositoryNotFound
	}
	return repositoryUnavailable(err)
}

func repositoryCommit(tx *sql.Tx) error {
	if err := tx.Commit(); err != nil {
		// A lost connection at commit leaves an uncertain outcome. Never infer
		// rejection or issue accepted; a future authenticated lookup must resolve it.
		return repositoryUnavailable(err)
	}
	return nil
}

func decodeRepositoryDigest(value string) []byte {
	decoded, _ := hex.DecodeString(value) // Derived from validated contract signing bytes.
	return decoded
}
