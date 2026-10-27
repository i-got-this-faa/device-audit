package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/nacl/box"
)

func (s *PostgresRepository) IssueBootstrapToken(ctx context.Context, request contracts.BootstrapTokenRequestV1, issuer, subject string) (contracts.BootstrapTokenV1, error) {
	if err := request.Validate(); err != nil || issuer == "" || subject == "" {
		return contracts.BootstrapTokenV1{}, &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	var secret, id [contracts.BootstrapSecretBytes]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return contracts.BootstrapTokenV1{}, repositoryUnavailable(err)
	}
	if _, err := rand.Read(id[:]); err != nil {
		return contracts.BootstrapTokenV1{}, repositoryUnavailable(err)
	}
	now := s.now().UTC().Truncate(time.Second)
	result := contracts.BootstrapTokenV1{SchemaVersion: contracts.BootstrapTokenV1Version, DeploymentID: s.deploymentID, DeviceID: request.DeviceID, Token: hex.EncodeToString(secret[:]), ExpiresAt: now.Add(contracts.EnrollmentMaxLifetimeV1).Format(time.RFC3339)}
	if err := result.Validate(); err != nil || now.IsZero() {
		return contracts.BootstrapTokenV1{}, &RepositoryRejection{Reason: contracts.EnvelopeRejectionStorageUnavailable}
	}
	digest := sha256.Sum256([]byte(result.Token))
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.BootstrapTokenV1{}, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO bootstrap_tokens
		(deployment_id,id,device_id,token_sha256,issued_by_issuer,issued_by_subject,created_at,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`, s.deploymentID, hex.EncodeToString(id[:]), request.DeviceID, digest[:], issuer, subject, now, now.Add(contracts.EnrollmentMaxLifetimeV1))
	if err != nil {
		return contracts.BootstrapTokenV1{}, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.BootstrapTokenV1{}, err
	}
	return result, nil
}

type bootstrapAuthorization struct {
	ID        string
	DeviceID  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// lockBootstrap is always the first admission lock. Expiry is checked again by
// the challenge transaction after any subsequent lock wait.
func (s *PostgresRepository) lockBootstrap(ctx context.Context, tx *sql.Tx, token, deviceID string) (bootstrapAuthorization, error) {
	var authorization bootstrapAuthorization
	if len(token) != contracts.BootstrapSecretBytes*2 {
		return authorization, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	raw, err := hex.DecodeString(token)
	if err != nil || hex.EncodeToString(raw) != token {
		return authorization, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	digest := sha256.Sum256([]byte(token))
	var consumed *time.Time
	err = tx.QueryRowContext(ctx, `SELECT id,device_id,created_at,expires_at,consumed_at FROM bootstrap_tokens
		WHERE deployment_id=$1 AND token_sha256=$2 FOR UPDATE`, s.deploymentID, digest[:]).Scan(&authorization.ID, &authorization.DeviceID, &authorization.CreatedAt, &authorization.ExpiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return authorization, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	if err != nil {
		return authorization, repositoryUnavailable(err)
	}
	now := s.now().UTC()
	if authorization.DeviceID != deviceID || consumed != nil || !now.Before(authorization.ExpiresAt) || now.Before(authorization.CreatedAt) {
		return authorization, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	return authorization, nil
}

func (s *PostgresRepository) StartEnrollment(ctx context.Context, token string, request contracts.EnrollmentStartV1) (contracts.EnrollmentChallengeV1, error) {
	var result contracts.EnrollmentChallengeV1
	if err := request.Validate(); err != nil {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	if request.DeploymentID != s.deploymentID {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionDeploymentMismatch}
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	authorization, err := s.lockBootstrap(ctx, tx, token, request.DeviceID)
	if err != nil {
		return result, err
	}
	public, _ := hex.DecodeString(request.PublicKey)
	keyID, _ := contracts.SigningKeyIDV1(public)
	network, _ := contracts.NetworkPublicKeyV1(request.NetworkPublicKey)
	var storedKey string
	var storedNetwork, sealed []byte
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT c.id,c.signing_key_id,c.expires_at,n.network_public_key,n.sealed_proof
		FROM enrollment_network_challenges n JOIN enrollment_challenges c
		ON (c.deployment_id=n.deployment_id AND c.id=n.challenge_id)
		WHERE n.deployment_id=$1 AND n.bootstrap_id=$2`, s.deploymentID, authorization.ID).Scan(&result.ChallengeID, &storedKey, &expires, &storedNetwork, &sealed)
	if err == nil {
		if storedKey != keyID || !hmac.Equal(storedNetwork, network[:]) {
			return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		var id, proof [contracts.BootstrapSecretBytes]byte
		if _, err := rand.Read(id[:]); err != nil {
			return result, repositoryUnavailable(err)
		}
		if _, err := rand.Read(proof[:]); err != nil {
			return result, repositoryUnavailable(err)
		}
		sealed, err = box.SealAnonymous(nil, proof[:], &network, rand.Reader)
		if err != nil {
			return result, repositoryUnavailable(err)
		}
		proofDigest := sha256.Sum256(proof[:])
		result.ChallengeID = hex.EncodeToString(id[:])
		now := s.now().UTC().Truncate(time.Microsecond)
		expires = authorization.ExpiresAt
		if !now.Before(expires) {
			return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO enrollment_challenges
			(deployment_id,id,device_id,signing_key_id,authorization_reference,created_at,expires_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7)`, s.deploymentID, result.ChallengeID, request.DeviceID, keyID, authorization.ID, now, expires)
		if err != nil {
			return result, repositoryUnavailable(err)
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO enrollment_network_challenges
			(deployment_id,challenge_id,bootstrap_id,network_public_key,proof_sha256,sealed_proof)
			VALUES ($1,$2,$3,$4,$5,$6)`, s.deploymentID, result.ChallengeID, authorization.ID, network[:], proofDigest[:], sealed)
		if err != nil {
			return result, repositoryUnavailable(err)
		}
	} else {
		return result, repositoryUnavailable(err)
	}
	result.SchemaVersion = contracts.EnrollmentChallengeV1Version
	result.DeploymentID, result.DeviceID, result.SigningKeyID = s.deploymentID, request.DeviceID, keyID
	result.NetworkPublicKey, result.NetworkChallenge, result.ExpiresAt = request.NetworkPublicKey, base64.StdEncoding.EncodeToString(sealed), expires.UTC().Format(time.RFC3339)
	if err := repositoryCommit(tx); err != nil {
		return contracts.EnrollmentChallengeV1{}, err
	}
	return result, nil
}

func (s *PostgresRepository) AdmitEnrollment(ctx context.Context, token string, request contracts.EnrollmentAdmissionV1) (contracts.EnrollmentAcceptedV1, error) {
	var result contracts.EnrollmentAcceptedV1
	if err := request.Validate(); err != nil {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidPayload}
	}
	public, _ := hex.DecodeString(request.Enrollment.PublicKey)
	if err := request.VerifySignature(ed25519.PublicKey(public)); err != nil {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionInvalidSignature}
	}
	if request.Enrollment.DeploymentID != s.deploymentID {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionDeploymentMismatch}
	}
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return result, err
	}
	defer tx.Rollback()
	authorization, err := s.lockBootstrap(ctx, tx, token, request.Enrollment.DeviceID)
	if err != nil {
		return result, err
	}
	var network, digest []byte
	err = tx.QueryRowContext(ctx, `SELECT network_public_key,proof_sha256 FROM enrollment_network_challenges
		WHERE deployment_id=$1 AND challenge_id=$2 AND bootstrap_id=$3`, s.deploymentID, request.Enrollment.ChallengeID, authorization.ID).Scan(&network, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	if err != nil {
		return result, repositoryUnavailable(err)
	}
	proposed, _ := hex.DecodeString(request.NetworkPublicKey)
	proof, _ := hex.DecodeString(request.NetworkProof)
	proofDigest := sha256.Sum256(proof)
	if !hmac.Equal(network, proposed) || !hmac.Equal(digest, proofDigest[:]) {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionKeyMismatch}
	}
	if err := s.enrollInTransaction(ctx, tx, request.Enrollment); err != nil {
		return result, err
	}
	canonical, _ := request.SigningBytes()
	fingerprint, _ := contracts.EnvelopeRequestSHA256V1(canonical, request.Signature)
	_, err = tx.ExecContext(ctx, `INSERT INTO device_network_bindings
		(deployment_id,device_id,network_public_key,request_sha256) VALUES ($1,$2,$3,$4)`, s.deploymentID, request.Enrollment.DeviceID, network, decodeRepositoryDigest(fingerprint))
	if err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == postgresUniqueViolationSQLState {
			return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionEnrollmentConflict}
		}
		return result, repositoryUnavailable(err)
	}
	now := s.now().UTC()
	if !now.Before(authorization.ExpiresAt) || now.Before(authorization.CreatedAt) {
		return result, &RepositoryRejection{Reason: contracts.EnvelopeRejectionBootstrapInvalid}
	}
	if reason, err := request.Enrollment.EnvelopeHeaderV1.FreshnessRejection(now, contracts.UnenrolledSequenceV1); err != nil {
		return result, err
	} else if reason != "" {
		return result, &RepositoryRejection{Reason: reason}
	}
	_, err = tx.ExecContext(ctx, `UPDATE bootstrap_tokens SET consumed_at=$3 WHERE deployment_id=$1 AND id=$2`, s.deploymentID, authorization.ID, now)
	if err != nil {
		return result, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return result, err
	}
	return contracts.EnrollmentAcceptedV1{SchemaVersion: contracts.EnrollmentAcceptedV1Version, DeploymentID: s.deploymentID, DeviceID: request.Enrollment.DeviceID, SigningKeyID: request.Enrollment.SigningKeyID, NetworkPublicKey: request.NetworkPublicKey, LastSequence: contracts.EnrollmentSequenceV1}, nil
}

type DeviceNetworkBinding struct {
	DeploymentID     string
	DeviceID         string
	SigningKeyID     string
	NetworkPublicKey string
	RequestSHA256    string
	EnrolledAt       time.Time
}

// NetworkBinding returns only a committed binding joined to its signed device.
// The caller must still authorize the actual peer and enforce device revocation.
func (s *PostgresRepository) NetworkBinding(ctx context.Context, deviceID string) (DeviceNetworkBinding, error) {
	var binding DeviceNetworkBinding
	var network, digest []byte
	err := s.db.QueryRowContext(ctx, `SELECT n.deployment_id,n.device_id,d.signing_key_id,n.network_public_key,n.request_sha256,d.enrolled_at FROM device_network_bindings n
		JOIN device_enrollments d USING (deployment_id,device_id)
		WHERE n.deployment_id=$1 AND n.device_id=$2 AND d.revoked_at IS NULL`, s.deploymentID, deviceID).Scan(&binding.DeploymentID, &binding.DeviceID, &binding.SigningKeyID, &network, &digest, &binding.EnrolledAt)
	if err != nil {
		return DeviceNetworkBinding{}, repositoryReadError(err)
	}
	binding.NetworkPublicKey, binding.RequestSHA256 = hex.EncodeToString(network), hex.EncodeToString(digest)
	return binding, nil
}
