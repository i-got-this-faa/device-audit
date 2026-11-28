package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/audit"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// manifestRequestDigest is the identity of a request: policy, expiry and the
// evidence set, with the evidence in a fixed order. Two requests that differ
// only in evidence order are the same request.
func manifestRequestDigest(request contracts.AuditManifestRequestV1) []byte {
	ids := append([]string(nil), request.EvidenceIDs...)
	sort.Strings(ids)
	fields := append([]string{request.PolicyVersion, request.ExpiresAt.UTC().Format(time.RFC3339), strconv.Itoa(len(ids))}, ids...)
	hash := sha256.New()
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		hash.Write(length[:])
		hash.Write([]byte(field))
	}
	return hash.Sum(nil)
}

// CreateAuditManifest signs a canonical manifest over evidence already stored
// by AUD01. The controller re-reads every record and re-checks its digest, then
// signs the exact digests and sizes. A repeat of the same request (evidence in
// any order) returns the stored manifest unchanged, even after the evidence
// retention ends. A manifest ID already used by different content is a
// conflict and nothing is replaced, so a signed identity never names two
// manifests.
func (s *PostgresRepository) CreateAuditManifest(ctx context.Context, request contracts.AuditManifestRequestV1, signer ed25519.PrivateKey, by contracts.ModelActorV1) (contracts.AuditManifestRecordV1, bool, error) {
	now := s.now().UTC()
	if err := by.Validate(); err != nil {
		return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionInvalidRequest
	}
	digest := manifestRequestDigest(request)
	// A stored manifest answers a repeat before anything else is checked, so its
	// identity stays stable after its evidence or lifetime has moved on.
	if request.SchemaVersion == contracts.AuditManifestRequestV1Version && repositoryIDPattern.MatchString(request.ManifestID) {
		if existing, requestDigest, found, err := s.storedAuditManifest(ctx, s.db, request.ManifestID); err != nil {
			return contracts.AuditManifestRecordV1{}, false, err
		} else if found {
			if hex.EncodeToString(requestDigest) != hex.EncodeToString(digest) {
				return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionConflict
			}
			return existing, false, nil
		}
	}
	if err := request.Validate(now); err != nil {
		return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionInvalidRequest
	}

	ids := append([]string(nil), request.EvidenceIDs...)
	sort.Strings(ids)
	created := now.Truncate(time.Second)
	references := make([]contracts.AuditEvidenceReferenceV1, 0, len(ids))
	basis := make([]contracts.AuditManifestBasisV1, 0, len(ids))
	for _, id := range ids {
		meta, content, err := s.AuditEvidenceContent(ctx, id, "")
		if err != nil {
			return contracts.AuditManifestRecordV1{}, false, err
		}
		if !contracts.AuditManifestEvidenceSupportedV1(meta.EvidenceSchemaVersion) {
			return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionIncompatible
		}
		// A reference may not outlast its evidence; round down to whole seconds.
		expiry := meta.RetentionExpiresAt.UTC().Truncate(time.Second)
		if !expiry.After(created) || request.ExpiresAt.After(expiry) {
			return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionOutlivesEvidence
		}
		item, err := s.manifestBasis(ctx, meta, content)
		if err != nil {
			return contracts.AuditManifestRecordV1{}, false, err
		}
		references = append(references, contracts.AuditEvidenceReferenceV1{ReferenceID: id, SchemaVersion: meta.EvidenceSchemaVersion,
			SHA256: meta.SHA256, SizeBytes: meta.SizeBytes, ExpiresAt: expiry.Format(time.RFC3339)})
		basis = append(basis, item)
	}

	// The commitment ID and nonce are independent random values, chosen once.
	var commitmentID, nonce [32]byte
	if _, err := io.ReadFull(s.randomSource(), commitmentID[:]); err != nil {
		return contracts.AuditManifestRecordV1{}, false, repositoryUnavailable(err)
	}
	if _, err := io.ReadFull(s.randomSource(), nonce[:]); err != nil {
		return contracts.AuditManifestRecordV1{}, false, repositoryUnavailable(err)
	}
	manifest, commitment, err := audit.BuildManifest(audit.ManifestSpec{
		DeploymentID: s.deploymentID, ManifestID: request.ManifestID, CommitmentID: hex.EncodeToString(commitmentID[:]),
		BlindingNonce: hex.EncodeToString(nonce[:]), PolicyVersion: request.PolicyVersion, CreatedAt: created,
		ExpiresAt: request.ExpiresAt.UTC(), Evidence: references,
	}, signer)
	if err != nil {
		return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionInvalidRequest
	}
	signing, err := manifest.SigningBytes()
	if err != nil {
		return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionInvalidRequest
	}
	manifestHash, err := contracts.EnvelopeRequestSHA256V1(signing, manifest.Signature)
	if err != nil {
		return contracts.AuditManifestRecordV1{}, false, err
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return contracts.AuditManifestRecordV1{}, false, err
	}

	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.AuditManifestRecordV1{}, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_manifests (deployment_id, manifest_id, commitment_id, commitment_sha256, manifest_sha256,
			request_sha256, policy_version, controller_key_id, manifest, created_at, expires_at, actor_issuer, actor_subject)
		VALUES ($1,$2,decode($3,'hex'),decode($4,'hex'),decode($5,'hex'),$6,$7,$8,$9,$10,$11,$12,$13)`,
		s.deploymentID, request.ManifestID, manifest.CommitmentID, commitment.CommitmentSHA256, manifestHash, digest, request.PolicyVersion,
		manifest.ControllerKeyID, string(manifestJSON), created, request.ExpiresAt.UTC(), by.Issuer, by.Subject); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == postgresUniqueViolationSQLState {
			tx.Rollback()
			// A concurrent request created it: an identical one is a repeat.
			existing, requestDigest, found, rerr := s.storedAuditManifest(ctx, s.db, request.ManifestID)
			if rerr != nil {
				return contracts.AuditManifestRecordV1{}, false, rerr
			}
			if found && hex.EncodeToString(requestDigest) == hex.EncodeToString(digest) {
				return existing, false, nil
			}
			return contracts.AuditManifestRecordV1{}, false, contracts.AuditManifestRejectionConflict
		}
		return contracts.AuditManifestRecordV1{}, false, repositoryUnavailable(err)
	}
	for _, item := range basis {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_manifest_evidence (deployment_id, manifest_id, reference_id, kind, device_id, schema_version,
				sha256, size_bytes, model_version, model_sha256, methodology_version)
			VALUES ($1,$2,$3,$4,$5,$6,decode($7,'hex'),$8,$9,decode($10,'hex'),$11)`,
			s.deploymentID, request.ManifestID, item.ReferenceID, string(item.Kind), item.DeviceID, item.EvidenceSchemaVersion, item.SHA256,
			int64(item.SizeBytes), item.ModelVersion, item.ModelSHA256, item.MethodologyVersion); err != nil {
			return contracts.AuditManifestRecordV1{}, false, repositoryUnavailable(err)
		}
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.AuditManifestRecordV1{}, false, err
	}
	record, _, _, err := s.storedAuditManifest(ctx, s.db, request.ManifestID)
	return record, true, err
}

func (s *PostgresRepository) randomSource() io.Reader {
	if s.manifestRandom != nil {
		return s.manifestRandom
	}
	return rand.Reader
}

// manifestBasis reads the versions behind one stored evidence record. The
// model and methodology come from the stored bytes and their durable source,
// never from the caller.
func (s *PostgresRepository) manifestBasis(ctx context.Context, meta contracts.AuditEvidenceV1, content []byte) (contracts.AuditManifestBasisV1, error) {
	item := contracts.AuditManifestBasisV1{ReferenceID: meta.EvidenceID, Kind: meta.Kind, DeviceID: meta.DeviceID,
		EvidenceSchemaVersion: meta.EvidenceSchemaVersion, SHA256: meta.SHA256, SizeBytes: meta.SizeBytes}
	_, id, _ := strings.Cut(meta.SourceReference, ":")
	switch meta.Kind {
	case contracts.AuditEvidenceTelemetry:
		var envelope contracts.EvidenceEnvelopeV1
		if json.Unmarshal(content, &envelope) != nil || envelope.PayloadSchemaVersion == "" {
			return item, contracts.AuditEvidenceRejectionUnavailable
		}
		item.MethodologyVersion = envelope.PayloadSchemaVersion
	case contracts.AuditEvidencePrediction:
		var prediction contracts.PredictionV2
		if json.Unmarshal(content, &prediction) != nil {
			return item, contracts.AuditEvidenceRejectionUnavailable
		}
		if prediction.Model != nil {
			version, digest := prediction.Model.Version, prediction.Model.SHA256
			item.ModelVersion, item.ModelSHA256 = &version, &digest
		}
		predictionID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return item, contracts.AuditEvidenceRejectionUnavailable
		}
		if err := s.db.QueryRowContext(ctx, `SELECT rules_version FROM device_predictions WHERE deployment_id=$1 AND id=$2`,
			s.deploymentID, predictionID).Scan(&item.MethodologyVersion); err != nil {
			return item, repositoryReadError(err)
		}
	case contracts.AuditEvidenceDiagnostic:
		if err := s.db.QueryRowContext(ctx, `SELECT probe_id FROM diagnostic_assignments WHERE deployment_id=$1 AND assignment_id=$2`,
			s.deploymentID, id).Scan(&item.MethodologyVersion); err != nil {
			return item, repositoryReadError(err)
		}
	default:
		return item, contracts.AuditManifestRejectionIncompatible
	}
	return item, nil
}

// AuditManifest returns one stored manifest, after re-checking that its signed
// content still produces the stored digests.
func (s *PostgresRepository) AuditManifest(ctx context.Context, manifestID string) (contracts.AuditManifestRecordV1, error) {
	if !repositoryIDPattern.MatchString(manifestID) {
		return contracts.AuditManifestRecordV1{}, contracts.AuditManifestRejectionNotFound
	}
	record, _, found, err := s.storedAuditManifest(ctx, s.db, manifestID)
	if err != nil {
		return contracts.AuditManifestRecordV1{}, err
	}
	if !found {
		return contracts.AuditManifestRecordV1{}, contracts.AuditManifestRejectionNotFound
	}
	return record, nil
}

func (s *PostgresRepository) storedAuditManifest(ctx context.Context, q dbQueryer, manifestID string) (contracts.AuditManifestRecordV1, []byte, bool, error) {
	record := contracts.AuditManifestRecordV1{SchemaVersion: contracts.AuditManifestRecordV1Version, DeploymentID: s.deploymentID, ManifestID: manifestID}
	var commitmentSHA, manifestSHA, requestSHA []byte
	var manifestJSON []byte
	err := q.QueryRowContext(ctx, `SELECT commitment_sha256, manifest_sha256, request_sha256, manifest, created_at, actor_issuer, actor_subject
		FROM audit_manifests WHERE deployment_id=$1 AND manifest_id=$2`, s.deploymentID, manifestID).
		Scan(&commitmentSHA, &manifestSHA, &requestSHA, &manifestJSON, &record.CreatedAt, &record.CreatedBy.Issuer, &record.CreatedBy.Subject)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AuditManifestRecordV1{}, nil, false, nil
	}
	if err != nil {
		return contracts.AuditManifestRecordV1{}, nil, false, repositoryUnavailable(err)
	}
	record.CreatedAt = record.CreatedAt.UTC()
	if json.Unmarshal(manifestJSON, &record.Manifest) != nil || record.Manifest.ManifestID != manifestID || record.Manifest.DeploymentID != s.deploymentID {
		return contracts.AuditManifestRecordV1{}, nil, false, contracts.AuditManifestRejectionUnavailable
	}
	signing, err := record.Manifest.SigningBytes()
	if err != nil {
		return contracts.AuditManifestRecordV1{}, nil, false, contracts.AuditManifestRejectionUnavailable
	}
	manifestHash, err := contracts.EnvelopeRequestSHA256V1(signing, record.Manifest.Signature)
	if err != nil || manifestHash != hex.EncodeToString(manifestSHA) {
		return contracts.AuditManifestRecordV1{}, nil, false, contracts.AuditManifestRejectionUnavailable
	}
	if record.Commitment, err = record.Manifest.Commitment(); err != nil || record.Commitment.CommitmentSHA256 != hex.EncodeToString(commitmentSHA) {
		return contracts.AuditManifestRecordV1{}, nil, false, contracts.AuditManifestRejectionUnavailable
	}
	record.ManifestSHA256 = manifestHash

	rows, err := q.QueryContext(ctx, `SELECT reference_id, kind, device_id, schema_version, sha256, size_bytes, model_version, model_sha256, methodology_version
		FROM audit_manifest_evidence WHERE deployment_id=$1 AND manifest_id=$2 ORDER BY reference_id`, s.deploymentID, manifestID)
	if err != nil {
		return contracts.AuditManifestRecordV1{}, nil, false, repositoryUnavailable(err)
	}
	defer rows.Close()
	record.Basis = []contracts.AuditManifestBasisV1{}
	for rows.Next() {
		var item contracts.AuditManifestBasisV1
		var kind string
		var digest, modelDigest []byte
		var size int64
		var modelVersion sql.NullString
		if err := rows.Scan(&item.ReferenceID, &kind, &item.DeviceID, &item.EvidenceSchemaVersion, &digest, &size, &modelVersion, &modelDigest, &item.MethodologyVersion); err != nil {
			return contracts.AuditManifestRecordV1{}, nil, false, repositoryUnavailable(err)
		}
		item.Kind, item.SHA256, item.SizeBytes = contracts.AuditEvidenceKindV1(kind), hex.EncodeToString(digest), uint32(size)
		if modelVersion.Valid {
			version, modelHex := modelVersion.String, hex.EncodeToString(modelDigest)
			item.ModelVersion, item.ModelSHA256 = &version, &modelHex
		}
		record.Basis = append(record.Basis, item)
	}
	if err := rows.Err(); err != nil {
		return contracts.AuditManifestRecordV1{}, nil, false, repositoryUnavailable(err)
	}
	// The signed references and the stored basis must describe the same evidence.
	if len(record.Basis) != len(record.Manifest.Evidence) {
		return contracts.AuditManifestRecordV1{}, nil, false, contracts.AuditManifestRejectionUnavailable
	}
	for i, reference := range record.Manifest.Evidence {
		item := record.Basis[i]
		if item.ReferenceID != reference.ReferenceID || item.EvidenceSchemaVersion != reference.SchemaVersion || item.SHA256 != reference.SHA256 || item.SizeBytes != reference.SizeBytes {
			return contracts.AuditManifestRecordV1{}, nil, false, contracts.AuditManifestRejectionUnavailable
		}
	}
	return record, requestSHA, true, nil
}

// AuditManifestService serves signed audit manifests to administrators. It
// holds the controller audit application key, which is separate from the
// device, diagnostic, acknowledgement and chain keys.
type AuditManifestService struct {
	repository *PostgresRepository
	auth       *auth.Service
	signer     ed25519.PrivateKey
}

func NewAuditManifestService(repository *PostgresRepository, consoleAuth *auth.Service, signer ed25519.PrivateKey) (*AuditManifestService, error) {
	if repository == nil || consoleAuth == nil || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("audit manifests require a repository, console authentication and an Ed25519 signing key")
	}
	return &AuditManifestService{repository: repository, auth: consoleAuth, signer: signer}, nil
}

func (s *AuditManifestService) Register(mux *http.ServeMux) {
	mux.Handle("POST /console/api/audit-manifests", s.auth.RequireFreshAdmin(http.HandlerFunc(s.create)))
	mux.Handle("GET /console/api/audit-manifests/{id}", s.auth.RequireRole(auth.RoleAdmin, http.HandlerFunc(s.get)))
	mux.Handle("GET /console/api/audit-manifests/{id}/verification", s.auth.RequireRole(auth.RoleAdmin, http.HandlerFunc(s.verify)))
	mux.Handle("GET /console/api/audit-manifests/{id}/commitment", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.commitment)))
}

func auditManifestStatus(err error) (int, string) {
	var manifestRejection contracts.AuditManifestRejection
	if errors.As(err, &manifestRejection) {
		switch manifestRejection {
		case contracts.AuditManifestRejectionNotFound:
			return http.StatusNotFound, string(manifestRejection)
		case contracts.AuditManifestRejectionConflict, contracts.AuditManifestRejectionIncompatible:
			return http.StatusConflict, string(manifestRejection)
		case contracts.AuditManifestRejectionUnavailable:
			return http.StatusInternalServerError, string(manifestRejection)
		}
		return http.StatusBadRequest, string(manifestRejection)
	}
	return auditEvidenceStatus(err)
}

func (s *AuditManifestService) create(w http.ResponseWriter, r *http.Request) {
	invalid := func() {
		http.Error(w, string(contracts.AuditManifestRejectionInvalidRequest), http.StatusBadRequest)
	}
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		invalid()
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	var request contracts.AuditManifestRequestV1
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&request); err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, string(contracts.AuditEvidenceRejectionTooLarge), http.StatusRequestEntityTooLarge)
			return
		}
		invalid()
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		invalid()
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	record, created, err := s.repository.CreateAuditManifest(r.Context(), request, s.signer, actor)
	if err != nil {
		status, text := auditManifestStatus(err)
		http.Error(w, text, status)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, status, record)
}

func (s *AuditManifestService) get(w http.ResponseWriter, r *http.Request) {
	record, err := s.repository.AuditManifest(r.Context(), r.PathValue("id"))
	if err != nil {
		status, text := auditManifestStatus(err)
		http.Error(w, text, status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, record)
}

// commitment returns only the public commitment, which carries no nonce.
func (s *AuditManifestService) commitment(w http.ResponseWriter, r *http.Request) {
	record, err := s.repository.AuditManifest(r.Context(), r.PathValue("id"))
	if err != nil {
		status, text := auditManifestStatus(err)
		http.Error(w, text, status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, record.Commitment)
}

// VerifyAuditManifest recomputes the verification of one stored manifest from
// the raw rows, trusting no stored digest or verdict: the manifest signature
// under auditKey, its commitment, every referenced record's retention, schema,
// digest and size, the versions recorded when it was signed, and each device
// signature under the key enrolled for it. Nothing is written. The result
// establishes integrity only, never the truthfulness of the endpoint.
func (s *PostgresRepository) VerifyAuditManifest(ctx context.Context, manifestID string, auditKey ed25519.PublicKey) (contracts.AuditManifestVerificationV1, error) {
	if !repositoryIDPattern.MatchString(manifestID) {
		return contracts.AuditManifestVerificationV1{}, contracts.AuditManifestRejectionNotFound
	}
	var commitmentID, commitmentSHA, manifestJSON []byte
	err := s.db.QueryRowContext(ctx, `SELECT commitment_id, commitment_sha256, manifest FROM audit_manifests WHERE deployment_id=$1 AND manifest_id=$2`,
		s.deploymentID, manifestID).Scan(&commitmentID, &commitmentSHA, &manifestJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return contracts.AuditManifestVerificationV1{}, contracts.AuditManifestRejectionNotFound
	}
	if err != nil {
		return contracts.AuditManifestVerificationV1{}, repositoryUnavailable(err)
	}
	var manifest contracts.AuditManifestV1
	if json.Unmarshal(manifestJSON, &manifest) != nil {
		return contracts.AuditManifestVerificationV1{}, contracts.AuditManifestRejectionUnavailable
	}
	input := audit.VerifyInput{Manifest: &manifest, AuditKey: auditKey, Now: s.now().UTC(),
		Commitment: contracts.AuditCommitmentV1{SchemaVersion: contracts.AuditCommitmentV1Version, CommitmentID: hex.EncodeToString(commitmentID), CommitmentSHA256: hex.EncodeToString(commitmentSHA)},
		Evidence:   map[string]audit.Evidence{}, Bindings: map[string]audit.Binding{}}
	if manifest.Validate() != nil {
		return contracts.AuditManifestVerificationV1{}, contracts.AuditManifestRejectionUnavailable
	}
	for _, reference := range manifest.Evidence {
		var stored audit.Evidence
		err := s.db.QueryRowContext(ctx, `SELECT schema_version, content, retention_expires_at FROM audit_evidence WHERE deployment_id=$1 AND evidence_id=$2`,
			s.deploymentID, reference.ReferenceID).Scan(&stored.SchemaVersion, &stored.Content, &stored.RetentionEndsAt)
		switch {
		case err == nil:
			stored.Found, stored.RetentionEndsAt = true, stored.RetentionEndsAt.UTC()
			input.Evidence[reference.ReferenceID] = stored
		case !errors.Is(err, sql.ErrNoRows):
			return contracts.AuditManifestVerificationV1{}, repositoryUnavailable(err)
		}
		var binding audit.Binding
		var modelVersion sql.NullString
		var modelDigest []byte
		err = s.db.QueryRowContext(ctx, `SELECT model_version, model_sha256, methodology_version FROM audit_manifest_evidence
			WHERE deployment_id=$1 AND manifest_id=$2 AND reference_id=$3`, s.deploymentID, manifestID, reference.ReferenceID).
			Scan(&modelVersion, &modelDigest, &binding.MethodologyVersion)
		switch {
		case err == nil:
			if modelVersion.Valid {
				version, digest := modelVersion.String, hex.EncodeToString(modelDigest)
				binding.ModelVersion, binding.ModelSHA256 = &version, &digest
			}
			input.Bindings[reference.ReferenceID] = binding
		case !errors.Is(err, sql.ErrNoRows):
			return contracts.AuditManifestVerificationV1{}, repositoryUnavailable(err)
		}
	}
	var lookupErr error
	input.DeviceKey = func(deviceID, signingKeyID string) (ed25519.PublicKey, bool) {
		var key []byte
		err := s.db.QueryRowContext(ctx, `SELECT public_key FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2 AND signing_key_id=$3`,
			s.deploymentID, deviceID, signingKeyID).Scan(&key)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			lookupErr = repositoryUnavailable(err)
		}
		return ed25519.PublicKey(key), err == nil && len(key) == ed25519.PublicKeySize
	}
	input.Assignment = func(assignmentID string) (contracts.DiagnosticAssignmentV1, bool) {
		var signed []byte
		err := s.db.QueryRowContext(ctx, `SELECT signed_assignment FROM diagnostic_assignments WHERE deployment_id=$1 AND assignment_id=$2`,
			s.deploymentID, assignmentID).Scan(&signed)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			lookupErr = repositoryUnavailable(err)
		}
		var assignment contracts.DiagnosticAssignmentV1
		return assignment, err == nil && json.Unmarshal(signed, &assignment) == nil
	}
	report, err := audit.VerifyManifest(input)
	if err == nil {
		err = lookupErr
	}
	if err != nil {
		var rejection contracts.AuditManifestRejection
		if errors.As(err, &rejection) || errors.Is(err, ErrRepositoryUnavailable) {
			return contracts.AuditManifestVerificationV1{}, err
		}
		return contracts.AuditManifestVerificationV1{}, contracts.AuditManifestRejectionUnavailable
	}
	return report, nil
}

func (s *AuditManifestService) verify(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, string(contracts.AuditManifestRejectionInvalidRequest), http.StatusBadRequest)
		return
	}
	report, err := s.repository.VerifyAuditManifest(r.Context(), r.PathValue("id"), s.signer.Public().(ed25519.PublicKey))
	if err != nil {
		status, text := auditManifestStatus(err)
		http.Error(w, text, status)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, report)
}
