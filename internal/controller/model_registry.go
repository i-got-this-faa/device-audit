package controller

import (
	"context"
	"crypto/ed25519"
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
	"reflect"
	"slices"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrModelArtifactCorrupt means stored bytes no longer match their signed
// digest. They are never served.
var ErrModelArtifactCorrupt = errors.New("stored model artifact failed its digest check")

// PutModelArtifact admits one signed upload. created is false when the same
// manifest and bytes are already stored. Any other upload under a stored
// version or digest is a version_conflict; nothing is replaced.
func (s *PostgresRepository) PutModelArtifact(ctx context.Context, upload contracts.ModelArtifactUploadV1, publisherKey ed25519.PublicKey, actor contracts.ModelActorV1) (record contracts.ModelArtifactV1, created bool, err error) {
	if err := upload.Verify(publisherKey); err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	if err := actor.Validate(); err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	manifest, err := json.Marshal(upload.Manifest)
	if err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	digest, _ := hex.DecodeString(upload.Manifest.ArtifactSHA256)
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO model_artifacts (deployment_id, model_version, artifact_sha256, manifest, artifact,
		source_reference, uploaded_at, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT DO NOTHING`,
		s.deploymentID, upload.Manifest.ModelVersion, digest, manifest, upload.Artifact, upload.SourceReference,
		s.now().UTC().Truncate(time.Microsecond), actor.Issuer, actor.Subject)
	if err != nil {
		return contracts.ModelArtifactV1{}, false, repositoryUnavailable(err)
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return contracts.ModelArtifactV1{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	record, err = s.ModelArtifact(ctx, upload.Manifest.ModelVersion)
	if inserted == 1 || err != nil && !errors.Is(err, ErrRepositoryNotFound) {
		return record, inserted == 1, err
	}
	// The version or the digest is already stored. Only the identical upload
	// is a repeat; the source reference and uploader stay as first recorded.
	if err == nil && reflect.DeepEqual(record.Manifest, upload.Manifest) {
		return record, false, nil
	}
	return contracts.ModelArtifactV1{}, false, contracts.ModelRejectionVersionConflict
}

// ModelArtifact returns one stored entry with its approval, without the bytes.
func (s *PostgresRepository) ModelArtifact(ctx context.Context, version string) (contracts.ModelArtifactV1, error) {
	return s.modelArtifact(ctx, s.db, version)
}

func (s *PostgresRepository) modelArtifact(ctx context.Context, q dbQueryer, version string) (contracts.ModelArtifactV1, error) {
	if !repositoryIDPattern.MatchString(version) {
		return contracts.ModelArtifactV1{}, ErrRepositoryNotFound
	}
	record := contracts.ModelArtifactV1{SchemaVersion: contracts.ModelArtifactV1Version, DeploymentID: s.deploymentID}
	var manifest []byte
	var evaluation []byte
	var policy, approverIssuer, approverSubject sql.NullString
	var approvedAt sql.NullTime
	err := q.QueryRowContext(ctx, `SELECT a.manifest, octet_length(a.artifact), a.source_reference, a.uploaded_at, a.actor_issuer, a.actor_subject,
		p.evaluation_sha256, p.policy_version, p.approved_at, p.actor_issuer, p.actor_subject
		FROM model_artifacts a LEFT JOIN model_approvals p USING (deployment_id, model_version, artifact_sha256)
		WHERE a.deployment_id=$1 AND a.model_version=$2`, s.deploymentID, version).
		Scan(&manifest, &record.ArtifactByteSize, &record.SourceReference, &record.UploadedAt, &record.UploadedBy.Issuer, &record.UploadedBy.Subject,
			&evaluation, &policy, &approvedAt, &approverIssuer, &approverSubject)
	if err != nil {
		return contracts.ModelArtifactV1{}, repositoryReadError(err)
	}
	if err := json.Unmarshal(manifest, &record.Manifest); err != nil {
		return contracts.ModelArtifactV1{}, repositoryUnavailable(fmt.Errorf("stored manifest %s: %w", version, err))
	}
	record.UploadedAt = record.UploadedAt.UTC()
	if approvedAt.Valid {
		record.Approval = &contracts.ModelApprovalV1{EvaluationSHA256: hex.EncodeToString(evaluation), PolicyVersion: policy.String,
			ApprovedAt: approvedAt.Time.UTC(), ApprovedBy: contracts.ModelActorV1{Issuer: approverIssuer.String, Subject: approverSubject.String}}
	}
	return record, nil
}

// ModelArtifactBytes returns the stored bytes after checking them against the
// signed digest, so bytes changed at rest are refused rather than served.
func (s *PostgresRepository) ModelArtifactBytes(ctx context.Context, version string) (contracts.ModelManifestV1, []byte, error) {
	return s.modelArtifactBytes(ctx, s.db, version)
}

func (s *PostgresRepository) modelArtifactBytes(ctx context.Context, q dbQueryer, version string) (contracts.ModelManifestV1, []byte, error) {
	if !repositoryIDPattern.MatchString(version) {
		return contracts.ModelManifestV1{}, nil, ErrRepositoryNotFound
	}
	var manifestJSON, artifact []byte
	if err := q.QueryRowContext(ctx, `SELECT manifest, artifact FROM model_artifacts WHERE deployment_id=$1 AND model_version=$2`,
		s.deploymentID, version).Scan(&manifestJSON, &artifact); err != nil {
		return contracts.ModelManifestV1{}, nil, repositoryReadError(err)
	}
	var manifest contracts.ModelManifestV1
	if err := json.Unmarshal(manifestJSON, &manifest); err != nil {
		return contracts.ModelManifestV1{}, nil, repositoryUnavailable(fmt.Errorf("stored manifest %s: %w", version, err))
	}
	if sum := sha256.Sum256(artifact); hex.EncodeToString(sum[:]) != manifest.ArtifactSHA256 {
		return contracts.ModelManifestV1{}, nil, ErrModelArtifactCorrupt
	}
	return manifest, artifact, nil
}

// ApproveModel records the one approval an artifact can have. created is false
// for a repeat of the stored approval; a different one is a version_conflict.
func (s *PostgresRepository) ApproveModel(ctx context.Context, request contracts.ModelApprovalRequestV1, actor contracts.ModelActorV1) (contracts.ModelArtifactV1, bool, error) {
	if err := request.Validate(); err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	if err := actor.Validate(); err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	record, err := s.ModelArtifact(ctx, request.ModelVersion)
	if err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	if record.Manifest.ArtifactSHA256 != request.ArtifactSHA256 {
		return contracts.ModelArtifactV1{}, false, contracts.ModelRejectionReferenceMismatch
	}
	if a := record.Approval; a != nil {
		if a.EvaluationSHA256 == request.EvaluationSHA256 && a.PolicyVersion == request.PolicyVersion {
			return record, false, nil
		}
		return contracts.ModelArtifactV1{}, false, contracts.ModelRejectionVersionConflict
	}
	digest, _ := hex.DecodeString(request.ArtifactSHA256)
	evaluation, _ := hex.DecodeString(request.EvaluationSHA256)
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO model_approvals (deployment_id, model_version, artifact_sha256, evaluation_sha256,
		policy_version, approved_at, actor_issuer, actor_subject) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		s.deploymentID, request.ModelVersion, digest, evaluation, request.PolicyVersion, s.now().UTC().Truncate(time.Microsecond),
		actor.Issuer, actor.Subject); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == postgresUniqueViolationSQLState {
			// A concurrent approval won; report it as a repeat or a conflict.
			return s.ApproveModel(ctx, request, actor)
		}
		return contracts.ModelArtifactV1{}, false, repositoryUnavailable(err)
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.ModelArtifactV1{}, false, err
	}
	record, err = s.ModelArtifact(ctx, request.ModelVersion)
	return record, err == nil, err
}

// SetModelReference points one slot at a stored artifact. Activation needs an
// approval and the inference purpose; activating the candidate clears it.
// A refusal leaves both slots unchanged.
func (s *PostgresRepository) SetModelReference(ctx context.Context, slot contracts.ModelSlotV1, request contracts.ModelReferenceRequestV1, actor contracts.ModelActorV1) (contracts.ModelReferencesV1, error) {
	if slot != contracts.ModelSlotActive && slot != contracts.ModelSlotCandidate {
		return contracts.ModelReferencesV1{}, contracts.ModelRejectionInvalidRequest
	}
	if err := request.Validate(); err != nil {
		return contracts.ModelReferencesV1{}, err
	}
	if err := actor.Validate(); err != nil {
		return contracts.ModelReferencesV1{}, err
	}
	record, err := s.ModelArtifact(ctx, request.ModelVersion)
	if err != nil {
		return contracts.ModelReferencesV1{}, err
	}
	if record.Manifest.ArtifactSHA256 != request.ArtifactSHA256 {
		return contracts.ModelReferencesV1{}, contracts.ModelRejectionReferenceMismatch
	}
	if slot == contracts.ModelSlotActive {
		if record.Approval == nil {
			return contracts.ModelReferencesV1{}, contracts.ModelRejectionNotApproved
		}
		if !slices.Contains(record.Manifest.Purposes, contracts.ModelPurposeInference) {
			return contracts.ModelReferencesV1{}, contracts.ModelRejectionPurposeUnsupported
		}
	}
	digest, _ := hex.DecodeString(request.ArtifactSHA256)
	tx, err := s.beginWrite(ctx)
	if err != nil {
		return contracts.ModelReferencesV1{}, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO model_references (deployment_id, slot, model_version, artifact_sha256, set_at, actor_issuer, actor_subject)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (deployment_id, slot) DO UPDATE SET model_version=EXCLUDED.model_version,
		artifact_sha256=EXCLUDED.artifact_sha256, set_at=EXCLUDED.set_at, actor_issuer=EXCLUDED.actor_issuer, actor_subject=EXCLUDED.actor_subject`,
		s.deploymentID, string(slot), request.ModelVersion, digest, s.now().UTC().Truncate(time.Microsecond), actor.Issuer, actor.Subject); err != nil {
		return contracts.ModelReferencesV1{}, repositoryUnavailable(err)
	}
	if slot == contracts.ModelSlotActive {
		if _, err := tx.ExecContext(ctx, `DELETE FROM model_references WHERE deployment_id=$1 AND slot='candidate' AND model_version=$2`,
			s.deploymentID, request.ModelVersion); err != nil {
			return contracts.ModelReferencesV1{}, repositoryUnavailable(err)
		}
	}
	if err := repositoryCommit(tx); err != nil {
		return contracts.ModelReferencesV1{}, err
	}
	return s.ModelReferences(ctx)
}

// ModelReferences returns both slots; an unset slot is null.
func (s *PostgresRepository) ModelReferences(ctx context.Context) (contracts.ModelReferencesV1, error) {
	return s.modelReferences(ctx, s.db)
}

func (s *PostgresRepository) modelReferences(ctx context.Context, q dbQueryer) (contracts.ModelReferencesV1, error) {
	refs := contracts.ModelReferencesV1{SchemaVersion: contracts.ModelReferencesV1Version, DeploymentID: s.deploymentID}
	rows, err := q.QueryContext(ctx, `SELECT slot, model_version, artifact_sha256, set_at, actor_issuer, actor_subject
		FROM model_references WHERE deployment_id=$1`, s.deploymentID)
	if err != nil {
		return contracts.ModelReferencesV1{}, repositoryUnavailable(err)
	}
	defer rows.Close()
	for rows.Next() {
		var slot string
		var digest []byte
		var ref contracts.ModelReferenceV1
		if err := rows.Scan(&slot, &ref.ModelVersion, &digest, &ref.SetAt, &ref.SetBy.Issuer, &ref.SetBy.Subject); err != nil {
			return contracts.ModelReferencesV1{}, repositoryUnavailable(err)
		}
		ref.ArtifactSHA256, ref.SetAt = hex.EncodeToString(digest), ref.SetAt.UTC()
		if contracts.ModelSlotV1(slot) == contracts.ModelSlotActive {
			refs.Active = &ref
		} else {
			refs.Candidate = &ref
		}
	}
	if err := rows.Err(); err != nil {
		return contracts.ModelReferencesV1{}, repositoryUnavailable(err)
	}
	return refs, nil
}

// ModelRegistryService exposes the registry to console administrators. Writes
// need a fresh administrator; artifact bytes need an administrator; metadata
// needs a viewer. Uploads must verify against the configured publisher key.
type ModelRegistryService struct {
	repository   *PostgresRepository
	auth         *auth.Service
	publisherKey ed25519.PublicKey
}

func NewModelRegistryService(repository *PostgresRepository, consoleAuth *auth.Service, publisherKey ed25519.PublicKey) (*ModelRegistryService, error) {
	if repository == nil || consoleAuth == nil || len(publisherKey) != ed25519.PublicKeySize {
		return nil, errors.New("the model registry requires a durable repository, console authentication and an Ed25519 publisher key")
	}
	return &ModelRegistryService{repository: repository, auth: consoleAuth, publisherKey: publisherKey}, nil
}

func (s *ModelRegistryService) Register(mux *http.ServeMux) {
	mux.Handle("POST /console/api/models", s.auth.RequireFreshAdmin(http.HandlerFunc(s.upload)))
	mux.Handle("GET /console/api/models/{version}", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.artifact)))
	mux.Handle("GET /console/api/models/{version}/artifact", s.auth.RequireRole(auth.RoleAdmin, http.HandlerFunc(s.download)))
	mux.Handle("POST /console/api/models/{version}/approval", s.auth.RequireFreshAdmin(http.HandlerFunc(s.approve)))
	mux.Handle("GET /console/api/model-references", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.references)))
	mux.Handle("PUT /console/api/model-references/{slot}", s.auth.RequireFreshAdmin(http.HandlerFunc(s.setReference)))
}

// modelRequestLimit fits a base64 artifact at the size budget plus its manifest.
const modelRequestLimit = contracts.ModelArtifactMaxBytesV1/3*4 + 64<<10

// decodeModelRequest reads exactly one JSON object into target. The decoder
// applies each contract type's strict UnmarshalJSON.
func decodeModelRequest(w http.ResponseWriter, r *http.Request, limit int64, target any) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, string(contracts.ModelRejectionInvalidRequest), http.StatusBadRequest)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, string(contracts.ModelRejectionArtifactTooLarge), http.StatusRequestEntityTooLarge)
			return false
		}
		http.Error(w, string(contracts.ModelRejectionInvalidRequest), http.StatusBadRequest)
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		http.Error(w, string(contracts.ModelRejectionInvalidRequest), http.StatusBadRequest)
		return false
	}
	return true
}

func sessionActor(w http.ResponseWriter, r *http.Request) (contracts.ModelActorV1, bool) {
	issuer, subject, ok := auth.SessionIdentity(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
	}
	return contracts.ModelActorV1{Issuer: issuer, Subject: subject}, ok
}

func (s *ModelRegistryService) upload(w http.ResponseWriter, r *http.Request) {
	var upload contracts.ModelArtifactUploadV1
	if !decodeModelRequest(w, r, modelRequestLimit, &upload) {
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	record, created, err := s.repository.PutModelArtifact(r.Context(), upload, s.publisherKey, actor)
	writeModelResult(w, record, created, err)
}

func (s *ModelRegistryService) artifact(w http.ResponseWriter, r *http.Request) {
	record, err := s.repository.ModelArtifact(r.Context(), r.PathValue("version"))
	writeModelResult(w, record, false, err)
}

func (s *ModelRegistryService) download(w http.ResponseWriter, r *http.Request) {
	manifest, artifact, err := s.repository.ModelArtifactBytes(r.Context(), r.PathValue("version"))
	if err != nil {
		writeModelResult(w, nil, false, err)
		return
	}
	digest, _ := hex.DecodeString(manifest.ArtifactSHA256)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Repr-Digest", "sha-256=:"+base64.StdEncoding.EncodeToString(digest)+":")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact)
}

func (s *ModelRegistryService) approve(w http.ResponseWriter, r *http.Request) {
	var request contracts.ModelApprovalRequestV1
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
	record, created, err := s.repository.ApproveModel(r.Context(), request, actor)
	writeModelResult(w, record, created, err)
}

func (s *ModelRegistryService) references(w http.ResponseWriter, r *http.Request) {
	refs, err := s.repository.ModelReferences(r.Context())
	writeModelResult(w, refs, false, err)
}

func (s *ModelRegistryService) setReference(w http.ResponseWriter, r *http.Request) {
	var request contracts.ModelReferenceRequestV1
	if !decodeModelRequest(w, r, 16<<10, &request) {
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	refs, err := s.repository.SetModelReference(r.Context(), contracts.ModelSlotV1(r.PathValue("slot")), request, actor)
	writeModelResult(w, refs, false, err)
}

// writeModelResult answers with the value, or with the stable refusal code.
func writeModelResult(w http.ResponseWriter, value any, created bool, err error) {
	var rejection contracts.ModelRejection
	switch {
	case err == nil && created:
		writeJSON(w, http.StatusCreated, value)
	case err == nil:
		writeJSON(w, http.StatusOK, value)
	case errors.Is(err, ErrRepositoryNotFound):
		http.Error(w, "model artifact not found", http.StatusNotFound)
	case errors.As(err, &rejection):
		http.Error(w, string(rejection), modelRejectionStatus(rejection))
	case errors.Is(err, ErrModelArtifactCorrupt):
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		// Includes an uncertain COMMIT: repeat the request to learn the outcome.
		http.Error(w, "model registry unavailable; repeat the request to confirm the outcome", http.StatusServiceUnavailable)
	}
}

func modelRejectionStatus(rejection contracts.ModelRejection) int {
	switch rejection {
	case contracts.ModelRejectionKeyMismatch, contracts.ModelRejectionInvalidSignature:
		// The artifact is not from the trusted publisher.
		return http.StatusForbidden
	case contracts.ModelRejectionVersionConflict, contracts.ModelRejectionNotApproved, contracts.ModelRejectionReferenceMismatch:
		return http.StatusConflict
	case contracts.ModelRejectionArtifactTooLarge:
		return http.StatusRequestEntityTooLarge
	case contracts.ModelRejectionDigestMismatch, contracts.ModelRejectionPurposeUnsupported:
		return http.StatusUnprocessableEntity
	default:
		return http.StatusBadRequest
	}
}
