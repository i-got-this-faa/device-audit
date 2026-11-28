package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type ModelDownloadRepository interface {
	ApprovedModelDownload(ctx context.Context, deployment, digest string) (contracts.ModelDownloadV1, []byte, error)
}

// ApprovedModelDownload reads a single registry snapshot. An empty digest
// requests metadata only, so that part of the exchange never loads the bytes.
func (s *PostgresRepository) ApprovedModelDownload(ctx context.Context, deployment, digest string) (contracts.ModelDownloadV1, []byte, error) {
	var metadata contracts.ModelDownloadV1
	if deployment != s.deploymentID {
		return metadata, nil, ErrRepositoryNotFound
	}
	var requested []byte
	if digest != "" {
		if !evaluationSHA256Pattern.MatchString(digest) {
			return metadata, nil, contracts.ModelRejectionInvalidRequest
		}
		requested, _ = hex.DecodeString(digest)
	}
	var manifest, activeDigest, evaluation, artifact []byte
	var version string
	err := s.db.QueryRowContext(ctx, `
		SELECT r.model_version, r.artifact_sha256, p.evaluation_sha256, a.manifest,
			octet_length(a.artifact), CASE WHEN $2::bytea IS NOT NULL THEN a.artifact END
		FROM model_references r
		JOIN model_artifacts a USING (deployment_id, model_version, artifact_sha256)
		JOIN model_approvals p USING (deployment_id, model_version, artifact_sha256)
		JOIN model_evaluations e USING (deployment_id, model_version, artifact_sha256, evaluation_sha256)
		JOIN model_promotions d USING (deployment_id, model_version, artifact_sha256, evaluation_sha256)
		WHERE r.deployment_id=$1 AND r.slot='active' AND e.verdict='pass' AND d.outcome='promoted'
			AND ($2::bytea IS NULL OR r.artifact_sha256=$2)`, deployment, requested).
		Scan(&version, &activeDigest, &evaluation, &manifest, &metadata.ArtifactByteSize, &artifact)
	if err != nil {
		return metadata, nil, repositoryReadError(err)
	}
	metadata.SchemaVersion = contracts.ModelDownloadV1Version
	metadata.DeploymentID = deployment
	metadata.EvaluationSHA256 = hex.EncodeToString(evaluation)
	if json.Unmarshal(manifest, &metadata.Manifest) != nil || metadata.Validate() != nil ||
		metadata.Manifest.ModelVersion != version || metadata.Manifest.ArtifactSHA256 != hex.EncodeToString(activeDigest) ||
		!slices.Contains(metadata.Manifest.Purposes, contracts.ModelPurposeInference) {
		return metadata, nil, ErrModelArtifactCorrupt
	}
	if digest != "" {
		sum := sha256.Sum256(artifact)
		if len(artifact) != metadata.ArtifactByteSize || hex.EncodeToString(sum[:]) != digest {
			return metadata, nil, ErrModelArtifactCorrupt
		}
	}
	return metadata, artifact, nil
}

func handleModelDownload(w http.ResponseWriter, r *http.Request, cfg MeshConfig, withArtifact bool) {
	w.Header().Set("Cache-Control", "no-store")
	peer, _ := r.Context().Value(meshPeerContextKey{}).(string)
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	binding, status, reason, ok := authenticateMeshPeer(ctx, cfg, peer)
	if !ok {
		http.Error(w, reason, status)
		return
	}
	if cfg.ModelDownloads == nil {
		http.Error(w, "model registry unavailable", http.StatusServiceUnavailable)
		return
	}
	digest := r.PathValue("sha256")
	if r.URL.RawQuery != "" || r.URL.ForceQuery || (withArtifact && !evaluationSHA256Pattern.MatchString(digest)) {
		http.Error(w, "invalid model download request", http.StatusBadRequest)
		return
	}
	metadata, artifact, err := cfg.ModelDownloads.ApprovedModelDownload(ctx, binding.DeploymentID, digest)
	switch {
	case errors.Is(err, ErrRepositoryNotFound):
		http.Error(w, "approved active model unavailable", http.StatusNotFound)
	case errors.Is(err, ErrModelArtifactCorrupt):
		http.Error(w, "stored artifact failed verification", http.StatusInternalServerError)
	case err != nil:
		http.Error(w, "model registry unavailable", http.StatusServiceUnavailable)
	case withArtifact:
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(artifact)))
		_, _ = w.Write(artifact)
	default:
		writeJSON(w, http.StatusOK, metadata)
	}
}
