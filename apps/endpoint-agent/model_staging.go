package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

const stagedModelFile = "staged-model.json"

type stagedModel struct {
	Metadata contracts.ModelDownloadV1 `json:"metadata"`
	Artifact []byte                    `json:"artifact"`
}

func stageApprovedModel(ctx context.Context, stateDir, serverKey, regionFile, publisherKeyFile string) (contracts.ModelDownloadV1, error) {
	var metadata contracts.ModelDownloadV1
	if !filepath.IsAbs(stateDir) || !filepath.IsAbs(publisherKeyFile) {
		return metadata, errors.New("model staging requires absolute state directory and publisher key paths")
	}
	key, err := loadPinnedEd25519Key(publisherKeyFile)
	if err != nil {
		return metadata, err
	}
	store, err := openIdentityStore(stateDir, false)
	if err != nil {
		return metadata, err
	}
	defer store.close()
	id, receipt, err := store.admitted()
	if err != nil {
		return metadata, err
	}
	cfg, err := admittedMeshConfig(store, id, serverKey, regionFile)
	if err != nil {
		return metadata, err
	}
	defer clear(cfg.NetworkPrivateKey)
	if err := mesh.CheckRelay(ctx, cfg.DERP, cfg.NetworkPrivateKey); err != nil {
		return metadata, err
	}
	client, err := mesh.NewClient(cfg)
	if err != nil {
		return metadata, err
	}
	defer client.Close()
	return downloadAndStageModel(ctx, client.HTTPClient(), key, receipt.DeploymentID, store)
}

func downloadAndStageModel(ctx context.Context, client *http.Client, key ed25519.PublicKey, deployment string, store *identityStore) (contracts.ModelDownloadV1, error) {
	var metadata contracts.ModelDownloadV1
	data, err := fetchModelResource(ctx, client, contracts.ModelDownloadMetadataPathV1, maxModelMetadata, false)
	if err != nil {
		return metadata, err
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return metadata, fmt.Errorf("decode model download metadata: %w", err)
	}
	if err := metadata.Validate(); err != nil {
		return metadata, err
	}
	if metadata.DeploymentID != deployment {
		return metadata, errors.New("model deployment does not match admitted identity")
	}
	manifest := metadata.Manifest
	if err := manifest.CheckCompatibility(health.EndpointInferenceRuntime(), contracts.ModelPurposeInference, key); err != nil {
		return metadata, err
	}

	artifact, err := fetchModelResource(ctx, client, contracts.ModelDownloadArtifactPrefixV1+manifest.ArtifactSHA256, int64(metadata.ArtifactByteSize), true)
	if err != nil {
		return metadata, err
	}
	if sum := sha256.Sum256(artifact); hex.EncodeToString(sum[:]) != manifest.ArtifactSHA256 {
		return metadata, contracts.ModelRejectionDigestMismatch
	}
	if err := health.ValidateLogisticArtifact(manifest, artifact); err != nil {
		return metadata, err
	}
	bundle, err := json.Marshal(stagedModel{Metadata: metadata, Artifact: artifact})
	if err != nil {
		return metadata, err
	}
	if err := ctx.Err(); err != nil {
		return metadata, err
	}
	return metadata, store.replace(stagedModelFile, stagedModelFile+".tmp", bundle)
}

func fetchModelResource(ctx context.Context, client *http.Client, path string, limit int64, exactSize bool) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+mesh.ApplicationHost+path, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("model download: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("model download returned HTTP %d", res.StatusCode)
	}
	if exactSize && res.ContentLength != limit {
		return nil, errors.New("artifact content length does not match approved metadata")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read model download: %w", err)
	}
	if int64(len(data)) > limit || (exactSize && int64(len(data)) != limit) {
		return nil, errors.New("model download size mismatch")
	}
	return data, nil
}
