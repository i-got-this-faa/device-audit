package contracts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
)

func signedRegistryUpload(t *testing.T, key ed25519.PrivateKey, artifact []byte) ModelArtifactUploadV1 {
	t.Helper()
	features, _, err := FeatureNamesV1(FeatureVersionHDDSMART7DV1)
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	sum := sha256.Sum256(artifact)
	m := ModelManifestV1{SchemaVersion: ModelManifestV1Version, ModelVersion: "synthetic.1", ArtifactSHA256: hex.EncodeToString(sum[:]),
		Architecture: "synthetic.v1", ParameterCount: 6, RuntimeName: "device-audit-runtime", RuntimeVersion: "1.0.0",
		FeatureVersion: FeatureVersionHDDSMART7DV1, Features: features, Purposes: []string{ModelPurposeInference}, SigningKeyID: keyID}
	message, err := m.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	m.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	return ModelArtifactUploadV1{SchemaVersion: ModelArtifactUploadV1Version, Manifest: m, Artifact: artifact, SourceReference: "training-run:1"}
}

func TestModelArtifactUploadVerify(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	trusted := key.Public().(ed25519.PublicKey)
	if err := signedRegistryUpload(t, key, []byte("model")).Verify(trusted); err != nil {
		t.Fatal(err)
	}
	oversized := make([]byte, ModelArtifactMaxBytesV1+1)
	cases := map[string]struct {
		upload ModelArtifactUploadV1
		want   ModelRejection
	}{
		"oversized":     {signedRegistryUpload(t, key, oversized), ModelRejectionArtifactTooLarge},
		"empty":         {signedRegistryUpload(t, key, nil), ModelRejectionInvalidRequest},
		"untrusted key": {signedRegistryUpload(t, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32)), []byte("model")), ModelRejectionKeyMismatch},
		"no source": {func() ModelArtifactUploadV1 {
			u := signedRegistryUpload(t, key, []byte("model"))
			u.SourceReference = ""
			return u
		}(), ModelRejectionInvalidRequest},
		"swapped artifact": {func() ModelArtifactUploadV1 {
			u := signedRegistryUpload(t, key, []byte("model"))
			u.Artifact = []byte("other")
			return u
		}(), ModelRejectionDigestMismatch},
	}
	for name, tc := range cases {
		if err := tc.upload.Verify(trusted); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %s", name, err, tc.want)
		}
	}
}

func TestModelRegistryRequestsRejectUnknownAndNullFields(t *testing.T) {
	for _, body := range []string{
		`{"schema_version":"device-audit.model-reference-request.v1","model_version":"m.1","artifact_sha256":null}`,
		`{"schema_version":"device-audit.model-reference-request.v1","model_version":"m.1","artifact_sha256":"` + string(bytes.Repeat([]byte("a"), 64)) + `","force":true}`,
		`{"schema_version":"device-audit.model-reference-request.v1","model_version":"m.1","model_version":"m.2","artifact_sha256":"` + string(bytes.Repeat([]byte("a"), 64)) + `"}`,
	} {
		var request ModelReferenceRequestV1
		if err := json.Unmarshal([]byte(body), &request); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}
