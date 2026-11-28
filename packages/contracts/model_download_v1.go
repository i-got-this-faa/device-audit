package contracts

import "crypto/sha256"

const (
	ModelDownloadV1Version        = "device-audit.model-download.v1"
	ModelDownloadMetadataPathV1   = "/v1/models/active"
	ModelDownloadArtifactPrefixV1 = "/v1/models/active/artifact/"
)

// ModelDownloadV1 describes the deployment's approved active artifact.
// The authenticated controller conveys approval; the CT10 signature authenticates the manifest.
type ModelDownloadV1 struct {
	SchemaVersion    string          `json:"schema_version"`
	DeploymentID     string          `json:"deployment_id"`
	Manifest         ModelManifestV1 `json:"manifest"`
	ArtifactByteSize int             `json:"artifact_byte_size"`
	EvaluationSHA256 string          `json:"evaluation_sha256"`
}

func (m *ModelDownloadV1) UnmarshalJSON(data []byte) error {
	type wire ModelDownloadV1
	return decodeEnvelopeJSON(data, (*wire)(m), []string{
		"schema_version", "deployment_id", "manifest", "artifact_byte_size", "evaluation_sha256",
	})
}

func (m ModelDownloadV1) Validate() error {
	if m.SchemaVersion != ModelDownloadV1Version || !opaqueIDPattern.MatchString(m.DeploymentID) ||
		!fixedEnvelopeHex(m.EvaluationSHA256, sha256.Size) || m.ArtifactByteSize <= 0 {
		return ModelRejectionInvalidRequest
	}
	if m.ArtifactByteSize > ModelArtifactMaxBytesV1 {
		return ModelRejectionArtifactTooLarge
	}
	return m.Manifest.Validate()
}
