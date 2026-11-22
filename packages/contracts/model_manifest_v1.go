package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
)

// CT10 #101 freezes what a model artifact must declare before an endpoint or
// trainer activates it; see model-manifest-v1.md and fixtures/models.
const (
	ModelManifestV1Version = "device-audit.model-manifest.v1"
	ModelPurposeInference  = "inference"
	ModelPurposeTraining   = "training"
)

// ModelRejection is the stable reason a manifest cannot activate. It is the
// error value itself so callers can compare it with errors.Is.
type ModelRejection string

func (r ModelRejection) Error() string { return string(r) }

const (
	ModelRejectionInvalidManifest            ModelRejection = "invalid_manifest"
	ModelRejectionUnsupportedManifestVersion ModelRejection = "unsupported_manifest_version"
	ModelRejectionUnsupportedFeatureVersion  ModelRejection = "unsupported_feature_version"
	ModelRejectionFeatureOrder               ModelRejection = "feature_order_mismatch"
	ModelRejectionInvalidSignature           ModelRejection = ModelRejection(EnvelopeRejectionInvalidSignature)
	ModelRejectionKeyMismatch                ModelRejection = ModelRejection(EnvelopeRejectionKeyMismatch)
	ModelRejectionRuntimeMismatch            ModelRejection = "runtime_mismatch"
	ModelRejectionUnsupportedArchitecture    ModelRejection = "unsupported_architecture"
	ModelRejectionPurposeUnsupported         ModelRejection = "purpose_unsupported"
	ModelRejectionDigestMismatch             ModelRejection = "digest_mismatch"
)

// ModelManifestV1 describes one signed model artifact. The signature binds every
// other field, including the artifact digest, to the model publisher's key.
// That key is separate from device, network and chain identities.
type ModelManifestV1 struct {
	SchemaVersion  string   `json:"schema_version"`
	ModelVersion   string   `json:"model_version"`
	ArtifactSHA256 string   `json:"artifact_sha256"`
	Architecture   string   `json:"architecture"`
	ParameterCount uint32   `json:"parameter_count"`
	RuntimeName    string   `json:"runtime_name"`
	RuntimeVersion string   `json:"runtime_version"`
	FeatureVersion string   `json:"feature_version"`
	Features       []string `json:"features"`
	Purposes       []string `json:"purposes"`
	SigningKeyID   string   `json:"signing_key_id"`
	Signature      string   `json:"signature"`
}

// ModelRuntimeV1 is the runtime that would load the artifact. It must match the
// manifest exactly; there is no version range or fallback.
type ModelRuntimeV1 struct {
	Name          string
	Version       string
	Architectures []string
}

// ModelActivationV1 is what the activating process knows for itself. TrustedKey
// comes from configuration, never from the manifest.
type ModelActivationV1 struct {
	Runtime    ModelRuntimeV1
	Purpose    string
	Artifact   []byte
	TrustedKey ed25519.PublicKey
}

func (m *ModelManifestV1) UnmarshalJSON(data []byte) error {
	type wire ModelManifestV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "model_version", "artifact_sha256", "architecture", "parameter_count", "runtime_name", "runtime_version", "feature_version", "features", "purposes", "signing_key_id", "signature"}); err != nil {
		return err
	}
	*m = ModelManifestV1(v)
	return nil
}

// validateBody checks the signed fields' shape. It accepts a feature version or
// order that Validate rejects, so such a manifest can still be signed and the
// signature is not what rejects it.
func (m ModelManifestV1) validateBody() error {
	if m.SchemaVersion != ModelManifestV1Version {
		return ModelRejectionUnsupportedManifestVersion
	}
	for _, id := range []string{m.ModelVersion, m.Architecture, m.RuntimeName, m.RuntimeVersion, m.FeatureVersion} {
		if !opaqueIDPattern.MatchString(id) {
			return fmt.Errorf("%w: invalid identifier", ModelRejectionInvalidManifest)
		}
	}
	if !fixedEnvelopeHex(m.ArtifactSHA256, sha256.Size) || m.ParameterCount < 1 || m.ParameterCount > 4096 || !validEnvelopeKeyID(m.SigningKeyID) {
		return fmt.Errorf("%w: invalid digest, parameter count or key ID", ModelRejectionInvalidManifest)
	}
	if len(m.Features) < 1 || len(m.Features) > 64 {
		return fmt.Errorf("%w: features are required and limited to 64", ModelRejectionInvalidManifest)
	}
	for _, name := range m.Features {
		if !opaqueIDPattern.MatchString(name) {
			return fmt.Errorf("%w: invalid feature name", ModelRejectionInvalidManifest)
		}
	}
	if len(m.Purposes) < 1 || len(m.Purposes) > 2 {
		return fmt.Errorf("%w: purposes must list inference and/or training once", ModelRejectionInvalidManifest)
	}
	for i, purpose := range m.Purposes {
		if (purpose != ModelPurposeInference && purpose != ModelPurposeTraining) || slices.Contains(m.Purposes[:i], purpose) {
			return fmt.Errorf("%w: purposes must list inference and/or training once", ModelRejectionInvalidManifest)
		}
	}
	return nil
}

// Validate checks structure, then that the feature version is implemented and
// the declared feature order is the frozen one. It does not check the signature.
func (m ModelManifestV1) Validate() error {
	if err := m.validateBody(); err != nil {
		return err
	}
	if err := validateEnvelopeSignature(m.Signature); err != nil {
		return fmt.Errorf("%w: %v", ModelRejectionInvalidManifest, err)
	}
	names, _, err := FeatureNamesV1(m.FeatureVersion)
	if errors.Is(err, ErrUnsupportedFeatureVersion) {
		return ModelRejectionUnsupportedFeatureVersion
	}
	if !slices.Equal(names, m.Features) {
		return ModelRejectionFeatureOrder
	}
	return nil
}

// SigningBytes uses the application signing format. The two lists are written as
// a decimal count followed by their entries, so no entry can shift a boundary.
func (m ModelManifestV1) SigningBytes() ([]byte, error) {
	if err := m.validateBody(); err != nil {
		return nil, err
	}
	fields := []string{m.SchemaVersion, m.ModelVersion, m.ArtifactSHA256, m.Architecture, strconv.FormatUint(uint64(m.ParameterCount), 10), m.RuntimeName, m.RuntimeVersion, m.FeatureVersion, m.SigningKeyID, strconv.Itoa(len(m.Features))}
	fields = append(fields, m.Features...)
	fields = append(fields, strconv.Itoa(len(m.Purposes)))
	return canonicalEnvelopeFields(append(fields, m.Purposes...)), nil
}

// VerifySignature checks integrity against the externally trusted publisher key.
func (m ModelManifestV1) VerifySignature(trustedKey ed25519.PublicKey) error {
	message, err := m.SigningBytes()
	if err != nil {
		return err
	}
	if validateEnvelopeSignature(m.Signature) != nil {
		return ModelRejectionInvalidSignature
	}
	if err := verifyEnvelopeSignature(trustedKey, m.SigningKeyID, m.Signature, message); err != nil {
		if err.Error() == EnvelopeRejectionInvalidSignature {
			return ModelRejectionInvalidSignature
		}
		// A key of the wrong size or fingerprint cannot be the key that signed.
		return ModelRejectionKeyMismatch
	}
	return nil
}

// CheckActivation decides whether this process may load the artifact for the
// given purpose. Every refusal is a ModelRejection and happens before any model
// state changes; a caller must not fall back to another version. It does not
// track revocation or rollback of earlier manifests.
func (m ModelManifestV1) CheckActivation(a ModelActivationV1) error {
	if err := m.Validate(); err != nil {
		return err
	}
	if err := m.VerifySignature(a.TrustedKey); err != nil {
		return err
	}
	if a.Runtime.Name != m.RuntimeName || a.Runtime.Version != m.RuntimeVersion {
		return ModelRejectionRuntimeMismatch
	}
	if !slices.Contains(a.Runtime.Architectures, m.Architecture) {
		return ModelRejectionUnsupportedArchitecture
	}
	if !slices.Contains(m.Purposes, a.Purpose) {
		return ModelRejectionPurposeUnsupported
	}
	if sum := sha256.Sum256(a.Artifact); hex.EncodeToString(sum[:]) != m.ArtifactSHA256 {
		return ModelRejectionDigestMismatch
	}
	return nil
}
