//go:build ignore

// Regenerate with go run packages/contracts/fixtures/models/generate.go.
// The signing seeds are public RFC 8032 test material, never operational keys.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"slices"

	c "github.com/i-got-this-faa/device-audit/packages/contracts"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type activation struct {
	RuntimeName    string   `json:"runtime_name"`
	RuntimeVersion string   `json:"runtime_version"`
	Architectures  []string `json:"architectures"`
	Purpose        string   `json:"purpose"`
	ArtifactBase64 string   `json:"artifact_base64"`
}

type vector struct {
	Name           string     `json:"name"`
	Payload        any        `json:"payload"`
	Valid          bool       `json:"valid"`
	SchemaValid    bool       `json:"schema_valid"`
	Rejection      string     `json:"rejection"`
	SignatureValid bool       `json:"signature_valid"`
	Activation     activation `json:"activation"`
	CanonicalHex   string     `json:"canonical_hex"`
}

func main() {
	seed := func(s string) ed25519.PrivateKey {
		b, err := hex.DecodeString(s)
		must(err)
		return ed25519.NewKeyFromSeed(b)
	}
	publisher := seed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	other := seed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	keyID := func(k ed25519.PrivateKey) string {
		id, err := c.SigningKeyIDV1(k.Public().(ed25519.PublicKey))
		must(err)
		return id
	}

	artifact := []byte("synthetic model artifact, not a trained model")
	sum := sha256.Sum256(artifact)
	names, _, err := c.FeatureNamesV1(c.FeatureVersionHDDSMART7DV1)
	must(err)
	base := c.ModelManifestV1{
		SchemaVersion: c.ModelManifestV1Version, ModelVersion: "synthetic.1", ArtifactSHA256: hex.EncodeToString(sum[:]),
		Architecture: "synthetic.v1", ParameterCount: 6, RuntimeName: "device-audit-runtime", RuntimeVersion: "1.0.0",
		FeatureVersion: c.FeatureVersionHDDSMART7DV1, Features: names,
		Purposes: []string{c.ModelPurposeInference, c.ModelPurposeTraining}, SigningKeyID: keyID(publisher),
	}
	good := activation{"device-audit-runtime", "1.0.0", []string{"synthetic.v1"}, c.ModelPurposeInference, base64.StdEncoding.EncodeToString(artifact)}

	var vectors []vector
	// add signs with key, then records the outcome the other fields should produce.
	add := func(name string, m c.ModelManifestV1, key ed25519.PrivateKey, schemaValid bool, rejection string, a activation) {
		var canonical string
		if message, err := m.SigningBytes(); err == nil {
			canonical = hex.EncodeToString(message)
			if key != nil {
				m.Signature = hex.EncodeToString(ed25519.Sign(key, message))
			}
		}
		message, _ := m.SigningBytes()
		signed := m.VerifySignature(publisher.Public().(ed25519.PublicKey)) == nil && message != nil
		vectors = append(vectors, vector{name, m, rejection == "", schemaValid, rejection, signed, a, canonical})
	}
	with := func(edit func(*c.ModelManifestV1)) c.ModelManifestV1 {
		m := base
		m.Features, m.Purposes = slices.Clone(base.Features), slices.Clone(base.Purposes)
		edit(&m)
		return m
	}

	add("valid_inference", base, publisher, true, "", good)
	training := good
	training.Purpose = c.ModelPurposeTraining
	add("valid_training", base, publisher, true, "", training)

	inferenceOnly := with(func(m *c.ModelManifestV1) { m.Purposes = []string{c.ModelPurposeInference} })
	add("inference_only_cannot_train", inferenceOnly, publisher, true, "purpose_unsupported", training)

	runtime := good
	runtime.RuntimeVersion = "1.1.0"
	add("runtime_version_mismatch", base, publisher, true, "runtime_mismatch", runtime)
	runtime = good
	runtime.RuntimeName = "other-runtime"
	add("runtime_name_mismatch", base, publisher, true, "runtime_mismatch", runtime)
	arch := good
	arch.Architectures = []string{"other.v1"}
	add("unsupported_architecture", base, publisher, true, "unsupported_architecture", arch)
	arch.Architectures = []string{}
	add("runtime_with_no_architectures", base, publisher, true, "unsupported_architecture", arch)

	tampered := good
	tampered.ArtifactBase64 = base64.StdEncoding.EncodeToString(append(slices.Clone(artifact), 0))
	add("artifact_digest_mismatch", base, publisher, true, "digest_mismatch", tampered)
	tampered.ArtifactBase64 = ""
	add("empty_artifact_digest_mismatch", base, publisher, true, "digest_mismatch", tampered)

	swapped := with(func(m *c.ModelManifestV1) { m.Features[0], m.Features[1] = m.Features[1], m.Features[0] })
	add("feature_order_swapped", swapped, publisher, true, "feature_order_mismatch", good)
	reversed := with(func(m *c.ModelManifestV1) { slices.Reverse(m.Features) })
	add("feature_order_reversed", reversed, publisher, true, "feature_order_mismatch", good)
	missing := with(func(m *c.ModelManifestV1) { m.Features = m.Features[:5] })
	add("feature_missing", missing, publisher, true, "feature_order_mismatch", good)
	extra := with(func(m *c.ModelManifestV1) { m.Features = append(m.Features, "smart_187_raw.last") })
	add("feature_extra", extra, publisher, true, "feature_order_mismatch", good)

	add("unsupported_feature_version", with(func(m *c.ModelManifestV1) { m.FeatureVersion = "hdd-smart-7d.v2" }), publisher, true, "unsupported_feature_version", good)
	unsupported := with(func(m *c.ModelManifestV1) { m.SchemaVersion = "device-audit.model-manifest.v2" })
	unsupported.Signature = hex.EncodeToString(make([]byte, ed25519.SignatureSize))
	add("unsupported_manifest_version", unsupported, nil, false, "unsupported_manifest_version", good)

	changed := with(func(m *c.ModelManifestV1) { m.ModelVersion = "synthetic.2" })
	changed.Signature = func() string { m, _ := base.SigningBytes(); return hex.EncodeToString(ed25519.Sign(publisher, m)) }()
	add("signed_field_changed_after_signing", changed, nil, true, "invalid_signature", good)
	add("signed_by_untrusted_key", with(func(m *c.ModelManifestV1) { m.SigningKeyID = keyID(other) }), other, true, "key_mismatch", good)

	short := base
	short.Signature = "00"
	add("signature_wrong_length", short, nil, false, "invalid_manifest", good)
	add("digest_uppercase", with(func(m *c.ModelManifestV1) { m.ArtifactSHA256 = "A" + m.ArtifactSHA256[1:] }), publisher, false, "invalid_manifest", good)
	add("zero_parameters", with(func(m *c.ModelManifestV1) { m.ParameterCount = 0 }), publisher, false, "invalid_manifest", good)
	add("no_purposes", with(func(m *c.ModelManifestV1) { m.Purposes = []string{} }), publisher, false, "invalid_manifest", good)
	add("duplicate_purpose", with(func(m *c.ModelManifestV1) { m.Purposes = []string{c.ModelPurposeInference, c.ModelPurposeInference} }), publisher, false, "invalid_manifest", good)
	add("unknown_purpose", with(func(m *c.ModelManifestV1) { m.Purposes = []string{"serving"} }), publisher, false, "invalid_manifest", good)
	add("empty_features", with(func(m *c.ModelManifestV1) { m.Features = []string{} }), publisher, false, "invalid_manifest", good)

	raw, err := json.Marshal(base)
	must(err)
	var fields map[string]any
	must(json.Unmarshal(raw, &fields))
	fields["weights_base64"] = "AAAAAAAAAAA="
	vectors = append(vectors, vector{"raw_weights_not_in_manifest", fields, false, false, "invalid_manifest", false, good, ""})

	out, err := json.MarshalIndent(map[string]any{
		"schema_version":   "device-audit.model-manifest-fixtures.v1",
		"verification_key": hex.EncodeToString(publisher.Public().(ed25519.PublicKey)),
		"vectors":          vectors,
	}, "", "  ")
	must(err)
	must(os.WriteFile("packages/contracts/fixtures/models/v1-vectors.json", append(out, '\n'), 0o644))
}
