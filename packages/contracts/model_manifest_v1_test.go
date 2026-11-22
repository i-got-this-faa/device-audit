package contracts

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

type modelManifestVector struct {
	Name       string          `json:"name"`
	Payload    json.RawMessage `json:"payload"`
	Valid      bool            `json:"valid"`
	Rejection  string          `json:"rejection"`
	Activation struct {
		RuntimeName    string   `json:"runtime_name"`
		RuntimeVersion string   `json:"runtime_version"`
		Architectures  []string `json:"architectures"`
		Purpose        string   `json:"purpose"`
		ArtifactBase64 string   `json:"artifact_base64"`
	} `json:"activation"`
	CanonicalHex string `json:"canonical_hex"`
}

type modelManifestCollection struct {
	Key     string                `json:"verification_key"`
	Vectors []modelManifestVector `json:"vectors"`
}

func readModelManifestVectors(t *testing.T) modelManifestCollection {
	t.Helper()
	data, err := os.ReadFile("fixtures/models/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var c modelManifestCollection
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return c
}

func (v modelManifestVector) activation(t *testing.T, key ed25519.PublicKey) ModelActivationV1 {
	t.Helper()
	artifact, err := base64.StdEncoding.DecodeString(v.Activation.ArtifactBase64)
	if err != nil {
		t.Fatal(err)
	}
	return ModelActivationV1{
		Runtime:    ModelRuntimeV1{Name: v.Activation.RuntimeName, Version: v.Activation.RuntimeVersion, Architectures: v.Activation.Architectures},
		Purpose:    v.Activation.Purpose,
		Artifact:   artifact,
		TrustedKey: key,
	}
}

func TestModelManifestV1Vectors(t *testing.T) {
	collection := readModelManifestVectors(t)
	key, err := hex.DecodeString(collection.Key)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, v := range collection.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var m ModelManifestV1
			got := ""
			if err := json.Unmarshal(v.Payload, &m); err != nil {
				got = string(ModelRejectionInvalidManifest)
			} else if err := m.CheckActivation(v.activation(t, key)); err != nil {
				var rejection ModelRejection
				if !errors.As(err, &rejection) {
					t.Fatalf("activation error is not a ModelRejection: %v", err)
				}
				got = string(rejection)
			}
			if got != v.Rejection || (got == "") != v.Valid {
				t.Fatalf("rejection %q valid=%v, want %q valid=%v", got, got == "", v.Rejection, v.Valid)
			}
			if v.CanonicalHex != "" {
				message, err := m.SigningBytes()
				if err != nil || hex.EncodeToString(message) != v.CanonicalHex {
					t.Fatalf("canonical signing bytes changed: %v", err)
				}
			}
			if v.Valid {
				// A valid manifest survives a round trip with nothing added or lost.
				encoded, _ := json.Marshal(m)
				var gotJSON, want any
				_ = json.Unmarshal(encoded, &gotJSON)
				_ = json.Unmarshal(v.Payload, &want)
				if !reflect.DeepEqual(gotJSON, want) {
					t.Fatal("round trip changed values")
				}
			}
			seen[v.Rejection] = true
		})
	}
	// Each refusal named in the contract must be exercised by a vector.
	for _, want := range []ModelRejection{
		ModelRejectionInvalidManifest, ModelRejectionUnsupportedManifestVersion, ModelRejectionUnsupportedFeatureVersion,
		ModelRejectionFeatureOrder, ModelRejectionInvalidSignature, ModelRejectionKeyMismatch, ModelRejectionRuntimeMismatch,
		ModelRejectionUnsupportedArchitecture, ModelRejectionPurposeUnsupported, ModelRejectionDigestMismatch,
	} {
		if !seen[string(want)] {
			t.Errorf("no vector rejects with %s", want)
		}
	}
}

// A mutation of one signed field must fail verification, not just a changed field set.
func TestModelManifestSignatureCoversEveryField(t *testing.T) {
	collection := readModelManifestVectors(t)
	key, _ := hex.DecodeString(collection.Key)
	var valid ModelManifestV1
	for _, v := range collection.Vectors {
		if v.Name == "valid_inference" {
			if err := json.Unmarshal(v.Payload, &valid); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := valid.VerifySignature(key); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*ModelManifestV1){
		"model_version":   func(m *ModelManifestV1) { m.ModelVersion = "synthetic.2" },
		"artifact_sha256": func(m *ModelManifestV1) { m.ArtifactSHA256 = strings.Repeat("0", 64) },
		"architecture":    func(m *ModelManifestV1) { m.Architecture = "synthetic.v2" },
		"parameter_count": func(m *ModelManifestV1) { m.ParameterCount++ },
		"runtime_name":    func(m *ModelManifestV1) { m.RuntimeName = "other" },
		"runtime_version": func(m *ModelManifestV1) { m.RuntimeVersion = "1.0.1" },
		"feature_version": func(m *ModelManifestV1) { m.FeatureVersion = "hdd-smart-7d.v2" },
		"features": func(m *ModelManifestV1) {
			m.Features = append([]string{m.Features[1], m.Features[0]}, m.Features[2:]...)
		},
		"purposes": func(m *ModelManifestV1) { m.Purposes = m.Purposes[:1] },
	}
	for field, mutate := range mutations {
		m := valid
		m.Features, m.Purposes = append([]string(nil), valid.Features...), append([]string(nil), valid.Purposes...)
		mutate(&m)
		if err := m.VerifySignature(key); !errors.Is(err, ModelRejectionInvalidSignature) {
			t.Errorf("%s is not signed: %v", field, err)
		}
	}
}

func TestModelManifestStrictJSON(t *testing.T) {
	var original string
	for _, v := range readModelManifestVectors(t).Vectors {
		if v.Name == "valid_inference" {
			original = strings.Join(strings.Fields(string(v.Payload)), "")
		}
	}
	for _, wire := range []string{
		strings.Replace(original, `"parameter_count":6`, `"parameter_count":6,"parameter_count":7`, 1),
		strings.Replace(original, `"parameter_count":6`, `"parameter_count":6.0`, 1),
		strings.Replace(original, `"parameter_count":6,`, "", 1),
		strings.Replace(original, `"parameter_count":6`, `"parameter_count":null`, 1),
		original + ` {}`,
	} {
		if wire == original {
			t.Fatal("unchanged mutation")
		}
		var m ModelManifestV1
		if json.Unmarshal([]byte(wire), &m) == nil {
			t.Fatalf("accepted invalid JSON: %s", wire)
		}
	}
}
