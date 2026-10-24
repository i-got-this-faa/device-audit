//go:build ignore

// Public test seeds only. Run from the repository root with go run.
package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"strings"

	c "github.com/i-got-this-faa/device-audit/packages/contracts"
)

func main() {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	key := ed25519.NewKeyFromSeed(seed)
	public := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	kid, _ := c.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	networkSeed, _ := hex.DecodeString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	network, _ := ecdh.X25519().NewPrivateKey(networkSeed)
	netKey := hex.EncodeToString(network.PublicKey().Bytes())
	challengeID := strings.Repeat("ab", 32)
	enrollment := c.EnrollmentEnvelopeV1{EnvelopeHeaderV1: c.EnvelopeHeaderV1{
		SchemaVersion: c.EnrollmentV1Version, DeploymentID: "deployment:fixture", DeviceID: "device:fixture", SigningKeyID: kid,
		Sequence: 1, IssuedAt: "2026-10-24T12:00:00Z", ExpiresAt: "2026-10-24T12:10:00Z",
	}, PublicKey: public, ChallengeID: challengeID}
	message, _ := enrollment.SigningBytes()
	enrollment.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	admission := c.EnrollmentAdmissionV1{SchemaVersion: c.EnrollmentAdmissionV1Version, Enrollment: enrollment, NetworkPublicKey: netKey, NetworkProof: strings.Repeat("cd", 32)}
	message, _ = admission.SigningBytes()
	admission.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	values := []any{
		c.BootstrapTokenRequestV1{SchemaVersion: c.BootstrapTokenRequestV1Version, DeviceID: enrollment.DeviceID},
		c.BootstrapTokenV1{SchemaVersion: c.BootstrapTokenV1Version, DeploymentID: enrollment.DeploymentID, DeviceID: enrollment.DeviceID, Token: strings.Repeat("ef", 32), ExpiresAt: enrollment.ExpiresAt},
		c.EnrollmentStartV1{SchemaVersion: c.EnrollmentStartV1Version, DeploymentID: enrollment.DeploymentID, DeviceID: enrollment.DeviceID, PublicKey: public, NetworkPublicKey: netKey},
		c.EnrollmentChallengeV1{SchemaVersion: c.EnrollmentChallengeV1Version, DeploymentID: enrollment.DeploymentID, DeviceID: enrollment.DeviceID, SigningKeyID: kid, NetworkPublicKey: netKey, ChallengeID: challengeID, NetworkChallenge: base64.StdEncoding.EncodeToString(make([]byte, c.NetworkChallengeBytes)), ExpiresAt: enrollment.ExpiresAt},
		admission,
		c.EnrollmentAcceptedV1{SchemaVersion: c.EnrollmentAcceptedV1Version, DeploymentID: enrollment.DeploymentID, DeviceID: enrollment.DeviceID, SigningKeyID: kid, NetworkPublicKey: netKey, LastSequence: 1},
		c.EnrollmentErrorV1{SchemaVersion: c.EnrollmentErrorV1Version, Reason: "bootstrap_invalid"},
	}
	var vectors []map[string]any
	var wires struct {
		SchemaVersion string            `json:"schema_version"`
		Vectors       []json.RawMessage `json:"vectors"`
	}
	wirePath := "packages/contracts/fixtures/conformance/v1-vectors.json"
	data, err := os.ReadFile(wirePath)
	must(err)
	must(json.Unmarshal(data, &wires))
	var kept []json.RawMessage
	for _, w := range wires.Vectors {
		var header struct {
			ReaderVersion string `json:"reader_version"`
		}
		must(json.Unmarshal(w, &header))
		if !strings.Contains(header.ReaderVersion, "bootstrap-") && !strings.Contains(header.ReaderVersion, "enrollment-start.") && !strings.Contains(header.ReaderVersion, "enrollment-challenge.") && !strings.Contains(header.ReaderVersion, "enrollment-admission.") && !strings.Contains(header.ReaderVersion, "enrollment-accepted.") && !strings.Contains(header.ReaderVersion, "enrollment-error.") {
			kept = append(kept, w)
		}
	}
	wires.Vectors = kept
	for _, v := range values {
		encoded, err := json.Marshal(v)
		must(err)
		var object map[string]any
		must(json.Unmarshal(encoded, &object))
		version := object["schema_version"].(string)
		vector := map[string]any{"name": "valid/" + version, "message": object, "contract_valid": true, "schema_valid": true}
		if _, ok := v.(c.EnrollmentAdmissionV1); ok {
			vector["canonical_hex"] = hex.EncodeToString(message)
			vector["signature_valid"] = true
		}
		vectors = append(vectors, vector)
		for _, unsupported := range []bool{false, true} {
			name, expected := "valid/", "accepted"
			if unsupported {
				object["schema_version"] = "device-audit.unsupported.v999"
				name, expected = "unsupported/", "unsupported_schema"
			}
			wire, err := json.Marshal(object)
			must(err)
			wires.Vectors = append(wires.Vectors, raw(map[string]any{"name": name + version, "reader_version": version, "wire": string(wire), "expected_go": expected, "expected_schema": expected, "expected_python": expected}))
		}
		object["schema_version"] = version
		for _, field := range []string{"missing", "unknown"} {
			clone := map[string]any{}
			for k, v := range object {
				clone[k] = v
			}
			if field == "missing" {
				delete(clone, "schema_version")
				clone["schema_version"] = version
				var fields []string
				for k := range object {
					if k != "schema_version" {
						fields = append(fields, k)
					}
				}
				sort.Strings(fields)
				delete(clone, fields[0])
			} else {
				clone["extra"] = true
			}
			vectors = append(vectors, map[string]any{"name": field + "/" + version, "message": clone, "contract_valid": false, "schema_valid": false})
		}
	}
	for _, bad := range []struct {
		name, key string
		schema    bool
	}{
		{"low-order", strings.Repeat("00", 32), true},
		{"noncanonical-high-bit", netKey[:62] + "ea", true},
		{"same-signing-network", public, true},
		{"uppercase", strings.ToUpper(netKey), false},
	} {
		v := c.EnrollmentStartV1{SchemaVersion: c.EnrollmentStartV1Version, DeploymentID: enrollment.DeploymentID, DeviceID: enrollment.DeviceID, PublicKey: public, NetworkPublicKey: bad.key}
		vectors = append(vectors, map[string]any{"name": bad.name, "message": v, "contract_valid": false, "schema_valid": bad.schema})
	}
	admission.NetworkProof = strings.Repeat("ee", 32)
	message, err = admission.SigningBytes()
	must(err)
	vectors = append(vectors, map[string]any{"name": "altered-network-proof", "message": admission, "contract_valid": true, "schema_valid": true, "canonical_hex": hex.EncodeToString(message), "signature_valid": false})
	vectors = append(vectors, map[string]any{"name": "identifier-final-newline", "message": c.BootstrapTokenRequestV1{SchemaVersion: c.BootstrapTokenRequestV1Version, DeviceID: "device:fixture\n"}, "contract_valid": false, "schema_valid": false})
	newlineWire, _ := json.Marshal(c.BootstrapTokenRequestV1{SchemaVersion: c.BootstrapTokenRequestV1Version, DeviceID: "device:fixture\n"})
	wires.Vectors = append(wires.Vectors, raw(map[string]any{"name": "bootstrap-identifier-final-newline", "reader_version": c.BootstrapTokenRequestV1Version, "wire": string(newlineWire), "expected_go": "invalid_contract", "expected_schema": "invalid_contract", "expected_python": "invalid_contract"}))
	write("packages/contracts/fixtures/bootstrap/v1-vectors.json", map[string]any{"schema_version": "device-audit.bootstrap-fixtures.v1", "vectors": vectors})
	write(wirePath, wires)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func write(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	must(err)
	must(os.WriteFile(path, append(data, '\n'), 0644))
}

func raw(value any) json.RawMessage { data, err := json.Marshal(value); must(err); return data }
