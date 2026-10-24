package contracts

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

func bootstrapReader(version string) interface{ Validate() error } {
	switch version {
	case BootstrapTokenRequestV1Version:
		return &BootstrapTokenRequestV1{}
	case BootstrapTokenV1Version:
		return &BootstrapTokenV1{}
	case EnrollmentStartV1Version:
		return &EnrollmentStartV1{}
	case EnrollmentChallengeV1Version:
		return &EnrollmentChallengeV1{}
	case EnrollmentAdmissionV1Version:
		return &EnrollmentAdmissionV1{}
	case EnrollmentAcceptedV1Version:
		return &EnrollmentAcceptedV1{}
	case EnrollmentErrorV1Version:
		return &EnrollmentErrorV1{}
	default:
		panic(fmt.Sprintf("unknown bootstrap fixture version %q", version))
	}
}

func TestBootstrapV1GoldenVectors(t *testing.T) {
	data, err := os.ReadFile("fixtures/bootstrap/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var catalogue struct {
		Vectors []struct {
			Name           string          `json:"name"`
			Message        json.RawMessage `json:"message"`
			ContractValid  bool            `json:"contract_valid"`
			CanonicalHex   string          `json:"canonical_hex"`
			SignatureValid bool            `json:"signature_valid"`
		}
	}
	if err := json.Unmarshal(data, &catalogue); err != nil {
		t.Fatal(err)
	}
	for _, vector := range catalogue.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			var version struct {
				SchemaVersion string `json:"schema_version"`
			}
			if err := json.Unmarshal(vector.Message, &version); err != nil {
				t.Fatal(err)
			}
			reader := bootstrapReader(version.SchemaVersion)
			err := json.Unmarshal(vector.Message, reader)
			if err == nil {
				err = reader.Validate()
			}
			if (err == nil) != vector.ContractValid {
				t.Fatalf("valid=%v want=%v: %v", err == nil, vector.ContractValid, err)
			}
			if !vector.ContractValid {
				return
			}
			if admission, ok := reader.(*EnrollmentAdmissionV1); ok {
				canonical, err := admission.SigningBytes()
				if err != nil || hex.EncodeToString(canonical) != vector.CanonicalHex {
					t.Fatalf("signing bytes differ: %x %v", canonical, err)
				}
				key, _ := hex.DecodeString(admission.Enrollment.PublicKey)
				if err := admission.VerifySignature(ed25519.PublicKey(key)); (err == nil) != vector.SignatureValid {
					t.Fatalf("signature valid=%v: %v", err == nil, err)
				}
			}
		})
	}
}

func TestBootstrapStrictDecoding(t *testing.T) {
	for _, wire := range []string{
		`{"schema_version":"device-audit.bootstrap-token-request.v1","device_id":"a","device_id":"b"}`,
		`{"schema_version":"device-audit.bootstrap-token-request.v1","device_id":null}`,
		`{"schema_version":"device-audit.bootstrap-token-request.v1","Device_ID":"a"}`,
		`{"schema_version":"device-audit.bootstrap-token-request.v1","device_id":"a","extra":true}`,
		`{"schema_version":"device-audit.bootstrap-token-request.v1","device_id":"a"}{}`,
	} {
		var value BootstrapTokenRequestV1
		if err := json.Unmarshal([]byte(wire), &value); err == nil {
			t.Fatalf("accepted invalid wire: %s", wire)
		}
	}
}
