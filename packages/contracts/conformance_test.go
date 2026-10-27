package contracts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

type contractWireVector struct {
	Name            string `json:"name"`
	ReaderVersion   string `json:"reader_version"`
	Wire            string `json:"wire"`
	ExpectedGo      string `json:"expected_go"`
	CanonicalHex    string `json:"canonical_hex"`
	VerificationKey string `json:"verification_key"`
	Now             string `json:"now"`
	LastSequence    uint64 `json:"last_sequence"`
}

func readContractWire(vector contractWireVector) (string, error) {
	data := []byte(vector.Wire)
	if err := rejectEnvelopeDuplicateKeys(data); err != nil {
		return "invalid_json", nil
	}
	var version struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &version); err != nil {
		return "invalid_contract", nil
	}
	if version.SchemaVersion != "" && version.SchemaVersion != vector.ReaderVersion {
		return "unsupported_schema", nil
	}
	var value interface{ Validate() error }
	switch vector.ReaderVersion {
	case BootstrapTokenRequestV1Version, BootstrapTokenV1Version, EnrollmentStartV1Version, EnrollmentChallengeV1Version, EnrollmentAdmissionV1Version, EnrollmentAcceptedV1Version, EnrollmentErrorV1Version:
		value = bootstrapReader(vector.ReaderVersion)
	case Version:
		value = &Telemetry{}
	case TelemetryV2Version:
		value = &TelemetryV2{}
	case PredictionV2Version:
		value = &PredictionV2{}
	case LifecycleV2Version:
		value = &LifecycleV2{}
	case EnrollmentV1Version:
		value = &EnrollmentEnvelopeV1{}
	case EvidenceEnvelopeV1Version:
		value = &EvidenceEnvelopeV1{}
	case AcknowledgementV1Version:
		value = &AcknowledgementV1{}
	case DiagnosticAssignmentV1Version:
		value = &DiagnosticAssignmentV1{}
	case DiagnosticResultV1Version:
		value = &DiagnosticResultV1{}
	case FederatedRoundV1Version:
		value = &FederatedRoundV1{}
	case FederatedUpdateV1Version:
		value = &FederatedUpdateV1{}
	case FederatedPromotionV1Version:
		value = &FederatedPromotionV1{}
	case AuditManifestV1Version:
		value = &AuditManifestV1{}
	case AuditCommitmentV1Version:
		value = &AuditCommitmentV1{}
	case AuditReceiptV1Version:
		value = &AuditReceiptV1{}
	case AuditVerificationV1Version:
		value = &AuditVerificationV1{}
	default:
		return "", fmt.Errorf("unregistered reader %s", vector.ReaderVersion)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return "invalid_contract", nil
	}
	if err := value.Validate(); err != nil {
		return "invalid_contract", nil
	}
	if vector.CanonicalHex != "" || vector.VerificationKey != "" {
		signed, ok := value.(signedEnvelope)
		if !ok {
			return "", fmt.Errorf("signed fixture has unsigned reader")
		}
		canonical, err := signed.SigningBytes()
		if err != nil {
			return "", err
		}
		if vector.CanonicalHex != "" && hex.EncodeToString(canonical) != vector.CanonicalHex {
			return "", fmt.Errorf("canonical signing bytes differ")
		}
		key, err := hex.DecodeString(vector.VerificationKey)
		if err != nil {
			return "", err
		}
		if err = signed.VerifySignature(key); err != nil {
			return err.Error(), nil
		}
	}
	if vector.Now != "" {
		now, err := time.Parse(time.RFC3339, vector.Now)
		if err != nil {
			return "", err
		}
		var header EnvelopeHeaderV1
		switch v := value.(type) {
		case *EnrollmentEnvelopeV1:
			header = v.EnvelopeHeaderV1
		case *EvidenceEnvelopeV1:
			header = v.EnvelopeHeaderV1
		default:
			return "", fmt.Errorf("freshness requires enrollment or evidence")
		}
		rejection, err := header.FreshnessRejection(now, vector.LastSequence)
		if err != nil {
			return "", err
		}
		if rejection != "" {
			return rejection, nil
		}
	}
	return "accepted", nil
}

func TestContractWireVectors(t *testing.T) {
	data, err := os.ReadFile("fixtures/conformance/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		SchemaVersion string               `json:"schema_version"`
		Vectors       []contractWireVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if collection.SchemaVersion != "device-audit.conformance-wire.v1" || len(collection.Vectors) == 0 {
		t.Fatal("missing or incompatible wire vectors")
	}
	for _, v := range collection.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := readContractWire(v)
			if err != nil || got != v.ExpectedGo {
				t.Fatalf("classification=%s error=%v, want %s", got, err, v.ExpectedGo)
			}
		})
	}
}
