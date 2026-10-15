package contracts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"
)

type envelopeVector struct {
	Name               string          `json:"name"`
	Envelope           json.RawMessage `json:"envelope"`
	ContractValid      bool            `json:"contract_valid"`
	VerificationKey    string          `json:"verification_key"`
	SignatureValid     bool            `json:"signature_valid"`
	SignatureError     string          `json:"signature_error"`
	CanonicalHex       string          `json:"canonical_hex"`
	RequestSHA256      string          `json:"request_sha256"`
	Now                string          `json:"now"`
	LastSequence       uint64          `json:"last_sequence"`
	FreshnessRejection string          `json:"freshness_rejection"`
}

type signedEnvelope interface {
	Validate() error
	SigningBytes() ([]byte, error)
	VerifySignature(ed25519.PublicKey) error
}

func loadEnvelopeVectors(t *testing.T) []envelopeVector {
	t.Helper()
	data, err := os.ReadFile("fixtures/envelopes/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Vectors []envelopeVector `json:"vectors"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if len(fixture.Vectors) == 0 {
		t.Fatal("no envelope vectors")
	}
	return fixture.Vectors
}

func decodeSignedEnvelope(data []byte) (signedEnvelope, error) {
	var version struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &version); err != nil {
		return nil, err
	}
	var value signedEnvelope
	switch version.SchemaVersion {
	case EnrollmentV1Version:
		value = &EnrollmentEnvelopeV1{}
	case EvidenceEnvelopeV1Version:
		value = &EvidenceEnvelopeV1{}
	default:
		value = &AcknowledgementV1{}
	}
	return value, json.Unmarshal(data, value)
}

func TestEnvelopeV1GoldenVectors(t *testing.T) {
	for _, vector := range loadEnvelopeVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			envelope, err := decodeSignedEnvelope(vector.Envelope)
			if err == nil {
				err = envelope.Validate()
			}
			if (err == nil) != vector.ContractValid {
				t.Fatalf("contract valid=%t want %t: %v", err == nil, vector.ContractValid, err)
			}
			if !vector.ContractValid {
				return
			}
			canonical, err := envelope.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(canonical) != vector.CanonicalHex {
				t.Fatalf("canonical bytes changed: %x", canonical)
			}
			key, err := hex.DecodeString(vector.VerificationKey)
			if err != nil {
				t.Fatal(err)
			}
			err = envelope.VerifySignature(key)
			if (err == nil) != vector.SignatureValid {
				t.Fatalf("signature valid=%t want %t: %v", err == nil, vector.SignatureValid, err)
			}
			if err != nil && err.Error() != vector.SignatureError {
				t.Fatalf("signature error=%v want %s", err, vector.SignatureError)
			}
			var header EnvelopeHeaderV1
			var signature string
			switch value := envelope.(type) {
			case *EnrollmentEnvelopeV1:
				header, signature = value.EnvelopeHeaderV1, value.Signature
			case *EvidenceEnvelopeV1:
				header, signature = value.EnvelopeHeaderV1, value.Signature
			case *AcknowledgementV1:
				return
			}
			digest, err := EnvelopeRequestSHA256V1(canonical, signature)
			if err != nil {
				t.Fatal(err)
			}
			if digest != vector.RequestSHA256 {
				t.Fatalf("request digest=%s want %s", digest, vector.RequestSHA256)
			}
			if !vector.SignatureValid {
				return
			}
			now, err := time.Parse(time.RFC3339, vector.Now)
			if err != nil {
				t.Fatal(err)
			}
			reason, err := header.FreshnessRejection(now, vector.LastSequence)
			if err != nil || reason != vector.FreshnessRejection {
				t.Fatalf("freshness=%s (%v), want %s", reason, err, vector.FreshnessRejection)
			}
		})
	}
}

func TestEnvelopeV1StrictDecoding(t *testing.T) {
	vectors := loadEnvelopeVectors(t)
	original := vectors[0].Envelope
	var compact bytes.Buffer
	if err := json.Compact(&compact, original); err != nil {
		t.Fatal(err)
	}
	data := compact.String()
	for _, invalid := range []string{
		data + " {}",
		data[:len(data)-1] + `,"sequence":1}`,
		data[:len(data)-1] + `,"Sequence":1}`,
		data[:len(data)-1] + `,"mesh_credential":"forbidden-fixture"}`,
		string(bytes.ReplaceAll([]byte(data), []byte(`"sequence":1`), []byte(`"sequence":1.0`))),
		string(bytes.ReplaceAll([]byte(data), []byte(`"sequence":1`), []byte(`"sequence":true`))),
	} {
		if _, err := decodeSignedEnvelope([]byte(invalid)); err == nil {
			t.Fatalf("accepted invalid wire: %s", invalid)
		}
	}
	var report EvidenceEnvelopeV1
	if err := json.Unmarshal(vectors[1].Envelope, &report); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(report.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	payload = bytes.Replace(payload, []byte(`"value":0`), []byte(`"value":0,"value":10`), 1)
	setEvidencePayload(&report, payload)
	if err := report.Validate(); err == nil {
		t.Fatal("accepted duplicate nested payload key")
	}
}

func setEvidencePayload(report *EvidenceEnvelopeV1, payload []byte) {
	report.PayloadBase64 = base64.StdEncoding.EncodeToString(payload)
	digest := sha256.Sum256(payload)
	report.PayloadSHA256 = hex.EncodeToString(digest[:])
}

func TestEnvelopeV1PayloadSizeAndUTF8(t *testing.T) {
	vectors := loadEnvelopeVectors(t)
	var report EvidenceEnvelopeV1
	if err := json.Unmarshal(vectors[1].Envelope, &report); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(report.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	maximum := append(bytes.Clone(payload), bytes.Repeat([]byte(" "), MaxEvidencePayloadBytes-len(payload))...)
	setEvidencePayload(&report, maximum)
	if err := report.Validate(); err != nil {
		t.Fatalf("maximum payload rejected: %v", err)
	}
	setEvidencePayload(&report, append(maximum, ' '))
	if err := report.Validate(); err == nil {
		t.Fatal("oversized payload accepted")
	}
	setEvidencePayload(&report, append(payload, 0xff))
	if err := report.Validate(); err == nil {
		t.Fatal("invalid UTF-8 payload accepted")
	}
}

func TestEnvelopeV1WrongSignerAndDomain(t *testing.T) {
	vectors := loadEnvelopeVectors(t)
	var report EvidenceEnvelopeV1
	if err := json.Unmarshal(vectors[1].Envelope, &report); err != nil {
		t.Fatal(err)
	}
	message, err := report.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := hex.DecodeString(vectors[1].VerificationKey)
	if err != nil {
		t.Fatal(err)
	}
	// Public RFC 8032 test seed for a different key, never an operational secret.
	seed, err := hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	if err != nil {
		t.Fatal(err)
	}
	report.Signature = hex.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), message))
	if err := report.VerifySignature(deviceKey); err == nil || err.Error() != "invalid_signature" {
		t.Fatalf("wrong signer accepted: %v", err)
	}
	if err := report.VerifySignature(nil); err == nil {
		t.Fatal("invalid-length key accepted")
	}
	var original EvidenceEnvelopeV1
	if err := json.Unmarshal(vectors[1].Envelope, &original); err != nil {
		t.Fatal(err)
	}
	sig, _ := hex.DecodeString(original.Signature)
	for _, altered := range [][]byte{message[len(envelopeDomain):], append([]byte("other-domain\x00"), message...), append(bytes.Clone(message), 0)} {
		if ed25519.Verify(deviceKey, altered, sig) {
			t.Fatal("altered signing domain or trailing bytes accepted")
		}
	}
}

func TestEnvelopeV1UnsignedConstructionAndClockFailures(t *testing.T) {
	vectors := loadEnvelopeVectors(t)
	for _, vector := range vectors {
		if !vector.ContractValid {
			continue
		}
		value, err := decodeSignedEnvelope(vector.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		var signature *string
		switch v := value.(type) {
		case *EnrollmentEnvelopeV1:
			signature = &v.Signature
		case *EvidenceEnvelopeV1:
			signature = &v.Signature
		case *AcknowledgementV1:
			signature = &v.Signature
		}
		*signature = ""
		if _, err := value.SigningBytes(); err != nil {
			t.Fatalf("unsigned construction cannot sign: %v", err)
		}
		if err := value.Validate(); err == nil {
			t.Fatal("unsigned envelope validated")
		}
	}
	var enrollment EnrollmentEnvelopeV1
	if err := json.Unmarshal(vectors[0].Envelope, &enrollment); err != nil {
		t.Fatal(err)
	}
	if _, err := enrollment.FreshnessRejection(time.Time{}, 0); err == nil {
		t.Fatal("zero receiver clock accepted")
	}
	if _, err := enrollment.FreshnessRejection(time.Now(), MaxEnvelopeSequence+1); err == nil {
		t.Fatal("invalid durable mark accepted")
	}
}

func TestEnvelopeV1RejectedBodyCanBeCorrelated(t *testing.T) {
	vectors := loadEnvelopeVectors(t)
	var report EvidenceEnvelopeV1
	if err := json.Unmarshal(vectors[1].Envelope, &report); err != nil {
		t.Fatal(err)
	}
	report.PayloadBase64 = base64.StdEncoding.EncodeToString([]byte(`{"altered":"fixture"}`))
	if err := report.Validate(); err == nil {
		t.Fatal("altered payload validated")
	}
	message, err := report.SigningBytes()
	if err != nil {
		t.Fatalf("cannot correlate rejection: %v", err)
	}
	digest, err := EnvelopeRequestSHA256V1(message, report.Signature)
	if err != nil || digest != vectors[1].RequestSHA256 {
		t.Fatalf("declared commitment fingerprint changed: %s (%v)", digest, err)
	}
	key, err := hex.DecodeString(vectors[1].VerificationKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.VerifySignature(key); err == nil || err.Error() != "payload_digest_mismatch" {
		t.Fatalf("invalid body passed signature API: %v", err)
	}
}

func TestEnvelopeV1DecodeReplacesReusedValue(t *testing.T) {
	vectors := loadEnvelopeVectors(t)
	var value AcknowledgementV1
	for _, name := range []string{"explicit rejection replay", "accepted durable evidence acknowledgement"} {
		for _, vector := range vectors {
			if vector.Name == name {
				if err := json.Unmarshal(vector.Envelope, &value); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	if value.Status != "accepted" || value.RejectionReason != nil || value.LastSequence == nil || *value.LastSequence != 2 {
		t.Fatalf("stale acknowledgement data: %+v", value)
	}
}
