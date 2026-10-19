package contracts

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type auditVector struct {
	Name           string          `json:"name"`
	Payload        json.RawMessage `json:"payload"`
	Valid          bool            `json:"valid"`
	SignatureValid bool            `json:"signature_valid"`
	CanonicalHex   string          `json:"canonical_hex"`
}
type auditCheck struct {
	Name     string `json:"name"`
	Manifest string `json:"manifest"`
	Bytes    string `json:"bytes"`
	Now      string `json:"now"`
	Status   string `json:"status"`
}
type auditCollection struct {
	Key       string            `json:"verification_key"`
	Artifacts map[string]string `json:"artifacts_base64"`
	Checks    []auditCheck      `json:"checks"`
	Vectors   []auditVector     `json:"vectors"`
}

func auditVectors(t *testing.T) auditCollection {
	t.Helper()
	data, err := os.ReadFile("fixtures/audit/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var c auditCollection
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Vectors) == 0 || len(c.Checks) == 0 {
		t.Fatal("missing audit vectors")
	}
	return c
}
func TestAuditV1Vectors(t *testing.T) {
	collection := auditVectors(t)
	key, err := hex.DecodeString(collection.Key)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range collection.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			var kind struct {
				Version string `json:"schema_version"`
			}
			if err := json.Unmarshal(v.Payload, &kind); err != nil {
				t.Fatal(err)
			}
			var value interface{ Validate() error }
			switch kind.Version {
			case AuditManifestV1Version:
				value = &AuditManifestV1{}
			case AuditCommitmentV1Version:
				value = &AuditCommitmentV1{}
			case AuditReceiptV1Version:
				value = &AuditReceiptV1{}
			case AuditVerificationV1Version:
				value = &AuditVerificationV1{}
			default:
				t.Fatal("unknown fixture version")
			}
			err := json.Unmarshal(v.Payload, value)
			if err == nil {
				err = value.Validate()
			}
			if (err == nil) != v.Valid {
				t.Fatalf("valid=%v want %v: %v", err == nil, v.Valid, err)
			}
			if !v.Valid {
				return
			}
			if m, ok := value.(*AuditManifestV1); ok {
				if err := m.VerifySignature(key); (err == nil) != v.SignatureValid {
					t.Fatalf("signature mismatch: %v", err)
				}
				if v.CanonicalHex != "" {
					message, err := m.SigningBytes()
					if err != nil {
						t.Fatal(err)
					}
					if hex.EncodeToString(message) != v.CanonicalHex {
						t.Fatal("canonical manifest bytes changed")
					}
				}
			}
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			_ = json.Unmarshal(raw, &got)
			_ = json.Unmarshal(v.Payload, &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("round trip changed values/nulls")
			}
		})
	}
}
func TestAuditEvidenceVerification(t *testing.T) {
	c := auditVectors(t)
	var manifest AuditManifestV1
	if err := json.Unmarshal(c.Vectors[0].Payload, &manifest); err != nil {
		t.Fatal(err)
	}
	var commitment AuditCommitmentV1
	if err := json.Unmarshal(c.Vectors[1].Payload, &commitment); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(c.Key)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := manifest.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	if expected != commitment {
		t.Fatal("commitment vector changed")
	}
	for _, tc := range c.Checks {
		t.Run(tc.Name, func(t *testing.T) {
			evidence := map[string][]byte{}
			for name, encoded := range c.Artifacts {
				raw, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				evidence[name] = raw
			}
			switch tc.Bytes {
			case "missing":
				delete(evidence, "evidence-a")
			case "altered":
				evidence["evidence-a"] = []byte("altered bytes")
			case "complete":
			default:
				t.Fatal("unknown byte case")
			}
			m := manifest
			var supplied *AuditManifestV1
			switch tc.Manifest {
			case "present":
				supplied = &m
			case "tampered_signature":
				m.Signature = strings.Repeat("0", 128)
				supplied = &m
			case "missing":
			default:
				t.Fatal("unknown manifest case")
			}
			now, err := time.Parse(time.RFC3339, tc.Now)
			if err != nil {
				t.Fatal(err)
			}
			status, err := CheckAuditEvidenceV1(commitment, supplied, evidence, key, now)
			if err != nil || status != tc.Status {
				t.Fatalf("status=%s error=%v, want %s", status, err, tc.Status)
			}
		})
	}
	wrong := commitment
	wrong.CommitmentSHA256 = strings.Repeat("f", 64)
	status, err := CheckAuditEvidenceV1(wrong, &manifest, nil, key, time.Date(2026, 10, 19, 12, 5, 0, 0, time.UTC))
	if err != nil || status != "digest_mismatch" {
		t.Fatalf("wrong commitment became %s, %v", status, err)
	}
	for _, v := range c.Vectors {
		var receipt AuditReceiptV1
		if json.Unmarshal(v.Payload, &receipt) != nil || receipt.SchemaVersion != AuditReceiptV1Version || !v.Valid {
			continue
		}
		if err := receipt.CheckCommitment(commitment); err != nil {
			t.Fatal(err)
		}
		if receipt.CheckCommitment(wrong) == nil {
			t.Fatal("accepted receipt for another digest")
		}
	}
}
func TestAuditStrictJSON(t *testing.T) {
	var b bytes.Buffer
	if err := json.Compact(&b, auditVectors(t).Vectors[0].Payload); err != nil {
		t.Fatal(err)
	}
	original := b.String()
	for _, wire := range []string{strings.Replace(original, `"size_bytes":`, `"command":"whoami","size_bytes":`, 1), strings.Replace(original, `"manifest_id":"manifest-a"`, `"manifest_id":"manifest-a","manifest_id":"other"`, 1), strings.Replace(original, `"evidence":[`, `"evidence":null,"ignored":[`, 1), original + ` {}`} {
		if wire == original {
			t.Fatal("unchanged mutation")
		}
		var m AuditManifestV1
		if json.Unmarshal([]byte(wire), &m) == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
