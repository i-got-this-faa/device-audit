package contracts

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type diagnosticVector struct {
	Name           string          `json:"name"`
	Payload        json.RawMessage `json:"payload"`
	Valid          bool            `json:"valid"`
	SignatureValid bool            `json:"signature_valid"`
	PublicKey      string          `json:"public_key"`
	CanonicalHex   string          `json:"canonical_hex"`
}

func diagnosticVectors(t *testing.T) []diagnosticVector {
	t.Helper()
	data, err := os.ReadFile("fixtures/diagnostics/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var collection struct {
		Vectors []diagnosticVector `json:"vectors"`
	}
	if err = json.Unmarshal(data, &collection); err != nil {
		t.Fatal(err)
	}
	if len(collection.Vectors) == 0 {
		t.Fatal("missing vectors")
	}
	return collection.Vectors
}
func TestDiagnosticV1Vectors(t *testing.T) {
	for _, v := range diagnosticVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			var kind struct {
				Version string `json:"schema_version"`
			}
			if err := json.Unmarshal(v.Payload, &kind); err != nil {
				t.Fatal(err)
			}
			var value interface {
				Validate() error
				SigningBytes() ([]byte, error)
				VerifySignature(ed25519.PublicKey) error
			}
			if kind.Version == DiagnosticAssignmentV1Version {
				value = &DiagnosticAssignmentV1{}
			} else {
				value = &DiagnosticResultV1{}
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
			key, err := hex.DecodeString(v.PublicKey)
			if err != nil {
				t.Fatal(err)
			}
			if err = value.VerifySignature(key); (err == nil) != v.SignatureValid {
				t.Fatalf("signature validity mismatch: %v", err)
			}
			if v.CanonicalHex != "" {
				message, err := value.SigningBytes()
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(message) != v.CanonicalHex {
					t.Fatal("canonical bytes changed")
				}
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var got, want any
			_ = json.Unmarshal(encoded, &got)
			_ = json.Unmarshal(v.Payload, &want)
			if !reflect.DeepEqual(got, want) {
				t.Fatal("round trip changed nulls or values")
			}
		})
	}
}
func TestDiagnosticAssignmentAndTerminalCorrelation(t *testing.T) {
	vectors := diagnosticVectors(t)
	var a DiagnosticAssignmentV1
	if err := json.Unmarshal(vectors[0].Payload, &a); err != nil {
		t.Fatal(err)
	}
	now := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, tc := range []struct {
		at    string
		valid bool
	}{{"2026-10-19T11:59:59Z", false}, {"2026-10-19T12:00:00Z", true}, {"2026-10-19T12:04:00Z", true}, {"2026-10-19T12:04:01Z", false}, {"2026-10-19T12:05:00Z", false}} {
		if err := a.CanStart(now(tc.at)); (err == nil) != tc.valid {
			t.Errorf("CanStart(%s): %v", tc.at, err)
		}
	}
	var success DiagnosticResultV1
	for _, v := range vectors {
		var r DiagnosticResultV1
		if json.Unmarshal(v.Payload, &r) != nil || r.SchemaVersion != DiagnosticResultV1Version || !v.Valid {
			continue
		}
		if err := r.CheckAssignment(a); err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if v.Name == "succeeded" {
			success = r
		}
	}
	if success.State != "succeeded" {
		t.Fatal("missing success")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*DiagnosticResultV1)
	}{
		{"different device", func(r *DiagnosticResultV1) { r.DeviceID = "device-b" }},
		{"different deployment", func(r *DiagnosticResultV1) { r.DeploymentID = "deployment-b" }},
		{"different assignment", func(r *DiagnosticResultV1) { r.AssignmentID = "assignment-b" }},
		{"digest mismatch", func(r *DiagnosticResultV1) { r.AssignmentSHA256 = strings.Repeat("b", 64) }},
		{"output over budget", func(r *DiagnosticResultV1) {
			r.Evidence = append([]DiagnosticEvidenceV1{}, r.Evidence...)
			r.Evidence[0].SizeBytes = 4097
		}},
		{"wall over budget", func(r *DiagnosticResultV1) {
			r.FinishedAt = "2026-10-19T12:01:02Z"
			r.IssuedAt = r.FinishedAt
			r.ExpiresAt = "2026-10-20T12:01:02Z"
		}},
		{"early expiry", func(r *DiagnosticResultV1) {
			r.State = "expired"
			reason := "deadline_exceeded"
			r.Reason = &reason
			r.Evidence = []DiagnosticEvidenceV1{}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := success
			tc.mutate(&r)
			if r.CheckAssignment(a) == nil {
				t.Fatal("accepted invalid correlation")
			}
		})
	}
}
func TestDiagnosticStrictJSON(t *testing.T) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, diagnosticVectors(t)[0].Payload); err != nil {
		t.Fatal(err)
	}
	original := compact.String()
	for _, wire := range []string{strings.Replace(original, `"sequence":1`, `"sequence":1.0`, 1), strings.Replace(original, `"sequence":1`, `"sequence":1,"sequence":2`, 1), strings.Replace(original, `"component_id":"storage-a"`, `"component_id":"storage-a","command":"whoami"`, 1), strings.Replace(original, `"lookback_seconds":null,`, "", 1), original + ` {}`} {
		if wire == original {
			t.Fatal("mutation did not change wire")
		}
		var a DiagnosticAssignmentV1
		if json.Unmarshal([]byte(wire), &a) == nil {
			t.Fatal("accepted invalid wire")
		}
	}
}
