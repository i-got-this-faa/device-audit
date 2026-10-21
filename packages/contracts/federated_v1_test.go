package contracts

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type federatedVector struct {
	Name           string          `json:"name"`
	Payload        json.RawMessage `json:"payload"`
	Valid          bool            `json:"valid"`
	ContextValid   bool            `json:"context_valid"`
	SignatureValid bool            `json:"signature_valid"`
	CanonicalHex   string          `json:"canonical_hex"`
}
type federatedCollection struct {
	Key     string            `json:"verification_key"`
	Now     string            `json:"now"`
	Vectors []federatedVector `json:"vectors"`
}

func federatedVectors(t *testing.T) federatedCollection {
	t.Helper()
	data, err := os.ReadFile("fixtures/federated/v1-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var c federatedCollection
	if err = json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if len(c.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	return c
}
func TestFederatedV1Vectors(t *testing.T) {
	collection := federatedVectors(t)
	var round FederatedRoundV1
	if err := json.Unmarshal(collection.Vectors[0].Payload, &round); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, collection.Now)
	if err != nil {
		t.Fatal(err)
	}
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
			case FederatedRoundV1Version:
				value = &FederatedRoundV1{}
			case FederatedUpdateV1Version:
				value = &FederatedUpdateV1{}
			case FederatedPromotionV1Version:
				value = &FederatedPromotionV1{}
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
			switch p := value.(type) {
			case *FederatedUpdateV1:
				if err := p.CheckRound(round, now); (err == nil) != v.ContextValid {
					t.Fatalf("round compatibility mismatch: %v", err)
				}
				if err := p.VerifySignature(key); (err == nil) != v.SignatureValid {
					t.Fatalf("signature mismatch: %v", err)
				}
				if v.CanonicalHex != "" {
					message, err := p.SigningBytes()
					if err != nil {
						t.Fatal(err)
					}
					if hex.EncodeToString(message) != v.CanonicalHex {
						t.Fatal("canonical bytes changed")
					}
				}
			case *FederatedPromotionV1:
				if err := p.CheckRound(round); (err == nil) != v.ContextValid {
					t.Fatalf("promotion context mismatch: %v", err)
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
				t.Fatal("round trip changed values or nulls")
			}
		})
	}
}
func TestFederatedUpdateAdmissionBoundaries(t *testing.T) {
	c := federatedVectors(t)
	var round FederatedRoundV1
	_ = json.Unmarshal(c.Vectors[0].Payload, &round)
	var update FederatedUpdateV1
	for _, v := range c.Vectors {
		if v.Name == "update" {
			if err := json.Unmarshal(v.Payload, &update); err != nil {
				t.Fatal(err)
			}
		}
	}
	if update.RoundID == "" {
		t.Fatal("no update")
	}
	for _, tc := range []struct {
		at    string
		valid bool
	}{{"2026-10-19T12:09:59Z", false}, {"2026-10-19T12:10:00Z", true}, {"2026-10-19T12:59:59Z", true}, {"2026-10-19T13:00:00Z", false}} {
		now, err := time.Parse(time.RFC3339, tc.at)
		if err != nil {
			t.Fatal(err)
		}
		if err := update.CheckRound(round, now); (err == nil) != tc.valid {
			t.Errorf("admission at %s: %v", tc.at, err)
		}
	}
	weights, err := DecodeFederatedWeightsV1(update.WeightsBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(weights, []float64{0.25, -0.5}) {
		t.Fatalf("wrong IEEE754 endian/order: %v", weights)
	}
}
func TestFederatedStrictJSON(t *testing.T) {
	var original string
	for _, v := range federatedVectors(t).Vectors {
		if v.Name == "update" {
			var b bytes.Buffer
			if err := json.Compact(&b, v.Payload); err != nil {
				t.Fatal(err)
			}
			original = b.String()
		}
	}
	if original == "" {
		t.Fatal("no update")
	}
	for _, wire := range []string{strings.Replace(original, `"sequence":2`, `"sequence":2,"sequence":3`, 1), strings.Replace(original, `"sample_count":24`, `"sample_count":24.0`, 1), strings.Replace(original, `"sample_count":24,`, "", 1), strings.Replace(original, `"sample_count":24`, `"sample_count":null`, 1), original + ` {}`} {
		if wire == original {
			t.Fatal("unchanged mutation")
		}
		var u FederatedUpdateV1
		if json.Unmarshal([]byte(wire), &u) == nil {
			t.Fatal("accepted invalid JSON")
		}
	}
}
