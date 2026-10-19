//go:build ignore

// Regenerate with go run packages/contracts/fixtures/federated/generate.go.
// The signing seed is public RFC 8032 test material, never an operational key.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	c "github.com/i-got-this-faa/device-audit/packages/contracts"
	"math"
	"os"
	"strings"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func ptr[T any](v T) *T { return &v }

type vector struct {
	Name           string `json:"name"`
	Payload        any    `json:"payload"`
	Valid          bool   `json:"valid"`
	SchemaValid    bool   `json:"schema_valid"`
	ContextValid   bool   `json:"context_valid"`
	SignatureValid bool   `json:"signature_valid"`
	CanonicalHex   string `json:"canonical_hex"`
}

func encode(values ...float64) (string, string) {
	var raw []byte
	for _, v := range values {
		raw = binary.BigEndian.AppendUint64(raw, math.Float64bits(v))
	}
	sum := sha256.Sum256(raw)
	return base64.StdEncoding.EncodeToString(raw), hex.EncodeToString(sum[:])
}
func main() {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	key := ed25519.NewKeyFromSeed(seed)
	keyID, _ := c.SigningKeyIDV1(ed25519.PublicKey(key[32:]))
	r := c.FederatedRoundV1{SchemaVersion: c.FederatedRoundV1Version, DeploymentID: "deployment-a", RoundID: "round-a", BaseModelVersion: "base.v1", BaseModelSHA256: strings.Repeat("a", 64), CandidateID: "candidate-a", FeatureVersion: "features.v1", ParameterCount: 2, OpenedAt: "2026-10-19T12:00:00Z", Deadline: "2026-10-19T13:00:00Z", MinParticipants: 2, Participants: []c.FederatedParticipantV1{{DeviceID: "device-a", SigningKeyID: keyID, Eligibility: "eligible"}, {DeviceID: "device-b", SigningKeyID: keyID, Eligibility: "eligible"}, {DeviceID: "device-c", SigningKeyID: keyID, Eligibility: "ineligible", Reason: ptr("insufficient_local_data")}}}
	var vectors []vector
	add := func(n string, p any, valid, schema, context, signature bool, canonical []byte) {
		vectors = append(vectors, vector{n, p, valid, schema, context, signature, hex.EncodeToString(canonical)})
	}
	add("round", r, true, true, true, false, nil)
	badRound := r
	badRound.Participants = append(append([]c.FederatedParticipantV1{}, r.Participants...), r.Participants[0])
	add("duplicate_participant", badRound, false, true, false, false, nil)
	badRound = r
	badRound.Deadline = badRound.OpenedAt
	add("empty_round_window", badRound, false, true, false, false, nil)
	weights, digest := encode(0.25, -0.5)
	u := c.FederatedUpdateV1{EnvelopeHeaderV1: c.EnvelopeHeaderV1{SchemaVersion: c.FederatedUpdateV1Version, DeploymentID: r.DeploymentID, DeviceID: "device-a", SigningKeyID: keyID, Sequence: 2, IssuedAt: "2026-10-19T12:10:00Z", ExpiresAt: "2026-10-19T13:00:00Z"}, RoundID: r.RoundID, BaseModelVersion: r.BaseModelVersion, BaseModelSHA256: r.BaseModelSHA256, CandidateID: r.CandidateID, FeatureVersion: r.FeatureVersion, SampleCount: 24, WeightsBase64: weights, UpdateSHA256: digest}
	sign := func(u c.FederatedUpdateV1) c.FederatedUpdateV1 {
		m, err := u.SigningBytes()
		must(err)
		u.Signature = hex.EncodeToString(ed25519.Sign(key, m))
		return u
	}
	addSigned := func(n string, u c.FederatedUpdateV1, context bool) {
		u = sign(u)
		m, _ := u.SigningBytes()
		add(n, u, true, true, context, true, m)
	}
	u = sign(u)
	addSigned("update", u, true)
	v := u
	v.BaseModelVersion = "other-base.v1"
	addSigned("incompatible_base", v, false)
	v = u
	v.BaseModelSHA256 = strings.Repeat("b", 64)
	addSigned("incompatible_base_digest", v, false)
	v = u
	v.FeatureVersion = "features.v2"
	addSigned("incompatible_features", v, false)
	v = u
	v.DeviceID = "device-c"
	addSigned("ineligible_participant", v, false)
	v = u
	v.WeightsBase64, v.UpdateSHA256 = encode(1)
	addSigned("incompatible_dimensions", v, false)
	v = u
	v.ExpiresAt = "2026-10-19T13:00:01Z"
	addSigned("expiry_after_round", v, false)
	v = u
	v.SampleCount = 25
	add("tampered_sample_count", v, true, true, true, false, nil)
	v = u
	v.SampleCount = 0
	add("zero_samples", v, false, false, false, false, nil)
	v = u
	v.WeightsBase64, v.UpdateSHA256 = encode(math.NaN(), 1)
	add("nonfinite_nan_update", v, false, true, false, false, nil)
	v = u
	v.WeightsBase64, v.UpdateSHA256 = encode(math.Inf(1), 1)
	add("nonfinite_infinity_update", v, false, true, false, false, nil)
	v = u
	v.UpdateSHA256 = strings.Repeat("f", 64)
	add("digest_mismatch", v, false, true, false, false, nil)
	raw, _ := json.Marshal(u)
	var fields map[string]any
	must(json.Unmarshal(raw, &fields))
	fields["observations"] = []any{1, 2}
	add("raw_observations_not_in_contract", fields, false, false, false, false, nil)
	p := c.FederatedPromotionV1{SchemaVersion: c.FederatedPromotionV1Version, DeploymentID: r.DeploymentID, RoundID: r.RoundID, CandidateID: r.CandidateID, BaseModelVersion: r.BaseModelVersion, BaseModelSHA256: r.BaseModelSHA256, FeatureVersion: r.FeatureVersion, CandidateModelVersion: ptr("candidate.v2"), CandidateModelSHA256: ptr(strings.Repeat("c", 64)), EvaluationSHA256: ptr(strings.Repeat("e", 64)), PolicyVersion: "heldout-policy.v1", DecidedAt: r.Deadline, Decision: "promoted", AcceptedParticipants: []string{"device-a", "device-b"}}
	add("promoted", p, true, true, true, false, nil)
	q := p
	q.Decision = "rejected"
	q.Reason = ptr("evaluation_failed")
	add("failed_promotion", q, true, true, true, false, nil)
	q = p
	q.Decision = "rejected"
	q.Reason = ptr("insufficient_participants")
	q.AcceptedParticipants = []string{"device-a"}
	q.CandidateModelVersion = nil
	q.CandidateModelSHA256 = nil
	q.EvaluationSHA256 = nil
	add("no_quorum", q, true, true, true, false, nil)
	q = p
	q.EvaluationSHA256 = nil
	add("promotion_without_evaluation", q, false, false, false, false, nil)
	q = p
	q.AcceptedParticipants = []string{"device-a", "device-a"}
	add("duplicate_accepted_participant", q, false, false, false, false, nil)
	q = p
	q.DecidedAt = "2026-10-19T12:59:59Z"
	add("premature_promotion", q, true, true, false, false, nil)
	q = p
	q.AcceptedParticipants = []string{"device-a", "device-c"}
	add("promotion_with_ineligible_participant", q, true, true, false, false, nil)
	out, err := json.MarshalIndent(map[string]any{"verification_key": hex.EncodeToString(key[32:]), "now": "2026-10-19T12:30:00Z", "vectors": vectors}, "", "  ")
	must(err)
	must(os.WriteFile("packages/contracts/fixtures/federated/v1-vectors.json", append(out, '\n'), 0644))
}
