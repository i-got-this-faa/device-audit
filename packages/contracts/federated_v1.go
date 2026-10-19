package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"time"
)

const (
	FederatedRoundV1Version     = "device-audit.federated-round.v1"
	FederatedUpdateV1Version    = "device-audit.federated-update.v1"
	FederatedPromotionV1Version = "device-audit.federated-promotion.v1"
)

type FederatedParticipantV1 struct {
	DeviceID     string  `json:"device_id"`
	SigningKeyID string  `json:"signing_key_id"`
	Eligibility  string  `json:"eligibility"`
	Reason       *string `json:"reason"`
}

type FederatedRoundV1 struct {
	SchemaVersion    string                   `json:"schema_version"`
	DeploymentID     string                   `json:"deployment_id"`
	RoundID          string                   `json:"round_id"`
	BaseModelVersion string                   `json:"base_model_version"`
	BaseModelSHA256  string                   `json:"base_model_sha256"`
	CandidateID      string                   `json:"candidate_id"`
	FeatureVersion   string                   `json:"feature_version"`
	ParameterCount   uint32                   `json:"parameter_count"`
	OpenedAt         string                   `json:"opened_at"`
	Deadline         string                   `json:"deadline"`
	MinParticipants  uint32                   `json:"min_participants"`
	Participants     []FederatedParticipantV1 `json:"participants"`
}

// Weights are a bounded model parameter vector, never local observations.
// The header identifies the participating device's application signing key.
type FederatedUpdateV1 struct {
	EnvelopeHeaderV1
	RoundID          string `json:"round_id"`
	BaseModelVersion string `json:"base_model_version"`
	BaseModelSHA256  string `json:"base_model_sha256"`
	CandidateID      string `json:"candidate_id"`
	FeatureVersion   string `json:"feature_version"`
	SampleCount      uint32 `json:"sample_count"`
	WeightsBase64    string `json:"weights_base64"`
	UpdateSHA256     string `json:"update_sha256"`
	Signature        string `json:"signature"`
}

type FederatedPromotionV1 struct {
	SchemaVersion         string   `json:"schema_version"`
	DeploymentID          string   `json:"deployment_id"`
	RoundID               string   `json:"round_id"`
	CandidateID           string   `json:"candidate_id"`
	BaseModelVersion      string   `json:"base_model_version"`
	BaseModelSHA256       string   `json:"base_model_sha256"`
	FeatureVersion        string   `json:"feature_version"`
	CandidateModelVersion *string  `json:"candidate_model_version"`
	CandidateModelSHA256  *string  `json:"candidate_model_sha256"`
	EvaluationSHA256      *string  `json:"evaluation_sha256"`
	PolicyVersion         string   `json:"policy_version"`
	DecidedAt             string   `json:"decided_at"`
	Decision              string   `json:"decision"`
	Reason                *string  `json:"reason"`
	AcceptedParticipants  []string `json:"accepted_participants"`
}

func (p *FederatedParticipantV1) UnmarshalJSON(data []byte) error {
	type wire FederatedParticipantV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"device_id", "signing_key_id", "eligibility", "reason"}, "reason"); err != nil {
		return err
	}
	*p = FederatedParticipantV1(v)
	return nil
}
func (r *FederatedRoundV1) UnmarshalJSON(data []byte) error {
	type wire FederatedRoundV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "deployment_id", "round_id", "base_model_version", "base_model_sha256", "candidate_id", "feature_version", "parameter_count", "opened_at", "deadline", "min_participants", "participants"}); err != nil {
		return err
	}
	*r = FederatedRoundV1(v)
	return nil
}
func (u *FederatedUpdateV1) UnmarshalJSON(data []byte) error {
	type wire FederatedUpdateV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at", "round_id", "base_model_version", "base_model_sha256", "candidate_id", "feature_version", "sample_count", "weights_base64", "update_sha256", "signature"}); err != nil {
		return err
	}
	*u = FederatedUpdateV1(v)
	return nil
}
func (p *FederatedPromotionV1) UnmarshalJSON(data []byte) error {
	type wire FederatedPromotionV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "deployment_id", "round_id", "candidate_id", "base_model_version", "base_model_sha256", "feature_version", "candidate_model_version", "candidate_model_sha256", "evaluation_sha256", "policy_version", "decided_at", "decision", "reason", "accepted_participants"}, "candidate_model_version", "candidate_model_sha256", "evaluation_sha256", "reason"); err != nil {
		return err
	}
	*p = FederatedPromotionV1(v)
	return nil
}

func (r FederatedRoundV1) Validate() error {
	if r.SchemaVersion != FederatedRoundV1Version || !opaqueIDPattern.MatchString(r.DeploymentID) || !opaqueIDPattern.MatchString(r.RoundID) || !opaqueIDPattern.MatchString(r.BaseModelVersion) || !fixedEnvelopeHex(r.BaseModelSHA256, 32) || !opaqueIDPattern.MatchString(r.CandidateID) || !opaqueIDPattern.MatchString(r.FeatureVersion) || r.ParameterCount < 1 || r.ParameterCount > 4096 || r.MinParticipants < 2 || r.MinParticipants > 128 || len(r.Participants) < 2 || len(r.Participants) > 128 {
		return fmt.Errorf("invalid round identity or bounds")
	}
	opened, err := parseEnvelopeTime(r.OpenedAt)
	if err != nil {
		return err
	}
	deadline, err := parseEnvelopeTime(r.Deadline)
	if err != nil {
		return err
	}
	if !deadline.After(opened) || deadline.Sub(opened) > 7*24*time.Hour {
		return fmt.Errorf("round lifetime outside (0,7 days]")
	}
	seen := map[string]bool{}
	eligible := uint32(0)
	for _, p := range r.Participants {
		if !opaqueIDPattern.MatchString(p.DeviceID) || !validEnvelopeKeyID(p.SigningKeyID) || seen[p.DeviceID] {
			return fmt.Errorf("invalid or duplicate participant")
		}
		seen[p.DeviceID] = true
		switch p.Eligibility {
		case "eligible":
			if p.Reason != nil {
				return fmt.Errorf("eligible participant requires null reason")
			}
			eligible++
		case "ineligible":
			if p.Reason == nil || (*p.Reason != "revoked" && *p.Reason != "incompatible_features" && *p.Reason != "insufficient_local_data" && *p.Reason != "not_authorized") {
				return fmt.Errorf("ineligible participant requires reason")
			}
		default:
			return fmt.Errorf("invalid participant eligibility")
		}
	}
	if eligible < r.MinParticipants {
		return fmt.Errorf("not enough eligible participants")
	}
	return nil
}

// DecodeFederatedWeightsV1 checks canonical base64 and finite big-endian IEEE754
// binary64 weights. Model architecture and feature compatibility are separate.
func DecodeFederatedWeightsV1(encoded string) ([]float64, error) {
	if len(encoded) > base64.StdEncoding.EncodedLen(4096*8) {
		return nil, fmt.Errorf("update exceeds parameter bound")
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) == 0 || len(data)%8 != 0 || len(data) > 4096*8 || base64.StdEncoding.EncodeToString(data) != encoded {
		return nil, fmt.Errorf("invalid canonical binary64 update")
	}
	weights := make([]float64, len(data)/8)
	for i := range weights {
		weights[i] = math.Float64frombits(binary.BigEndian.Uint64(data[i*8:]))
		if math.IsNaN(weights[i]) || math.IsInf(weights[i], 0) {
			return nil, fmt.Errorf("nonfinite update")
		}
	}
	return weights, nil
}

func (u FederatedUpdateV1) validateBody() error {
	if err := u.EnvelopeHeaderV1.validate(FederatedUpdateV1Version, 24*time.Hour); err != nil {
		return err
	}
	if u.Sequence < 2 || !opaqueIDPattern.MatchString(u.RoundID) || !opaqueIDPattern.MatchString(u.BaseModelVersion) || !fixedEnvelopeHex(u.BaseModelSHA256, 32) || !opaqueIDPattern.MatchString(u.CandidateID) || !opaqueIDPattern.MatchString(u.FeatureVersion) || u.SampleCount < 1 || u.SampleCount > 1000000000 || !fixedEnvelopeHex(u.UpdateSHA256, 32) {
		return fmt.Errorf("invalid update metadata")
	}
	if _, err := DecodeFederatedWeightsV1(u.WeightsBase64); err != nil {
		return err
	}
	data, _ := base64.StdEncoding.DecodeString(u.WeightsBase64)
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != u.UpdateSHA256 {
		return fmt.Errorf("update_digest_mismatch")
	}
	return nil
}
func (u FederatedUpdateV1) Validate() error {
	if err := u.validateBody(); err != nil {
		return err
	}
	return validateEnvelopeSignature(u.Signature)
}
func (u FederatedUpdateV1) SigningBytes() ([]byte, error) {
	if err := u.validateBody(); err != nil {
		return nil, err
	}
	return canonicalEnvelopeFields(append(u.signingFields(), u.RoundID, u.BaseModelVersion, u.BaseModelSHA256, u.CandidateID, u.FeatureVersion, strconv.FormatUint(uint64(u.SampleCount), 10), u.UpdateSHA256)), nil
}
func (u FederatedUpdateV1) VerifySignature(trustedDeviceKey ed25519.PublicKey) error {
	message, err := u.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(trustedDeviceKey, u.SigningKeyID, u.Signature, message)
}

// CheckRound checks a single update against an authorized round and receiver
// clock. Atomic duplicate/sequence admission and key trust remain consumer work.
func (u FederatedUpdateV1) CheckRound(r FederatedRoundV1, now time.Time) error {
	if err := u.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if u.DeploymentID != r.DeploymentID || u.RoundID != r.RoundID || u.BaseModelVersion != r.BaseModelVersion || u.BaseModelSHA256 != r.BaseModelSHA256 || u.CandidateID != r.CandidateID || u.FeatureVersion != r.FeatureVersion {
		return fmt.Errorf("incompatible round, base, candidate or feature version")
	}
	opened, _ := parseEnvelopeTime(r.OpenedAt)
	deadline, _ := parseEnvelopeTime(r.Deadline)
	issued, _ := parseEnvelopeTime(u.IssuedAt)
	expires, _ := parseEnvelopeTime(u.ExpiresAt)
	if now.IsZero() || now.Before(opened) || !now.Before(deadline) || now.Before(issued) || !now.Before(expires) || issued.Before(opened) || !issued.Before(deadline) || expires.After(deadline) {
		return fmt.Errorf("update outside round or freshness window")
	}
	weights, _ := DecodeFederatedWeightsV1(u.WeightsBase64)
	if uint32(len(weights)) != r.ParameterCount {
		return fmt.Errorf("incompatible parameter count")
	}
	for _, p := range r.Participants {
		if p.DeviceID == u.DeviceID && p.SigningKeyID == u.SigningKeyID && p.Eligibility == "eligible" {
			return nil
		}
	}
	return fmt.Errorf("participant is not eligible with this key")
}

func (p FederatedPromotionV1) Validate() error {
	if p.SchemaVersion != FederatedPromotionV1Version || !opaqueIDPattern.MatchString(p.DeploymentID) || !opaqueIDPattern.MatchString(p.RoundID) || !opaqueIDPattern.MatchString(p.CandidateID) || !opaqueIDPattern.MatchString(p.BaseModelVersion) || !fixedEnvelopeHex(p.BaseModelSHA256, 32) || !opaqueIDPattern.MatchString(p.FeatureVersion) || !opaqueIDPattern.MatchString(p.PolicyVersion) || p.AcceptedParticipants == nil || len(p.AcceptedParticipants) > 128 {
		return fmt.Errorf("invalid promotion metadata")
	}
	if _, err := parseEnvelopeTime(p.DecidedAt); err != nil {
		return err
	}
	if (p.CandidateModelVersion == nil) != (p.CandidateModelSHA256 == nil) {
		return fmt.Errorf("candidate version and digest must both be present or null")
	}
	if p.CandidateModelVersion != nil && (!opaqueIDPattern.MatchString(*p.CandidateModelVersion) || !fixedEnvelopeHex(*p.CandidateModelSHA256, 32)) {
		return fmt.Errorf("invalid candidate artifact")
	}
	if p.EvaluationSHA256 != nil && !fixedEnvelopeHex(*p.EvaluationSHA256, 32) {
		return fmt.Errorf("invalid evaluation digest")
	}
	seen := map[string]bool{}
	for _, id := range p.AcceptedParticipants {
		if !opaqueIDPattern.MatchString(id) || seen[id] {
			return fmt.Errorf("invalid or duplicate accepted participant")
		}
		seen[id] = true
	}
	switch p.Decision {
	case "promoted":
		if p.Reason != nil || p.CandidateModelVersion == nil || p.EvaluationSHA256 == nil || len(p.AcceptedParticipants) < 2 || *p.CandidateModelVersion == p.BaseModelVersion || *p.CandidateModelSHA256 == p.BaseModelSHA256 {
			return fmt.Errorf("promotion requires new evaluated artifact and participants")
		}
	case "rejected":
		if p.Reason == nil || (*p.Reason != "evaluation_failed" && *p.Reason != "insufficient_participants" && *p.Reason != "aggregation_failed" && *p.Reason != "cancelled") {
			return fmt.Errorf("rejection requires reason")
		}
		if *p.Reason == "evaluation_failed" && (p.CandidateModelVersion == nil || p.EvaluationSHA256 == nil) {
			return fmt.Errorf("failed evaluation requires artifact and evaluation evidence")
		}
	default:
		return fmt.Errorf("invalid promotion decision")
	}
	return nil
}

func (p FederatedPromotionV1) CheckRound(r FederatedRoundV1) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := r.Validate(); err != nil {
		return err
	}
	if p.DeploymentID != r.DeploymentID || p.RoundID != r.RoundID || p.CandidateID != r.CandidateID || p.BaseModelVersion != r.BaseModelVersion || p.BaseModelSHA256 != r.BaseModelSHA256 || p.FeatureVersion != r.FeatureVersion {
		return fmt.Errorf("promotion does not match round")
	}
	decided, _ := parseEnvelopeTime(p.DecidedAt)
	deadline, _ := parseEnvelopeTime(r.Deadline)
	opened, _ := parseEnvelopeTime(r.OpenedAt)
	if decided.Before(opened) {
		return fmt.Errorf("decision before round")
	}
	if p.Decision == "promoted" && (decided.Before(deadline) || len(p.AcceptedParticipants) < int(r.MinParticipants)) {
		return fmt.Errorf("promotion before close or without quorum")
	}
	for _, id := range p.AcceptedParticipants {
		eligible := false
		for _, member := range r.Participants {
			if id == member.DeviceID && member.Eligibility == "eligible" {
				eligible = true
				break
			}
		}
		if !eligible {
			return fmt.Errorf("accepted participant was not eligible")
		}
	}
	return nil
}
