package contracts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

const (
	EnrollmentV1Version              = "device-audit.enrollment.v1"
	EvidenceEnvelopeV1Version        = "device-audit.evidence.v1"
	AcknowledgementV1Version         = "device-audit.acknowledgement.v1"
	MaxEnvelopeSequence       uint64 = 9007199254740991
	MaxEvidencePayloadBytes          = 262144
	envelopeDomain                   = "device-audit/signature/v1\x00"
)

var envelopeTimestampPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
var envelopeHexPattern = regexp.MustCompile(`^[0-9a-f]+$`)

// EnvelopeHeaderV1 is application signing metadata, never mesh authentication.
// Times retain their exact wire spelling for cross-language signing.
type EnvelopeHeaderV1 struct {
	SchemaVersion string `json:"schema_version"`
	DeploymentID  string `json:"deployment_id"`
	DeviceID      string `json:"device_id"`
	SigningKeyID  string `json:"signing_key_id"`
	Sequence      uint64 `json:"sequence"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
}

type EnrollmentEnvelopeV1 struct {
	EnvelopeHeaderV1
	PublicKey   string `json:"public_key"`
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

type EvidenceEnvelopeV1 struct {
	EnvelopeHeaderV1
	PayloadSchemaVersion string `json:"payload_schema_version"`
	PayloadBase64        string `json:"payload_base64"`
	PayloadSHA256        string `json:"payload_sha256"`
	Signature            string `json:"signature"`
}

type AcknowledgementV1 struct {
	SchemaVersion        string  `json:"schema_version"`
	DeploymentID         string  `json:"deployment_id"`
	DeviceID             string  `json:"device_id"`
	ControllerKeyID      string  `json:"controller_key_id"`
	RequestSchemaVersion string  `json:"request_schema_version"`
	RequestKeyID         string  `json:"request_key_id"`
	RequestSequence      uint64  `json:"request_sequence"`
	RequestSHA256        string  `json:"request_sha256"`
	ReceivedAt           string  `json:"received_at"`
	Status               string  `json:"status"`
	RejectionReason      *string `json:"rejection_reason"`
	LastSequence         *uint64 `json:"last_sequence"`
	Signature            string  `json:"signature"`
}

func (e *EnrollmentEnvelopeV1) UnmarshalJSON(data []byte) error {
	type wire EnrollmentEnvelopeV1
	var decoded wire
	if err := decodeEnvelopeJSON(data, &decoded, []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at", "public_key", "challenge_id", "signature"}); err != nil {
		return err
	}
	*e = EnrollmentEnvelopeV1(decoded)
	return nil
}

func (e *EvidenceEnvelopeV1) UnmarshalJSON(data []byte) error {
	type wire EvidenceEnvelopeV1
	var decoded wire
	if err := decodeEnvelopeJSON(data, &decoded, []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at", "payload_schema_version", "payload_base64", "payload_sha256", "signature"}); err != nil {
		return err
	}
	*e = EvidenceEnvelopeV1(decoded)
	return nil
}

func (a *AcknowledgementV1) UnmarshalJSON(data []byte) error {
	type wire AcknowledgementV1
	var decoded wire
	if err := decodeEnvelopeJSON(data, &decoded, []string{"schema_version", "deployment_id", "device_id", "controller_key_id", "request_schema_version", "request_key_id", "request_sequence", "request_sha256", "received_at", "status", "rejection_reason", "last_sequence", "signature"}, "rejection_reason", "last_sequence"); err != nil {
		return err
	}
	*a = AcknowledgementV1(decoded)
	return nil
}

// SigningKeyIDV1 fingerprints a raw Ed25519 public key. It grants no trust.
func SigningKeyIDV1(publicKey ed25519.PublicKey) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", fmt.Errorf("Ed25519 public key must be 32 bytes")
	}
	digest := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(digest[:]), nil
}

func fixedEnvelopeHex(value string, size int) bool {
	return len(value) == size*2 && envelopeHexPattern.MatchString(value)
}

func validEnvelopeKeyID(value string) bool {
	return len(value) == 72 && value[:8] == "ed25519:" && fixedEnvelopeHex(value[8:], sha256.Size)
}

func parseEnvelopeTime(value string) (time.Time, error) {
	parsed, err := time.Parse("2006-01-02T15:04:05Z", value)
	if err != nil || !envelopeTimestampPattern.MatchString(value) || parsed.Year() < 2 {
		return time.Time{}, fmt.Errorf("timestamp must be a real UTC whole-second date in years 0002..9999")
	}
	return parsed, nil
}

func (h EnvelopeHeaderV1) validate(version string, lifetime time.Duration) error {
	if h.SchemaVersion != version || !opaqueIDPattern.MatchString(h.DeploymentID) || !opaqueIDPattern.MatchString(h.DeviceID) || !validEnvelopeKeyID(h.SigningKeyID) || h.Sequence < 1 || h.Sequence > MaxEnvelopeSequence {
		return fmt.Errorf("invalid envelope version, identity, key ID or sequence")
	}
	issued, err := parseEnvelopeTime(h.IssuedAt)
	if err != nil {
		return err
	}
	expires, err := parseEnvelopeTime(h.ExpiresAt)
	if err != nil {
		return err
	}
	if !expires.After(issued) || expires.Sub(issued) > lifetime {
		return fmt.Errorf("invalid envelope lifetime")
	}
	return nil
}

func (e EnrollmentEnvelopeV1) validateSigningFields() error {
	if err := e.EnvelopeHeaderV1.validate(EnrollmentV1Version, 10*time.Minute); err != nil {
		return err
	}
	if e.Sequence != 1 || !fixedEnvelopeHex(e.PublicKey, ed25519.PublicKeySize) || !opaqueIDPattern.MatchString(e.ChallengeID) {
		return fmt.Errorf("invalid enrollment key, challenge or initial sequence")
	}
	return nil
}

func (e EnrollmentEnvelopeV1) Validate() error {
	if err := e.validateSigningFields(); err != nil {
		return err
	}
	key, _ := hex.DecodeString(e.PublicKey)
	keyID, _ := SigningKeyIDV1(key)
	if keyID != e.SigningKeyID {
		return fmt.Errorf("enrollment public key does not match key ID")
	}
	return validateEnvelopeSignature(e.Signature)
}

func (e EvidenceEnvelopeV1) validateSigningFields() error {
	if err := e.EnvelopeHeaderV1.validate(EvidenceEnvelopeV1Version, 24*time.Hour); err != nil {
		return err
	}
	if e.Sequence < 2 || e.PayloadSchemaVersion != TelemetryV2Version || !fixedEnvelopeHex(e.PayloadSHA256, sha256.Size) {
		return fmt.Errorf("invalid evidence sequence, payload version or digest")
	}
	return nil
}

func (e EvidenceEnvelopeV1) Validate() error {
	if err := e.validateSigningFields(); err != nil {
		return err
	}
	if len(e.PayloadBase64) > base64.StdEncoding.EncodedLen(MaxEvidencePayloadBytes) {
		return fmt.Errorf("evidence payload exceeds bound")
	}
	payload, err := base64.StdEncoding.Strict().DecodeString(e.PayloadBase64)
	if err != nil || len(payload) == 0 || len(payload) > MaxEvidencePayloadBytes || !utf8.Valid(payload) || base64.StdEncoding.EncodeToString(payload) != e.PayloadBase64 {
		return fmt.Errorf("invalid canonical base64 UTF-8 payload")
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != e.PayloadSHA256 {
		return fmt.Errorf("payload_digest_mismatch")
	}
	if err := rejectEnvelopeDuplicateKeys(payload); err != nil {
		return err
	}
	var telemetry TelemetryV2
	if err := json.Unmarshal(payload, &telemetry); err != nil {
		return err
	}
	if err := telemetry.Validate(); err != nil {
		return err
	}
	if telemetry.DeviceID != e.DeviceID {
		return fmt.Errorf("payload device does not match envelope")
	}
	return validateEnvelopeSignature(e.Signature)
}

func (a AcknowledgementV1) validateBody() error {
	if a.SchemaVersion != AcknowledgementV1Version || !opaqueIDPattern.MatchString(a.DeploymentID) || !opaqueIDPattern.MatchString(a.DeviceID) || !validEnvelopeKeyID(a.ControllerKeyID) || !validEnvelopeKeyID(a.RequestKeyID) || !fixedEnvelopeHex(a.RequestSHA256, sha256.Size) {
		return fmt.Errorf("invalid acknowledgement identity or correlation")
	}
	if (a.RequestSchemaVersion != EnrollmentV1Version && a.RequestSchemaVersion != EvidenceEnvelopeV1Version) || a.RequestSequence < 1 || a.RequestSequence > MaxEnvelopeSequence {
		return fmt.Errorf("invalid acknowledgement request version or sequence")
	}
	if (a.RequestSchemaVersion == EnrollmentV1Version && a.RequestSequence != 1) || (a.RequestSchemaVersion == EvidenceEnvelopeV1Version && a.RequestSequence < 2) {
		return fmt.Errorf("request version and sequence disagree")
	}
	if _, err := parseEnvelopeTime(a.ReceivedAt); err != nil {
		return err
	}
	if a.LastSequence != nil && *a.LastSequence > MaxEnvelopeSequence {
		return fmt.Errorf("invalid last_sequence")
	}
	switch a.Status {
	case "accepted":
		if a.RejectionReason != nil || a.LastSequence == nil || *a.LastSequence != a.RequestSequence {
			return fmt.Errorf("accepted acknowledgement requires null reason and committed request sequence")
		}
	case "rejected":
		if a.RejectionReason == nil || !validEnvelopeRejection(*a.RejectionReason) {
			return fmt.Errorf("rejected acknowledgement requires explicit reason")
		}
		if *a.RejectionReason == "replay" && (a.LastSequence == nil || *a.LastSequence < a.RequestSequence) {
			return fmt.Errorf("replay requires a known high-water mark >= request sequence")
		}
	default:
		return fmt.Errorf("invalid acknowledgement status")
	}
	return nil
}

func validEnvelopeRejection(reason string) bool {
	switch reason {
	case "invalid_signature", "key_mismatch", "payload_digest_mismatch", "replay", "expired", "future_timestamp", "unknown_device", "revoked_key", "deployment_mismatch", "bootstrap_invalid", "challenge_expired", "challenge_reused", "enrollment_conflict", "unauthorized_peer", "storage_unavailable", "invalid_payload":
		return true
	}
	return false
}

func (a AcknowledgementV1) Validate() error {
	if err := a.validateBody(); err != nil {
		return err
	}
	return validateEnvelopeSignature(a.Signature)
}

func validateEnvelopeSignature(signature string) error {
	if !fixedEnvelopeHex(signature, ed25519.SignatureSize) {
		return fmt.Errorf("signature must be lowercase hex of 64 bytes")
	}
	return nil
}

func (h EnvelopeHeaderV1) signingFields() []string {
	return []string{h.SchemaVersion, h.DeploymentID, h.DeviceID, h.SigningKeyID, strconv.FormatUint(h.Sequence, 10), h.IssuedAt, h.ExpiresAt}
}

func canonicalEnvelopeFields(fields []string) []byte {
	result := []byte(envelopeDomain)
	for _, field := range fields {
		result = binary.BigEndian.AppendUint32(result, uint32(len(field)))
		result = append(result, field...)
	}
	return result
}

// SigningBytes validates signed fields but permits an absent signature and
// semantic failures outside those fields, so rejected requests can be correlated.
// Senders must also Validate the completed envelope before sending it.
func (e EnrollmentEnvelopeV1) SigningBytes() ([]byte, error) {
	if err := e.validateSigningFields(); err != nil {
		return nil, err
	}
	return canonicalEnvelopeFields(append(e.signingFields(), e.PublicKey, e.ChallengeID)), nil
}

func (e EvidenceEnvelopeV1) SigningBytes() ([]byte, error) {
	if err := e.validateSigningFields(); err != nil {
		return nil, err
	}
	return canonicalEnvelopeFields(append(e.signingFields(), e.PayloadSchemaVersion, e.PayloadSHA256)), nil
}

func (a AcknowledgementV1) SigningBytes() ([]byte, error) {
	if err := a.validateBody(); err != nil {
		return nil, err
	}
	reason, last := "", ""
	if a.RejectionReason != nil {
		reason = *a.RejectionReason
	}
	if a.LastSequence != nil {
		last = strconv.FormatUint(*a.LastSequence, 10)
	}
	return canonicalEnvelopeFields([]string{a.SchemaVersion, a.DeploymentID, a.DeviceID, a.ControllerKeyID, a.RequestSchemaVersion, a.RequestKeyID, strconv.FormatUint(a.RequestSequence, 10), a.RequestSHA256, a.ReceivedAt, a.Status, reason, last}), nil
}

func verifyEnvelopeSignature(publicKey ed25519.PublicKey, keyID, signature string, message []byte) error {
	fingerprint, err := SigningKeyIDV1(publicKey)
	if err != nil {
		return err
	}
	if fingerprint != keyID {
		return fmt.Errorf("key_mismatch")
	}
	if err := validateEnvelopeSignature(signature); err != nil {
		return err
	}
	sig, _ := hex.DecodeString(signature)
	if !ed25519.Verify(publicKey, message, sig) {
		return fmt.Errorf("invalid_signature")
	}
	return nil
}

// VerifySignature checks integrity, not enrollment authorization, revocation,
// freshness, peer identity, or endpoint truth. The caller supplies the right key.
func (e EnrollmentEnvelopeV1) VerifySignature(publicKey ed25519.PublicKey) error {
	if err := e.Validate(); err != nil {
		return err
	}
	message, err := e.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(publicKey, e.SigningKeyID, e.Signature, message)
}

func (e EvidenceEnvelopeV1) VerifySignature(publicKey ed25519.PublicKey) error {
	if err := e.Validate(); err != nil {
		return err
	}
	message, err := e.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(publicKey, e.SigningKeyID, e.Signature, message)
}

func (a AcknowledgementV1) VerifySignature(publicKey ed25519.PublicKey) error {
	message, err := a.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(publicKey, a.ControllerKeyID, a.Signature, message)
}

// EnvelopeRequestSHA256V1 correlates canonical request fields and a well-formed
// signature, even when semantic or cryptographic checks fail. It grants no trust.
func EnvelopeRequestSHA256V1(signingBytes []byte, signature string) (string, error) {
	if err := validateEnvelopeSignature(signature); err != nil {
		return "", err
	}
	sig, _ := hex.DecodeString(signature)
	hash := sha256.New()
	hash.Write(signingBytes)
	hash.Write(sig)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// FreshnessRejection is a pure contract check after validation/authentication.
// It neither reads nor advances durable state. Consumers must compare-and-commit
// atomically; a passing check alone must never produce an accepted response.
// Enrollment binding conflicts and challenge admission are outside this check.
func (h EnvelopeHeaderV1) FreshnessRejection(now time.Time, lastSequence uint64) (string, error) {
	var lifetime time.Duration
	switch h.SchemaVersion {
	case EnrollmentV1Version:
		lifetime = 10 * time.Minute
	case EvidenceEnvelopeV1Version:
		lifetime = 24 * time.Hour
	default:
		return "", fmt.Errorf("not a supported request version")
	}
	if err := h.validate(h.SchemaVersion, lifetime); err != nil {
		return "", err
	}
	if lastSequence > MaxEnvelopeSequence || now.IsZero() {
		return "", fmt.Errorf("invalid durable mark or receiver clock")
	}
	issued, _ := parseEnvelopeTime(h.IssuedAt)
	expires, _ := parseEnvelopeTime(h.ExpiresAt)
	if !now.Before(expires) {
		return "expired", nil
	}
	if issued.After(now.Add(5 * time.Minute)) {
		return "future_timestamp", nil
	}
	if h.Sequence <= lastSequence {
		return "replay", nil
	}
	return "", nil
}

func decodeEnvelopeJSON(data []byte, target any, required []string, nullable ...string) error {
	if err := rejectEnvelopeDuplicateKeys(data); err != nil {
		return err
	}
	if err := requireJSONFieldNames(data, required...); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	for _, name := range required {
		value, ok := fields[name]
		if !ok {
			return fmt.Errorf("missing field %s", name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			allowed := false
			for _, candidate := range nullable {
				if candidate == name {
					allowed = true
				}
			}
			if !allowed {
				return fmt.Errorf("null field %s", name)
			}
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

func rejectEnvelopeDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := readEnvelopeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON")
	}
	return nil
}

func readEnvelopeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if delim != '{' && delim != '[' {
		return fmt.Errorf("unexpected JSON delimiter")
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate JSON field %v", keyToken)
			}
			seen[key] = true
		}
		if err := readEnvelopeJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
