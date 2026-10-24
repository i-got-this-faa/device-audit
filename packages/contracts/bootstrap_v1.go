package contracts

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const (
	BootstrapTokenRequestV1Version = "device-audit.bootstrap-token-request.v1"
	BootstrapTokenV1Version        = "device-audit.bootstrap-token.v1"
	EnrollmentStartV1Version       = "device-audit.enrollment-start.v1"
	EnrollmentChallengeV1Version   = "device-audit.enrollment-challenge.v1"
	EnrollmentAdmissionV1Version   = "device-audit.enrollment-admission.v1"
	EnrollmentAcceptedV1Version    = "device-audit.enrollment-accepted.v1"
	EnrollmentErrorV1Version       = "device-audit.enrollment-error.v1"
	BootstrapSecretBytes           = 32
	NetworkChallengeBytes          = 80 // 32 random bytes plus NaCl anonymous-box overhead.
)

type BootstrapTokenRequestV1 struct {
	SchemaVersion string `json:"schema_version"`
	DeviceID      string `json:"device_id"`
}

type BootstrapTokenV1 struct {
	SchemaVersion string `json:"schema_version"`
	DeploymentID  string `json:"deployment_id"`
	DeviceID      string `json:"device_id"`
	Token         string `json:"token"`
	ExpiresAt     string `json:"expires_at"`
}

type EnrollmentStartV1 struct {
	SchemaVersion    string `json:"schema_version"`
	DeploymentID     string `json:"deployment_id"`
	DeviceID         string `json:"device_id"`
	PublicKey        string `json:"public_key"`
	NetworkPublicKey string `json:"network_public_key"`
}

type EnrollmentChallengeV1 struct {
	SchemaVersion    string `json:"schema_version"`
	DeploymentID     string `json:"deployment_id"`
	DeviceID         string `json:"device_id"`
	SigningKeyID     string `json:"signing_key_id"`
	NetworkPublicKey string `json:"network_public_key"`
	ChallengeID      string `json:"challenge_id"`
	NetworkChallenge string `json:"network_challenge"`
	ExpiresAt        string `json:"expires_at"`
}

type EnrollmentAdmissionV1 struct {
	SchemaVersion    string               `json:"schema_version"`
	Enrollment       EnrollmentEnvelopeV1 `json:"enrollment"`
	NetworkPublicKey string               `json:"network_public_key"`
	NetworkProof     string               `json:"network_proof"`
	Signature        string               `json:"signature"`
}

type EnrollmentAcceptedV1 struct {
	SchemaVersion    string `json:"schema_version"`
	DeploymentID     string `json:"deployment_id"`
	DeviceID         string `json:"device_id"`
	SigningKeyID     string `json:"signing_key_id"`
	NetworkPublicKey string `json:"network_public_key"`
	LastSequence     uint64 `json:"last_sequence"`
}

type EnrollmentErrorV1 struct {
	SchemaVersion string `json:"schema_version"`
	Reason        string `json:"reason"`
}

func (v *BootstrapTokenRequestV1) UnmarshalJSON(data []byte) error {
	type wire BootstrapTokenRequestV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "device_id"})
}
func (v *BootstrapTokenV1) UnmarshalJSON(data []byte) error {
	type wire BootstrapTokenV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "deployment_id", "device_id", "token", "expires_at"})
}
func (v *EnrollmentStartV1) UnmarshalJSON(data []byte) error {
	type wire EnrollmentStartV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "deployment_id", "device_id", "public_key", "network_public_key"})
}
func (v *EnrollmentChallengeV1) UnmarshalJSON(data []byte) error {
	type wire EnrollmentChallengeV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "network_public_key", "challenge_id", "network_challenge", "expires_at"})
}
func (v *EnrollmentAdmissionV1) UnmarshalJSON(data []byte) error {
	type wire EnrollmentAdmissionV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "enrollment", "network_public_key", "network_proof", "signature"})
}
func (v *EnrollmentAcceptedV1) UnmarshalJSON(data []byte) error {
	type wire EnrollmentAcceptedV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "network_public_key", "last_sequence"})
}
func (v *EnrollmentErrorV1) UnmarshalJSON(data []byte) error {
	type wire EnrollmentErrorV1
	return decodeEnvelopeJSON(data, (*wire)(v), []string{"schema_version", "reason"})
}

func (v BootstrapTokenRequestV1) Validate() error {
	if v.SchemaVersion != BootstrapTokenRequestV1Version || !opaqueIDPattern.MatchString(v.DeviceID) {
		return fmt.Errorf("invalid bootstrap token request")
	}
	return nil
}

func (v BootstrapTokenV1) Validate() error {
	if v.SchemaVersion != BootstrapTokenV1Version || !opaqueIDPattern.MatchString(v.DeploymentID) || !opaqueIDPattern.MatchString(v.DeviceID) || !fixedEnvelopeHex(v.Token, BootstrapSecretBytes) {
		return fmt.Errorf("invalid bootstrap token")
	}
	_, err := parseEnvelopeTime(v.ExpiresAt)
	return err
}

// NetworkPublicKeyV1 accepts canonical X25519 encodings and rejects low-order
// points. Canonical encoding prevents aliases from bypassing key uniqueness.
func NetworkPublicKeyV1(value string) ([32]byte, error) {
	var key [32]byte
	if !fixedEnvelopeHex(value, len(key)) {
		return key, fmt.Errorf("invalid network public key")
	}
	raw, _ := hex.DecodeString(value)
	copy(key[:], raw)
	// Compare the little-endian u coordinate with p = 2^255 - 19.
	var reversed [32]byte
	for i := range key {
		reversed[31-i] = key[i]
	}
	prime := [32]byte{0x7f}
	for i := 1; i < 32; i++ {
		prime[i] = 0xff
	}
	prime[31] = 0xed
	if bytes.Compare(reversed[:], prime[:]) >= 0 {
		return [32]byte{}, fmt.Errorf("noncanonical network public key")
	}
	public, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return [32]byte{}, fmt.Errorf("invalid network public key")
	}
	// A fixed public test scalar is used only to reject all-zero shared secrets.
	var scalar [32]byte
	scalar[0] = 1
	private, _ := ecdh.X25519().NewPrivateKey(scalar[:])
	if _, err := private.ECDH(public); err != nil {
		return [32]byte{}, fmt.Errorf("low-order network public key")
	}
	return key, nil
}

func (v EnrollmentStartV1) Validate() error {
	if v.SchemaVersion != EnrollmentStartV1Version || !opaqueIDPattern.MatchString(v.DeploymentID) || !opaqueIDPattern.MatchString(v.DeviceID) || !fixedEnvelopeHex(v.PublicKey, ed25519.PublicKeySize) || v.PublicKey == v.NetworkPublicKey {
		return fmt.Errorf("invalid enrollment start or reused key")
	}
	_, err := NetworkPublicKeyV1(v.NetworkPublicKey)
	return err
}

func (v EnrollmentChallengeV1) Validate() error {
	if v.SchemaVersion != EnrollmentChallengeV1Version || !opaqueIDPattern.MatchString(v.DeploymentID) || !opaqueIDPattern.MatchString(v.DeviceID) || !validEnvelopeKeyID(v.SigningKeyID) || !fixedEnvelopeHex(v.ChallengeID, BootstrapSecretBytes) {
		return fmt.Errorf("invalid enrollment challenge")
	}
	if _, err := NetworkPublicKeyV1(v.NetworkPublicKey); err != nil {
		return err
	}
	sealed, err := base64.StdEncoding.Strict().DecodeString(v.NetworkChallenge)
	if err != nil || len(sealed) != NetworkChallengeBytes || base64.StdEncoding.EncodeToString(sealed) != v.NetworkChallenge {
		return fmt.Errorf("invalid sealed network challenge")
	}
	_, err = parseEnvelopeTime(v.ExpiresAt)
	return err
}

func (v EnrollmentAdmissionV1) SigningBytes() ([]byte, error) {
	if v.SchemaVersion != EnrollmentAdmissionV1Version || !fixedEnvelopeHex(v.NetworkProof, BootstrapSecretBytes) || v.NetworkPublicKey == v.Enrollment.PublicKey {
		return nil, fmt.Errorf("invalid enrollment admission")
	}
	if _, err := NetworkPublicKeyV1(v.NetworkPublicKey); err != nil {
		return nil, err
	}
	if err := v.Enrollment.Validate(); err != nil {
		return nil, err
	}
	inner, err := v.Enrollment.SigningBytes()
	if err != nil {
		return nil, err
	}
	fingerprint, err := EnvelopeRequestSHA256V1(inner, v.Enrollment.Signature)
	if err != nil {
		return nil, err
	}
	return canonicalEnvelopeFields([]string{v.SchemaVersion, fingerprint, v.NetworkPublicKey, v.NetworkProof}), nil
}

func (v EnrollmentAdmissionV1) Validate() error {
	if _, err := v.SigningBytes(); err != nil {
		return err
	}
	return validateEnvelopeSignature(v.Signature)
}

func (v EnrollmentAdmissionV1) VerifySignature(publicKey ed25519.PublicKey) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if err := v.Enrollment.VerifySignature(publicKey); err != nil {
		return err
	}
	message, _ := v.SigningBytes()
	return verifyEnvelopeSignature(publicKey, v.Enrollment.SigningKeyID, v.Signature, message)
}

func (v EnrollmentAcceptedV1) Validate() error {
	if v.SchemaVersion != EnrollmentAcceptedV1Version || !opaqueIDPattern.MatchString(v.DeploymentID) || !opaqueIDPattern.MatchString(v.DeviceID) || !validEnvelopeKeyID(v.SigningKeyID) || v.LastSequence != EnrollmentSequenceV1 {
		return fmt.Errorf("invalid enrollment acceptance")
	}
	_, err := NetworkPublicKeyV1(v.NetworkPublicKey)
	return err
}

func (v EnrollmentErrorV1) Validate() error {
	if v.SchemaVersion != EnrollmentErrorV1Version {
		return fmt.Errorf("invalid enrollment error version")
	}
	switch v.Reason {
	case EnvelopeRejectionInvalidPayload, EnvelopeRejectionBootstrapInvalid, EnvelopeRejectionChallengeExpired, EnvelopeRejectionChallengeReused, EnvelopeRejectionEnrollmentConflict, EnvelopeRejectionInvalidSignature, EnvelopeRejectionKeyMismatch, EnvelopeRejectionDeploymentMismatch, EnvelopeRejectionExpired, EnvelopeRejectionFutureTimestamp, EnvelopeRejectionStorageUnavailable, "tls_required":
		return nil
	default:
		return fmt.Errorf("invalid enrollment error")
	}
}
