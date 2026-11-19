package contracts

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	DeviceRevocationRequestV1Version = "device-audit.device-revocation-request.v1"
	DeviceRevocationV1Version        = "device-audit.device-revocation.v1"
)

// DeviceRevocationRequestV1 asks the controller to stop admitting one enrolled
// device. Revocation is permanent; no reinstatement contract exists.
type DeviceRevocationRequestV1 struct {
	SchemaVersion   string `json:"schema_version"`
	DeviceID        string `json:"device_id"`
	ReasonReference string `json:"reason_reference"`
}

// DeviceRevocationV1 is the durable revocation audit record. Every field
// except the request's device and reason is controller-assigned.
type DeviceRevocationV1 struct {
	SchemaVersion    string    `json:"schema_version"`
	DeploymentID     string    `json:"deployment_id"`
	DeviceID         string    `json:"device_id"`
	RevokedAt        time.Time `json:"revoked_at"`
	ReasonReference  string    `json:"reason_reference"`
	EnrollmentSHA256 string    `json:"enrollment_sha256"`
	ActorIssuer      string    `json:"actor_issuer"`
	ActorSubject     string    `json:"actor_subject"`
}

func (r *DeviceRevocationRequestV1) UnmarshalJSON(data []byte) error {
	type wire DeviceRevocationRequestV1
	return decodeEnvelopeJSON(data, (*wire)(r), []string{"schema_version", "device_id", "reason_reference"})
}

func (r *DeviceRevocationV1) UnmarshalJSON(data []byte) error {
	type wire DeviceRevocationV1
	return decodeEnvelopeJSON(data, (*wire)(r), []string{"schema_version", "deployment_id", "device_id", "revoked_at", "reason_reference", "enrollment_sha256", "actor_issuer", "actor_subject"})
}

func (r DeviceRevocationRequestV1) Validate() error {
	if r.SchemaVersion != DeviceRevocationRequestV1Version || !opaqueIDPattern.MatchString(r.DeviceID) || !opaqueIDPattern.MatchString(r.ReasonReference) {
		return fmt.Errorf("invalid device revocation request version, device or reason reference")
	}
	return nil
}

func (r DeviceRevocationV1) Validate() error {
	if r.SchemaVersion != DeviceRevocationV1Version || !opaqueIDPattern.MatchString(r.DeploymentID) ||
		!opaqueIDPattern.MatchString(r.DeviceID) || !opaqueIDPattern.MatchString(r.ReasonReference) || r.RevokedAt.IsZero() ||
		!sha256Pattern.MatchString(r.EnrollmentSHA256) || strings.TrimSpace(r.ActorIssuer) == "" || utf8.RuneCountInString(r.ActorIssuer) > 2048 ||
		strings.TrimSpace(r.ActorSubject) == "" || utf8.RuneCountInString(r.ActorSubject) > 255 {
		return fmt.Errorf("invalid device revocation record provenance")
	}
	return nil
}
