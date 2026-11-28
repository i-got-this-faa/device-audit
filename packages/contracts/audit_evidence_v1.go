package contracts

import (
	"fmt"
	"time"
)

const (
	// AuditEvidenceStoreV1Version versions AuditEvidenceStoreRequestV1.
	AuditEvidenceStoreV1Version = "device-audit.audit-evidence-store.v1"
	// AuditEvidenceV1Version versions AuditEvidenceV1.
	AuditEvidenceV1Version = "device-audit.audit-evidence.v1"
	// AuditEvidenceMaxBytesV1 bounds one stored evidence object. It sits below
	// the 10 MiB reference limit of an audit manifest.
	AuditEvidenceMaxBytesV1 = 2 << 20
	// AuditEvidenceMaxRetentionV1 bounds how far ahead retention may be set.
	// It is a provisional sanity bound; the retention policy is #132's.
	AuditEvidenceMaxRetentionV1 = 10 * 365 * 24 * time.Hour
)

// AuditEvidenceKindV1 names the source of a stored evidence object.
type AuditEvidenceKindV1 string

const (
	// AuditEvidenceTelemetry is a device-signed evidence envelope.
	AuditEvidenceTelemetry AuditEvidenceKindV1 = "telemetry"
	// AuditEvidencePrediction is the prediction v2 payload of one persisted assessment.
	AuditEvidencePrediction AuditEvidenceKindV1 = "prediction"
	// AuditEvidenceDiagnostic is a device-signed diagnostic result.
	AuditEvidenceDiagnostic AuditEvidenceKindV1 = "diagnostic"
)

// AuditEvidenceRejection is a stable refusal code for the evidence store.
type AuditEvidenceRejection string

func (r AuditEvidenceRejection) Error() string { return string(r) }

const (
	AuditEvidenceRejectionInvalidRequest AuditEvidenceRejection = "invalid_request"
	// SourceNotFound: no such record for this device in this deployment.
	AuditEvidenceRejectionSourceNotFound AuditEvidenceRejection = "evidence_source_not_found"
	AuditEvidenceRejectionTooLarge       AuditEvidenceRejection = "evidence_too_large"
	AuditEvidenceRejectionConflict       AuditEvidenceRejection = "evidence_conflict"
	AuditEvidenceRejectionNotFound       AuditEvidenceRejection = "evidence_not_found"
	// WrongScope: the evidence belongs to another device than the one asserted.
	AuditEvidenceRejectionWrongScope AuditEvidenceRejection = "evidence_wrong_scope"
	// Expired: the retention period has ended; the bytes are no longer served.
	AuditEvidenceRejectionExpired AuditEvidenceRejection = "evidence_expired"
	// Unavailable: the source record or the stored bytes failed their integrity check.
	AuditEvidenceRejectionUnavailable AuditEvidenceRejection = "evidence_unavailable"
)

// AuditEvidenceStoreRequestV1 asks the controller to snapshot one durable
// record. The controller reads the bytes itself and never accepts them from
// the caller, so a console session cannot supply evidence of its own making.
// Exactly the selector for Kind is set: Sequence for telemetry, PredictionID
// for a prediction, AssignmentID for a diagnostic result.
type AuditEvidenceStoreRequestV1 struct {
	SchemaVersion      string              `json:"schema_version"`
	EvidenceID         string              `json:"evidence_id"`
	Kind               AuditEvidenceKindV1 `json:"kind"`
	DeviceID           string              `json:"device_id"`
	Sequence           uint64              `json:"sequence"`
	PredictionID       uint64              `json:"prediction_id"`
	AssignmentID       string              `json:"assignment_id"`
	RetentionExpiresAt time.Time           `json:"retention_expires_at"`
}

// AuditEvidenceV1 is the metadata of one stored object. It carries no bytes.
type AuditEvidenceV1 struct {
	SchemaVersion         string              `json:"schema_version"`
	DeploymentID          string              `json:"deployment_id"`
	EvidenceID            string              `json:"evidence_id"`
	Kind                  AuditEvidenceKindV1 `json:"kind"`
	EvidenceSchemaVersion string              `json:"evidence_schema_version"`
	DeviceID              string              `json:"device_id"`
	SourceReference       string              `json:"source_reference"`
	SHA256                string              `json:"sha256"`
	SizeBytes             uint32              `json:"size_bytes"`
	StoredAt              time.Time           `json:"stored_at"`
	RetentionExpiresAt    time.Time           `json:"retention_expires_at"`
	StoredBy              ModelActorV1        `json:"stored_by"`
}

func (r *AuditEvidenceStoreRequestV1) UnmarshalJSON(data []byte) error {
	type wire AuditEvidenceStoreRequestV1
	return decodeEnvelopeJSON(data, (*wire)(r), []string{"schema_version", "evidence_id", "kind", "device_id", "sequence", "prediction_id", "assignment_id", "retention_expires_at"})
}

// Validate checks the request's shape. now is the controller clock.
func (r AuditEvidenceStoreRequestV1) Validate(now time.Time) error {
	if r.SchemaVersion != AuditEvidenceStoreV1Version || !opaqueIDPattern.MatchString(r.EvidenceID) || !opaqueIDPattern.MatchString(r.DeviceID) {
		return fmt.Errorf("invalid audit evidence request")
	}
	switch r.Kind {
	case AuditEvidenceTelemetry:
		if r.Sequence < FirstEvidenceSequenceV1 || r.PredictionID != 0 || r.AssignmentID != "" {
			return fmt.Errorf("telemetry evidence needs exactly a sequence")
		}
	case AuditEvidencePrediction:
		if r.PredictionID == 0 || r.Sequence != 0 || r.AssignmentID != "" {
			return fmt.Errorf("prediction evidence needs exactly a prediction_id")
		}
	case AuditEvidenceDiagnostic:
		if !opaqueIDPattern.MatchString(r.AssignmentID) || r.Sequence != 0 || r.PredictionID != 0 {
			return fmt.Errorf("diagnostic evidence needs exactly an assignment_id")
		}
	default:
		return fmt.Errorf("unsupported evidence kind")
	}
	if now.IsZero() || !r.RetentionExpiresAt.After(now) || r.RetentionExpiresAt.Sub(now) > AuditEvidenceMaxRetentionV1 {
		return fmt.Errorf("retention must end in the future, within %s", AuditEvidenceMaxRetentionV1)
	}
	return nil
}
