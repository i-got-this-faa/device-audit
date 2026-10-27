package contracts

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	InventoryUpdateV1Version        = "device-audit.inventory-update.v1"
	InventoryRecordV1Version        = "device-audit.inventory-record.v1"
	MaxInventoryRevisionV1   uint64 = 9007199254740991
)

// InventoryUpdateV1 replaces the complete metadata snapshot. It is an
// administrator assertion, separate from signed endpoint telemetry.
type InventoryUpdateV1 struct {
	SchemaVersion    string      `json:"schema_version"`
	DeviceID         string      `json:"device_id"`
	ExpectedRevision uint64      `json:"expected_revision"`
	ObservedAt       time.Time   `json:"observed_at"`
	SourceReference  string      `json:"source_reference"`
	Inventory        InventoryV2 `json:"inventory"`
}

type InventoryRecordV1 struct {
	SchemaVersion    string      `json:"schema_version"`
	DeploymentID     string      `json:"deployment_id"`
	DeviceID         string      `json:"device_id"`
	Revision         uint64      `json:"revision"`
	ObservedAt       time.Time   `json:"observed_at"`
	RecordedAt       time.Time   `json:"recorded_at"`
	SourceReference  string      `json:"source_reference"`
	EnrollmentSHA256 string      `json:"enrollment_sha256"`
	ActorIssuer      string      `json:"actor_issuer"`
	ActorSubject     string      `json:"actor_subject"`
	Inventory        InventoryV2 `json:"inventory"`
}

func (u *InventoryUpdateV1) UnmarshalJSON(data []byte) error {
	type wire InventoryUpdateV1
	var decoded wire
	if err := decodeEnvelopeJSON(data, &decoded, []string{"schema_version", "device_id", "expected_revision", "observed_at", "source_reference", "inventory"}); err != nil {
		return err
	}
	*u = InventoryUpdateV1(decoded)
	return nil
}

func (r *InventoryRecordV1) UnmarshalJSON(data []byte) error {
	type wire InventoryRecordV1
	var decoded wire
	if err := decodeEnvelopeJSON(data, &decoded, []string{"schema_version", "deployment_id", "device_id", "revision", "observed_at", "recorded_at", "source_reference", "enrollment_sha256", "actor_issuer", "actor_subject", "inventory"}); err != nil {
		return err
	}
	*r = InventoryRecordV1(decoded)
	return nil
}

func (u InventoryUpdateV1) Validate() error {
	if u.SchemaVersion != InventoryUpdateV1Version || !opaqueIDPattern.MatchString(u.DeviceID) ||
		!opaqueIDPattern.MatchString(u.SourceReference) || u.ObservedAt.IsZero() || u.ExpectedRevision >= MaxInventoryRevisionV1 {
		return fmt.Errorf("invalid inventory update version, device, source, observation time or revision")
	}
	if err := u.Inventory.Validate(); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, c := range u.Inventory.Components {
		if seen[c.ID] {
			return fmt.Errorf("duplicate component identity")
		}
		seen[c.ID] = true
	}
	return nil
}

func (r InventoryRecordV1) Validate() error {
	if r.SchemaVersion != InventoryRecordV1Version || !opaqueIDPattern.MatchString(r.DeploymentID) ||
		r.Revision == 0 || r.Revision > MaxInventoryRevisionV1 || r.RecordedAt.IsZero() || r.ObservedAt.After(r.RecordedAt) ||
		!sha256Pattern.MatchString(r.EnrollmentSHA256) || strings.TrimSpace(r.ActorIssuer) == "" || utf8.RuneCountInString(r.ActorIssuer) > 2048 ||
		strings.TrimSpace(r.ActorSubject) == "" || utf8.RuneCountInString(r.ActorSubject) > 255 {
		return fmt.Errorf("invalid inventory record provenance")
	}
	return (InventoryUpdateV1{SchemaVersion: InventoryUpdateV1Version, DeviceID: r.DeviceID,
		ExpectedRevision: r.Revision - 1, ObservedAt: r.ObservedAt, SourceReference: r.SourceReference, Inventory: r.Inventory}).Validate()
}
