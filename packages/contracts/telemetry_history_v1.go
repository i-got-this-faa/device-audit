package contracts

import "time"

const (
	TelemetryHistoryV1Version = "device-audit.telemetry-history.v1"
	// TelemetryHistoryPageMaxV1 bounds one history page; larger requests are rejected.
	TelemetryHistoryPageMaxV1     = 100
	TelemetryHistoryPageDefaultV1 = 50
	// TelemetryHistoryWindowMaxV1 bounds the queried time window.
	TelemetryHistoryWindowMaxV1 = 31 * 24 * time.Hour
)

// HistorySampleV1 is one durable signed sample with its provenance. Metrics keep
// the explicit units and nullable values of telemetry v2; LogReferences are the
// structured error-evidence references the sample carried (digests, never log bodies).
type HistorySampleV1 struct {
	Sequence      uint64           `json:"sequence"`
	Source        string           `json:"source"`
	CollectedAt   time.Time        `json:"collected_at"`
	ReceivedAt    time.Time        `json:"received_at"`
	RequestSHA256 string           `json:"request_sha256"`
	Metrics       MetricsV2        `json:"metrics"`
	LogReferences []LogReferenceV2 `json:"log_references"`
}

// TelemetryHistoryV1 is one page of a device's samples with from <= collected_at < to,
// ordered by (collected_at, sequence). NextAfter is an opaque cursor, or null on the last page.
type TelemetryHistoryV1 struct {
	SchemaVersion string            `json:"schema_version"`
	DeploymentID  string            `json:"deployment_id"`
	DeviceID      string            `json:"device_id"`
	From          time.Time         `json:"from"`
	To            time.Time         `json:"to"`
	Samples       []HistorySampleV1 `json:"samples"`
	NextAfter     *string           `json:"next_after"`
}
