package contracts

import "time"

const (
	DeviceStateV1Version     = "device-audit.device-state.v1"
	DeviceStatePageV1Version = "device-audit.device-state-page.v1"
	// DeviceStatePageMaxV1 bounds one inventory page; larger requests are rejected.
	DeviceStatePageMaxV1     = 100
	DeviceStatePageDefaultV1 = 50
)

// Sensor availability values. "not_reported" means the sample omitted the
// metric; "missing" means it reported a null value with a reason.
const (
	SensorAvailable   = "available"
	SensorMissing     = "missing"
	SensorNotReported = "not_reported"
)

// SensorStateV1 summarizes one metric of the latest sample without repeating units.
type SensorStateV1 struct {
	Metric        string `json:"metric"`
	Availability  string `json:"availability"`
	MissingReason string `json:"missing_reason,omitempty"`
}

// LatestSampleV1 is the newest durable signed sample with its provenance.
// Metrics keep their explicit units and nullable values from telemetry v2.
type LatestSampleV1 struct {
	Sequence      uint64          `json:"sequence"`
	Source        string          `json:"source"`
	CollectedAt   time.Time       `json:"collected_at"`
	ReceivedAt    time.Time       `json:"received_at"`
	RequestSHA256 string          `json:"request_sha256"`
	Metrics       MetricsV2       `json:"metrics"`
	Sensors       []SensorStateV1 `json:"sensors"`
}

// DeviceStateV1 is one enrolled device with its latest durable sample.
// Latest is null when no sample body is retained for the device's newest
// sequence; LastSequence still reports the committed replay mark.
type DeviceStateV1 struct {
	SchemaVersion string          `json:"schema_version"`
	DeploymentID  string          `json:"deployment_id"`
	DeviceID      string          `json:"device_id"`
	SigningKeyID  string          `json:"signing_key_id"`
	EnrolledAt    time.Time       `json:"enrolled_at"`
	RevokedAt     *time.Time      `json:"revoked_at"`
	LastSequence  uint64          `json:"last_sequence"`
	Latest        *LatestSampleV1 `json:"latest"`
}

// DeviceStatePageV1 is one keyset page ordered by device ID. NextAfter is
// the cursor for the following page, or null on the last page.
type DeviceStatePageV1 struct {
	SchemaVersion string          `json:"schema_version"`
	DeploymentID  string          `json:"deployment_id"`
	Devices       []DeviceStateV1 `json:"devices"`
	NextAfter     *string         `json:"next_after"`
}

// SensorStates reports every v2 metric in a fixed order.
func SensorStates(m MetricsV2) []SensorStateV1 {
	named := []struct {
		name   string
		metric *MetricV2
	}{
		{"cpu_utilization", m.CPUUtilization}, {"gpu_utilization", m.GPUUtilization},
		{"memory_percent", m.MemoryPercent}, {"disk_used_percent", m.DiskUsedPercent},
		{"battery_percent", m.BatteryPercent}, {"temperature_c", m.TemperatureC},
		{"network_latency_ms", m.NetworkLatencyMS},
	}
	states := make([]SensorStateV1, 0, len(named))
	for _, n := range named {
		switch {
		case n.metric == nil:
			states = append(states, SensorStateV1{Metric: n.name, Availability: SensorNotReported})
		case n.metric.Value == nil:
			states = append(states, SensorStateV1{Metric: n.name, Availability: SensorMissing, MissingReason: n.metric.MissingReason})
		default:
			states = append(states, SensorStateV1{Metric: n.name, Availability: SensorAvailable})
		}
	}
	return states
}
