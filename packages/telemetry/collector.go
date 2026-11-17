// Package telemetry defines read-only collection boundaries: the TEL04 #85
// permission, cadence and sampling-overhead harness; the TEL05 #91 CPU, memory,
// disk and network sources and TEL06 #92 nullable battery, thermal and GPU
// sources of SensorCollector; the TEL07 #93 bounded error-evidence reader; and
// the TEL08 #94 per-source sampling Scheduler with its declared budget.
//
// The harness measures this process. It does not impersonate a service token or
// approve a production collector budget. Fixture and synthetic results are not
// endpoint telemetry.
package telemetry

import (
	"errors"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// EndpointTelemetryV2 builds the telemetry v2 payload for one collector sample.
// The caller supplies the admitted device ID; the collector never reads a
// hardware identifier. Inventory and log references are empty until their
// collectors exist. The payload is validated before it is returned.
func EndpointTelemetryV2(sample SensorSample, deviceID string) (contracts.TelemetryV2, error) {
	if sample.CollectedAt.IsZero() {
		return contracts.TelemetryV2{}, errors.New("telemetry: sample has no collection time")
	}
	payload := contracts.TelemetryV2{
		SchemaVersion: contracts.TelemetryV2Version,
		DeviceID:      deviceID,
		CollectedAt:   sample.CollectedAt.UTC(),
		Source:        "endpoint",
		Metrics:       sample.MetricsV2(),
		Inventory:     contracts.InventoryV2{Components: []contracts.ComponentV2{}},
		LogReferences: []contracts.LogReferenceV2{},
	}
	if err := payload.Validate(); err != nil {
		return contracts.TelemetryV2{}, err
	}
	return payload, nil
}
