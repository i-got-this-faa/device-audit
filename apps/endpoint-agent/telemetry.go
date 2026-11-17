package main

import (
	"context"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

// collectEndpointTelemetry reads every platform source once and returns a
// validated telemetry v2 payload with source "endpoint". Per-source provider,
// observation time and network rates stay in the collector sample; v2 has no
// field for them.
func collectEndpointTelemetry(ctx context.Context, deviceID string) (contracts.TelemetryV2, error) {
	sample, err := telemetry.NewSensorCollector().Collect(ctx)
	if err != nil {
		return contracts.TelemetryV2{}, err
	}
	return telemetry.EndpointTelemetryV2(sample, deviceID)
}
