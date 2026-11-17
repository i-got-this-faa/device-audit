// Package telemetry defines read-only collection boundaries, the TEL04 #85
// permission, cadence and sampling-overhead harness, and the TEL06 #92 nullable
// battery, thermal and GPU collector (sensors.go).
//
// The harness measures this process. It does not read Windows sensors, impersonate
// a service token, or approve a production collector budget. Fixture and synthetic
// results are not endpoint telemetry.
package telemetry

import (
	"context"
	"errors"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ErrNotImplemented is returned by collectors that have no production source.
var ErrNotImplemented = errors.New("telemetry: production collector is not implemented")

// Collector is the read-only collection boundary. Implementations must preserve
// null metrics and explicit units; a missing source is an error or a null
// reason, never a fabricated zero.
type Collector interface {
	Collect(context.Context) (contracts.Telemetry, error)
}

// UnimplementedCollector keeps the production boundary explicit until a
// platform collector exists. It returns no device identifier and no metrics.
type UnimplementedCollector struct{}

// Collect rejects use of the production boundary.
func (UnimplementedCollector) Collect(context.Context) (contracts.Telemetry, error) {
	return contracts.Telemetry{}, ErrNotImplemented
}
