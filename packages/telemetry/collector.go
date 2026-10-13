// Package telemetry defines read-only, platform-specific collection.
package telemetry

import (
	"context"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type Collector interface {
	Collect(context.Context) (contracts.Telemetry, error)
}
