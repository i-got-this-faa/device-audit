// Package health defines the bespoke model's inference boundary.
package health

import (
	"context"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type Predictor interface {
	Predict(context.Context, contracts.Telemetry) (contracts.Prediction, error)
}
