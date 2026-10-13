// Package lifecycle owns evidence-based repair, upgrade, replacement and sustainability analysis.
package lifecycle

import (
	"context"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type Evaluator interface {
	Evaluate(context.Context, contracts.Telemetry, contracts.Prediction) (contracts.AuditReport, error)
}
