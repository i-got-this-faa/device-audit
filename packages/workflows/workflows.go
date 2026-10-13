// Package workflows defines autonomous, bounded diagnostic jobs.
package workflows

import (
	"context"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type Result struct {
	TaskID          string
	EvidenceDigests []string
	Findings        []string
}

type Runner interface {
	Run(context.Context, contracts.DiagnosticTask) (Result, error)
}
