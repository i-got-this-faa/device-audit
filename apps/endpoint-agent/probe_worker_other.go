//go:build !windows

package main

import (
	"context"
	"errors"

	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func executeProbeWorker(context.Context, workflows.Request) ([]byte, error) {
	return nil, errors.New("isolated diagnostic probes require Windows")
}

func probeWorkerReady() bool { return false }
