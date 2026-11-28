package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

// probeFailure is what --run-probe prints when a started probe fails.
type probeFailure struct {
	Schema          string          `json:"schema"`
	Reason          string          `json:"reason"`
	Detail          string          `json:"detail"`
	PartialEvidence json.RawMessage `json:"partial_evidence"`
}

const probeFailureSchema = "device-audit.probe-failure.v1"

// runProbeRequest runs one strict probe request from in. It exits 0 with the
// evidence on out, 1 with a probe failure on out, or 2 when the request was
// rejected and nothing ran. It is a local operator check: assignment
// signatures, targets and expiry are verified by runAssignedProbe.
func runProbeRequest(ctx context.Context, runner interface {
	Run(context.Context, workflows.Request) ([]byte, error)
}, in io.Reader, out, errOut io.Writer) int {
	req, err := workflows.ParseRequest(in)
	if err != nil {
		fmt.Fprintf(errOut, "probe request rejected: %s\n", err)
		return 2
	}
	evidence, err := runner.Run(ctx, req)
	return writeProbeOutcome(evidence, err, out, errOut)
}

func runProbeWorker(in io.Reader, out, errOut io.Writer) int {
	req, err := workflows.ParseRequest(in)
	if err != nil || !probeWorkerReady() {
		fmt.Fprintln(errOut, "probe worker requires an isolated Windows job and a valid request")
		return 2
	}
	evidence, err := workflows.NewCatalog().Run(context.Background(), req)
	return writeProbeOutcome(evidence, err, out, errOut)
}

func writeProbeOutcome(evidence []byte, err error, out, errOut io.Writer) int {
	var failure *workflows.Failure
	switch {
	case errors.As(err, &failure):
		record := probeFailure{Schema: probeFailureSchema, Reason: string(failure.Reason), Detail: failure.Detail, PartialEvidence: json.RawMessage("null")}
		if failure.Partial != nil {
			record.PartialEvidence = failure.Partial
		}
		if json.NewEncoder(out).Encode(record) != nil {
			fmt.Fprintln(errOut, "write probe failure")
		}
		return 1
	case err != nil:
		fmt.Fprintf(errOut, "probe did not run: %s\n", err)
		return 2
	}
	if _, err := fmt.Fprintf(out, "%s\n", evidence); err != nil {
		fmt.Fprintln(errOut, "write probe evidence")
		return 1
	}
	return 0
}
