package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

type deniedDisks struct{ calls *int }

func (d deniedDisks) Health(context.Context, int) (workflows.StorageHealth, error) {
	*d.calls++
	return workflows.StorageHealth{}, telemetry.ErrPermissionDenied
}

// The CLI distinguishes a rejected request (exit 2, nothing ran) from a probe
// that ran and failed (exit 1, CT06 reason on stdout).
func TestRunProbeExitCodes(t *testing.T) {
	calls := 0
	catalog := workflows.Catalog{Disks: deniedDisks{&calls}, Now: func() time.Time { return time.Unix(0, 0) }}
	var out, errOut bytes.Buffer
	shell := `{"probe_id":"storage_health.v1","arguments":{"component_id":"storage:disk-0","lookback_seconds":null,"max_entries":null,"command":"whoami"},"budget":{"wall_seconds":5,"max_output_bytes":4096}}`
	if code := runProbeRequest(context.Background(), catalog, strings.NewReader(shell), &out, &errOut); code != 2 || out.Len() != 0 || calls != 0 {
		t.Fatalf("shell input: code %d, out %q, calls %d", code, out.String(), calls)
	}
	valid := strings.Replace(shell, `,"command":"whoami"`, "", 1)
	if code := runProbeRequest(context.Background(), catalog, strings.NewReader(valid), &out, &errOut); code != 1 || calls != 1 {
		t.Fatalf("denied disk: code %d, calls %d", code, calls)
	}
	var failure probeFailure
	if err := json.Unmarshal(out.Bytes(), &failure); err != nil || failure.Schema != probeFailureSchema || failure.Reason != "permission_denied" || string(failure.PartialEvidence) != "null" {
		t.Fatalf("failure record = %s (%v)", out.String(), err)
	}
}
