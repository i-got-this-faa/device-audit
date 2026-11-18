//go:build windows

package workflows

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// Runs both probes against this host. Hosted runners may expose only virtual
// disks, which are not eligible components; that is an explicit not-found.
func TestPlatformProbes(t *testing.T) {
	catalog := NewCatalog()
	encoded, err := catalog.Run(context.Background(), storageRequest("storage:disk-0"))
	var failure *Failure
	switch {
	case errors.As(err, &failure) && failure.Detail == "component_not_found":
		t.Log("disk 0 is not an eligible storage component on this host")
	case err != nil:
		t.Fatalf("storage_health.v1: %v", err)
	default:
		var evidence Evidence[StorageHealth]
		if err := json.Unmarshal(encoded, &evidence); err != nil || evidence.Body.BusType == "" {
			t.Fatalf("storage evidence = %s (%v)", encoded, err)
		}
		t.Logf("storage_health.v1 (%d bytes): %s", len(encoded), encoded)
	}
	encoded, err = catalog.Run(context.Background(), errorsRequest(3600, 4))
	if err != nil {
		t.Fatalf("system_errors.v1: %v", err)
	}
	var evidence Evidence[SystemErrors]
	if err := json.Unmarshal(encoded, &evidence); err != nil || len(evidence.Body.Logs) != 2 {
		t.Fatalf("error evidence = %s (%v)", encoded, err)
	}
	t.Logf("system_errors.v1 (%d bytes)", len(encoded))
}
