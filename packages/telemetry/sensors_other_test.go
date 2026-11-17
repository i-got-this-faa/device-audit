//go:build !windows

package telemetry

import (
	"context"
	"testing"
)

// Outside the selected Windows target every source is an explicit null, never
// a zero or a borrowed host reading.
func TestNonWindowsSensorsAreUnavailable(t *testing.T) {
	sample, err := NewSensorCollector().Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range sample.Sources {
		for _, r := range src.Readings {
			if r.Value != nil || r.MissingReason != ReasonSensorUnavailable || r.Detail != "platform_not_selected" {
				t.Fatalf("reading = %+v", r)
			}
		}
	}
}
