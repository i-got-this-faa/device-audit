package main

import (
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// On Windows the real collector's payload is accepted by the admitted signer.
// Other platforms have no selected provider, so the payload has no known
// metric and is refused instead of carrying fabricated values.
func TestCollectedTelemetrySignsAsEvidence(t *testing.T) {
	s, _, i, receipt := admittedStore(t)
	defer s.close()
	payload, err := collectEndpointTelemetry(context.Background(), receipt.DeviceID)
	if runtime.GOOS != "windows" {
		if err == nil {
			t.Fatal("non-Windows platform produced endpoint telemetry")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	if payload.Source != "endpoint" || payload.DeviceID != receipt.DeviceID || payload.Metrics.CPUUtilization == nil || payload.Metrics.MemoryPercent == nil || payload.Metrics.DiskUsedPercent == nil {
		t.Fatalf("payload = %+v", payload)
	}
	var encoded bytes.Buffer
	if err := json.NewEncoder(&encoded).Encode(payload); err != nil {
		t.Fatal(err)
	}
	envelope, err := s.signEvidence(encoded.Bytes(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signed, _ := json.Marshal(envelope)
	got := verifyEnvelope(t, i, receipt, signed)
	if got.PayloadSchemaVersion != contracts.TelemetryV2Version {
		t.Fatalf("payload schema = %s", got.PayloadSchemaVersion)
	}

	other, err := collectEndpointTelemetry(context.Background(), "other-device")
	if err != nil {
		t.Fatal(err)
	}
	encoded.Reset()
	_ = json.NewEncoder(&encoded).Encode(other)
	if _, err := s.signEvidence(encoded.Bytes(), time.Now()); err == nil {
		t.Fatal("payload for another device was signed")
	}
}
