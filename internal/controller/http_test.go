package controller

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const sample = `{"schema_version":"device-audit.v1","device_id":"demo-device","collected_at":"2026-10-13T06:00:00Z","source":"fixture","metrics":{"cpu_percent":12.5}}`

func TestTelemetryRoundTrip(t *testing.T) {
	handler := NewAPI(1).Handler()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/telemetry", strings.NewReader(sample)))
	if w.Code != http.StatusAccepted {
		t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
	}
	var accepted Device
	if err := json.Unmarshal(w.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Health != "unknown" || len(accepted.EvidenceDigest) != 64 || accepted.Telemetry.Metrics.MemoryPercent != nil {
		t.Fatalf("unexpected prediction/digest/missing metric: %+v", accepted)
	}
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/devices/demo-device", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("read: %d", w.Code)
	}
	var stored Device
	if err := json.Unmarshal(w.Body.Bytes(), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.EvidenceDigest != accepted.EvidenceDigest {
		t.Fatal("stored digest changed")
	}
}

func TestInvalidTelemetryAndDeviceLimit(t *testing.T) {
	handler := NewAPI(1).Handler()
	for _, body := range []string{
		strings.Replace(sample, "12.5", "101", 1),
		strings.Replace(sample, `"cpu_percent":12.5`, `"unexpected":12`, 1),
		sample + sample,
		strings.Replace(sample, `"cpu_percent":12.5`, "", 1),
		strings.Replace(sample, "device-audit.v1", "v2", 1),
	} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/telemetry", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid body accepted: %s (%d)", body, w.Code)
		}
	}
	for i, id := range []string{"demo-device", "second-device", "demo-device"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/telemetry", strings.NewReader(strings.Replace(sample, "demo-device", id, 1))))
		want := http.StatusAccepted
		if i == 1 {
			want = http.StatusServiceUnavailable
		}
		if w.Code != want {
			t.Fatalf("device %s: got %d, want %d", id, w.Code, want)
		}
	}
}
