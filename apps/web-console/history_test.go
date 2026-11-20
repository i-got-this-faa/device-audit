package webconsole

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func renderHistory(t *testing.T, view *HistoryView, status int) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := Render(w, status, Page{Title: "Device history", Section: "devices", Subject: "viewer", History: view}); err != nil {
		t.Fatal(err)
	}
	return w.Body.String()
}

func TestDeviceHistoryShowsUnitsProvenanceDenialAndErrorEvidence(t *testing.T) {
	cpu := 0.0
	observed := evaluatedAt.Add(-time.Hour)
	next := "1.2"
	reader := &fakeReader{history: contracts.TelemetryHistoryV1{NextAfter: &next, Samples: []contracts.HistorySampleV1{{
		Sequence: 4, Source: "endpoint", CollectedAt: observed, ReceivedAt: observed.Add(time.Second), RequestSHA256: strings.Repeat("ab", 32),
		Metrics: contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &cpu, Unit: "percent"},
			TemperatureC: &contracts.MetricV2{Unit: "celsius", MissingReason: "permission_denied"}},
		LogReferences: []contracts.LogReferenceV2{{ReferenceID: "log:app", SHA256: strings.Repeat("cd", 32), ByteSize: 12, WindowStart: observed, WindowEnd: observed.Add(time.Minute)}},
	}, {Sequence: 5, Source: "fixture", CollectedAt: observed.Add(time.Minute), ReceivedAt: observed.Add(time.Minute), LogReferences: []contracts.LogReferenceV2{}}}}}
	view, status, err := DeviceHistory(context.Background(), reader, nil, "device:a", evaluatedAt)
	if err != nil || status != http.StatusOK || view.State != "ready" {
		t.Fatalf("history: %d %v %+v", status, err, view)
	}
	if !reader.to.Equal(evaluatedAt) || reader.to.Sub(reader.from) != DefaultHistoryWindow || reader.historyAfter != "" {
		t.Fatalf("default window: %s..%s", reader.from, reader.to)
	}
	if !strings.Contains(view.NextURL, "after=1.2") || !strings.Contains(view.NextURL, "from=") || !strings.Contains(view.NextURL, "to=") {
		t.Fatalf("next must pin the window: %q", view.NextURL)
	}
	body := renderHistory(t, view, status)
	for _, fragment := range []string{`class="sensor-value">0</span> <span class="sensor-unit">percent`, "Collection permission denied", "Collection denied",
		"Fixture source", "log:app: 12 bytes", strings.Repeat("cd", 32), strings.Repeat("ab", 32), "No error evidence was attached", "Next page", "Last 7 days"} {
		if !strings.Contains(body, fragment) {
			t.Errorf("history missing %q", fragment)
		}
	}
}

func TestDeviceHistoryDistinguishesEmptyDeniedAndFailure(t *testing.T) {
	window := url.Values{"from": {"2026-11-20T10:00:00Z"}, "to": {"2026-11-20T11:00:00Z"}}
	for _, test := range []struct {
		name   string
		reader DeviceReader
		query  url.Values
		status int
		state  string
		text   string
	}{
		{"empty window", &fakeReader{history: contracts.TelemetryHistoryV1{}}, window, http.StatusOK, "empty", "not evidence that the device was healthy"},
		{"store failure", &fakeReader{err: errors.New("connection refused")}, window, http.StatusServiceUnavailable, "error", "This is not an empty window"},
		{"unknown device", &fakeReader{err: ErrDeviceNotFound}, window, http.StatusNotFound, "not-found", "Device not found"},
		{"oversized window", &fakeReader{err: ErrDeviceQueryInvalid}, window, http.StatusBadRequest, "invalid", "History selection is not valid"},
		{"only from", &fakeReader{}, url.Values{"from": {"2026-11-20T10:00:00Z"}}, http.StatusBadRequest, "invalid", "not valid"},
		{"cursor without window", &fakeReader{}, url.Values{"after": {"1.2"}}, http.StatusBadRequest, "invalid", "not valid"},
		{"bad time", &fakeReader{}, url.Values{"from": {"yesterday"}, "to": {"today"}}, http.StatusBadRequest, "invalid", "not valid"},
		{"unknown parameter", &fakeReader{}, url.Values{"limit": {"500"}}, http.StatusBadRequest, "invalid", "not valid"},
		{"not configured", nil, nil, http.StatusOK, "not-configured", "not configured"},
	} {
		view, status, err := DeviceHistory(context.Background(), test.reader, test.query, "device:a", evaluatedAt)
		if status != test.status || view.State != test.state || len(view.Samples) != 0 || (err != nil) != (test.state == "error") {
			t.Errorf("%s: %d %q err=%v", test.name, status, view.State, err)
			continue
		}
		body := renderHistory(t, view, status)
		if !strings.Contains(body, test.text) || strings.Contains(body, "sensor-value") {
			t.Errorf("%s: wrong rendering", test.name)
		}
	}
	if !IsDeviceHistoryPath("/console/devices/device:a/history") || IsDeviceHistoryPath("/console/devices/a/b/history") || IsDeviceHistoryPath("/console/devices/history") {
		t.Fatal("history path allowlist")
	}
}
