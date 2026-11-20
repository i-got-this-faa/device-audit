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

type fakeReader struct {
	page  contracts.DeviceStatePageV1
	state contracts.DeviceStateV1
	err   error
	after string
}

func (f *fakeReader) DeviceStates(_ context.Context, after string, _ int) (contracts.DeviceStatePageV1, error) {
	f.after = after
	return f.page, f.err
}

func (f *fakeReader) DeviceState(context.Context, string) (contracts.DeviceStateV1, error) {
	return f.state, f.err
}

var evaluatedAt = time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

func sampledDevice(id, source string, observedAt time.Time, metrics contracts.MetricsV2) contracts.DeviceStateV1 {
	return contracts.DeviceStateV1{DeviceID: id, SigningKeyID: "key:" + id, EnrolledAt: observedAt.Add(-time.Hour), LastSequence: 7,
		Latest: &contracts.LatestSampleV1{Sequence: 7, Source: source, CollectedAt: observedAt, ReceivedAt: observedAt.Add(time.Second),
			RequestSHA256: strings.Repeat("ab", 32), Metrics: metrics, Sensors: contracts.SensorStates(metrics)}}
}

func TestClassifyFreshnessUsesObservedTimeBoundaries(t *testing.T) {
	for _, test := range []struct {
		age  time.Duration
		want Freshness
	}{
		{-time.Minute, FreshnessCurrent}, {0, FreshnessCurrent}, {StaleAfter - time.Nanosecond, FreshnessCurrent},
		{StaleAfter, FreshnessStale}, {OfflineAfter - time.Nanosecond, FreshnessStale}, {OfflineAfter, FreshnessOffline},
	} {
		// A recent receipt must not refresh an old observation.
		latest := &contracts.LatestSampleV1{CollectedAt: evaluatedAt.Add(-test.age), ReceivedAt: evaluatedAt}
		if got := ClassifyFreshness(latest, evaluatedAt); got != test.want {
			t.Errorf("age %s: %s want %s", test.age, got, test.want)
		}
	}
	if got := ClassifyFreshness(nil, evaluatedAt); got != FreshnessNoSample {
		t.Fatalf("no sample: %s", got)
	}
}

func TestEnrolledDevicesListFreshnessUnitsAndProvenance(t *testing.T) {
	cpu, zero := 41.5, 0.0
	metrics := contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &cpu, Unit: "percent"},
		MemoryPercent:  &contracts.MetricV2{Value: &zero, Unit: "percent"},
		BatteryPercent: &contracts.MetricV2{Unit: "percent", MissingReason: "sensor_unavailable"}}
	next := "device:c"
	reader := &fakeReader{page: contracts.DeviceStatePageV1{NextAfter: &next, Devices: []contracts.DeviceStateV1{
		sampledDevice("device:a", "endpoint", evaluatedAt.Add(-30*time.Second), metrics),
		sampledDevice("device:b", "endpoint", evaluatedAt.Add(-5*time.Minute), metrics),
		sampledDevice("device:c", "fixture", evaluatedAt.Add(-time.Hour), metrics),
		{DeviceID: "device:d", SigningKeyID: "key:d", EnrolledAt: evaluatedAt},
	}}}
	view, status, err := EnrolledDevices(context.Background(), reader, url.Values{"after": {"device:0"}}, "", evaluatedAt)
	if err != nil || status != http.StatusOK || view.State != "ready" || reader.after != "device:0" {
		t.Fatalf("list: %d %v %+v", status, err, view)
	}
	want := []Freshness{FreshnessCurrent, FreshnessStale, FreshnessOffline, FreshnessNoSample}
	for i, row := range view.Rows {
		if row.Freshness != want[i] {
			t.Errorf("%s: %s want %s", row.ID, row.Freshness, want[i])
		}
	}
	if view.Rows[0].FixtureSource || !view.Rows[2].FixtureSource || view.Rows[3].HasSample {
		t.Fatal("source provenance lost")
	}
	if view.NextURL != "/console/devices?after=device%3Ac" {
		t.Fatalf("next page: %q", view.NextURL)
	}
	sensors := view.Rows[0].Sensors
	if sensors[0].Value != "41.5" || sensors[0].Unit != "percent" || sensors[2].Value != "0" ||
		sensors[4].Value != "Unknown" || !strings.Contains(sensors[4].Explanation, "Sensor unavailable") ||
		sensors[5].Value != "Unknown" || sensors[5].Unit != "celsius" || sensors[5].Explanation != "Not reported in this sample." {
		t.Fatalf("sensor rendering: %+v", sensors)
	}

	w := httptest.NewRecorder()
	if err := Render(w, status, Page{Title: "Devices", Section: "devices", Subject: "viewer", Inventory: view}); err != nil {
		t.Fatal(err)
	}
	body := w.Body.String()
	for _, fragment := range []string{`data-state="current">Current`, `data-state="stale">Stale`, `data-state="offline">Offline`,
		`data-state="no-sample">No sample`, "Fixture source", "5m0s before evaluation", "Next page"} {
		if !strings.Contains(body, fragment) {
			t.Errorf("list missing %q", fragment)
		}
	}
	if strings.Contains(body, "Synthetic examples") {
		t.Fatal("enrolled list carries the fixture catalogue banner")
	}
}

func TestEnrolledDeviceDetailShowsHistoricalWarnings(t *testing.T) {
	cpu := 12.0
	state := sampledDevice("device:b", "endpoint", evaluatedAt.Add(-20*time.Minute), contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &cpu, Unit: "percent"}})
	revoked := evaluatedAt.Add(-time.Minute)
	state.RevokedAt = &revoked
	view, status, err := EnrolledDevices(context.Background(), &fakeReader{state: state}, nil, "device:b", evaluatedAt)
	if err != nil || status != http.StatusOK || view.Detail == nil {
		t.Fatalf("detail: %d %v", status, err)
	}
	w := httptest.NewRecorder()
	if err := Render(w, status, Page{Title: "Device detail", Section: "devices", Subject: "viewer", Inventory: view}); err != nil {
		t.Fatal(err)
	}
	body := w.Body.String()
	for _, fragment := range []string{"Offline: the endpoint has not reported recently", "Revoked at", `class="sensor-value">12</span>`, "Reported by the endpoint.", strings.Repeat("ab", 32)} {
		if !strings.Contains(body, fragment) {
			t.Errorf("detail missing %q", fragment)
		}
	}
}

func TestEnrolledDevicesFailuresShowNoMeasurements(t *testing.T) {
	outage := errors.New("connection refused")
	for _, test := range []struct {
		name   string
		reader DeviceReader
		query  url.Values
		id     string
		status int
		state  string
	}{
		{"outage list", &fakeReader{err: outage}, nil, "", http.StatusServiceUnavailable, "error"},
		{"outage detail", &fakeReader{err: outage}, nil, "device:a", http.StatusServiceUnavailable, "error"},
		{"unknown device", &fakeReader{err: ErrDeviceNotFound}, nil, "device:x", http.StatusNotFound, "not-found"},
		{"bad cursor", &fakeReader{err: ErrDeviceQueryInvalid}, url.Values{"after": {"device:a"}}, "", http.StatusBadRequest, "invalid"},
		{"unknown parameter", &fakeReader{}, url.Values{"limit": {"500"}}, "", http.StatusBadRequest, "invalid"},
		{"repeated cursor", &fakeReader{}, url.Values{"after": {"a", "b"}}, "", http.StatusBadRequest, "invalid"},
		{"detail cursor", &fakeReader{}, url.Values{"after": {"a"}}, "device:a", http.StatusBadRequest, "invalid"},
		{"not configured", nil, nil, "", http.StatusOK, "not-configured"},
		{"empty", &fakeReader{}, nil, "", http.StatusOK, "empty"},
	} {
		view, status, err := EnrolledDevices(context.Background(), test.reader, test.query, test.id, evaluatedAt)
		if status != test.status || view.State != test.state || view.Detail != nil || len(view.Rows) != 0 || (err != nil) != (test.state == "error") {
			t.Errorf("%s: %d %q err=%v", test.name, status, view.State, err)
			continue
		}
		w := httptest.NewRecorder()
		if err := Render(w, status, Page{Title: "Devices", Section: "devices", Subject: "viewer", Inventory: view}); err != nil {
			t.Fatal(err)
		}
		body := w.Body.String()
		if !strings.Contains(body, "data-protected") || strings.Contains(body, "sensor-value") || strings.Contains(body, "Current") || strings.Contains(body, "Operations laptop") {
			t.Errorf("%s rendered a measurement, freshness or fixture device", test.name)
		}
	}
}
