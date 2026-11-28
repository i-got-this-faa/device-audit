package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	webconsole "github.com/i-got-this-faa/device-audit/apps/web-console"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestConsoleNavigationAuthorization(t *testing.T) {
	s, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, s)
	viewer, _ := addSession(t, store, clock, "viewer:private", RoleViewer)
	admin, _ := addSession(t, store, clock, "admin:private", RoleAdmin)
	client := noRedirectClient()
	for _, path := range []string{"/console", "/console/devices", "/console/devices/fixture-laptop", "/console/workflows", "/console/access"} {
		r := request(t, client, server.URL+path, "GET", "", map[string]string{"Accept": "text/html"}, "")
		if r.StatusCode != 302 || !strings.Contains(r.Header.Get("Location"), "return_to=") {
			t.Fatalf("anonymous %s: %d", path, r.StatusCode)
		}
		if strings.Contains(readBody(r), "private") {
			t.Fatal("anonymous navigation leaked subject")
		}
		r.Body.Close()
		r = request(t, client, server.URL+path, "GET", "", map[string]string{}, viewer)
		want := 200
		if path == "/console/access" {
			want = 403
		}
		body := readBody(r)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("viewer %s: %d", path, r.StatusCode)
		}
		if path == "/console/access" && strings.Contains(body, "admin:private") {
			t.Fatal("denied page leaked bindings")
		}
		if r.Header.Get("Cache-Control") != "no-store" || !strings.Contains(r.Header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatal("unprotected response policy")
		}
		r = request(t, client, server.URL+path, "GET", "", map[string]string{}, admin)
		if r.StatusCode != 200 {
			t.Fatalf("admin %s: %d", path, r.StatusCode)
		}
		r.Body.Close()
	}
	clock.Advance(15 * time.Minute)
	for _, path := range []string{"/console/devices", "/console/devices/fixture-laptop", "/console/workflows", "/console/access"} {
		r := request(t, client, server.URL+path, "GET", "", map[string]string{}, admin)
		body := readBody(r)
		r.Body.Close()
		if r.StatusCode != 302 || strings.Contains(body, "private") {
			t.Fatalf("expired %s: %d", path, r.StatusCode)
		}
	}
	for _, target := range []string{"//attacker.example", "/console/devices?next=https://attacker.example", "/console/devices/../access", "/console/api/devices/x/inventory", "/console/workflows/evil", "/console/devices/", "/console/devices/bad id", "/console/devices/.hidden", "/console/devices/fixture-laptop?fixture=live", "/console/devices/fixture-laptop/extra"} {
		if allowedReturnTo(target) {
			t.Fatalf("unsafe return path %q", target)
		}
	}
}

func TestConsoleEscapesSubjectsAndFailsClosed(t *testing.T) {
	s, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, s)
	id, _ := addSession(t, store, clock, `<script>alert("subject")</script>`, RoleViewer)
	r := request(t, noRedirectClient(), server.URL+"/console", "GET", "", nil, id)
	body := readBody(r)
	r.Body.Close()
	if strings.Contains(body, `<script>alert`) || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("unescaped subject")
	}
	store.setFail(true)
	r = request(t, noRedirectClient(), server.URL+"/console/devices/fixture-laptop", "GET", "", nil, id)
	body = readBody(r)
	r.Body.Close()
	if r.StatusCode != 503 || strings.Contains(body, "subject") || strings.Contains(body, "data-protected") {
		t.Fatal("unavailable store leaked protected shell")
	}
}

// browserDevices is a test-only enrolled inventory for the browser suite.
// Devices report at read time unless a control pins an older observation.
type browserDevices struct {
	mu       sync.Mutex
	observed map[string]time.Duration
	fail     bool
	denied   bool
}

var browserDeviceIDs = []string{"endpoint:browser-a", "endpoint:browser-b", "endpoint:browser-fixture"}

func (d *browserDevices) state(id string, now time.Time) contracts.DeviceStateV1 {
	zero, latency := 0.0, 18.25
	metrics := contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &zero, Unit: "percent"},
		BatteryPercent:   &contracts.MetricV2{Unit: "percent", MissingReason: "sensor_unavailable"},
		NetworkLatencyMS: &contracts.MetricV2{Value: &latency, Unit: "milliseconds"}}
	source := "endpoint"
	if strings.HasSuffix(id, "fixture") {
		source = "fixture"
	}
	observed := now.Add(-d.observed[id]).Truncate(time.Second)
	return contracts.DeviceStateV1{DeviceID: id, SigningKeyID: "key:" + id, EnrolledAt: observed.Add(-time.Hour), LastSequence: 9,
		Latest: &contracts.LatestSampleV1{Sequence: 9, Source: source, CollectedAt: observed, ReceivedAt: observed,
			RequestSHA256: strings.Repeat("0f", 32), Metrics: metrics, Sensors: contracts.SensorStates(metrics)}}
}

func (d *browserDevices) DeviceStates(_ context.Context, after string, _ int) (contracts.DeviceStatePageV1, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	page := contracts.DeviceStatePageV1{Devices: []contracts.DeviceStateV1{}}
	if d.fail {
		return page, errors.New("synthetic inventory outage")
	}
	for _, id := range browserDeviceIDs {
		if id > after {
			page.Devices = append(page.Devices, d.state(id, time.Now()))
		}
	}
	return page, nil
}

func (d *browserDevices) DeviceState(_ context.Context, id string) (contracts.DeviceStateV1, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return contracts.DeviceStateV1{}, errors.New("synthetic inventory outage")
	}
	for _, known := range browserDeviceIDs {
		if known == id {
			return d.state(id, time.Now()), nil
		}
	}
	return contracts.DeviceStateV1{}, webconsole.ErrDeviceNotFound
}

// TelemetryHistory serves three synthetic samples ending at read time. The
// middle one carries a denied sensor and an error-evidence reference.
func (d *browserDevices) TelemetryHistory(_ context.Context, id string, from, to time.Time, after string, _ int) (contracts.TelemetryHistoryV1, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return contracts.TelemetryHistoryV1{}, errors.New("synthetic inventory outage")
	}
	if !slices.Contains(browserDeviceIDs, id) {
		return contracts.TelemetryHistoryV1{}, webconsole.ErrDeviceNotFound
	}
	if !from.Before(to) || to.Sub(from) > contracts.TelemetryHistoryWindowMaxV1 {
		return contracts.TelemetryHistoryV1{}, webconsole.ErrDeviceQueryInvalid
	}
	page := contracts.TelemetryHistoryV1{From: from, To: to, Samples: []contracts.HistorySampleV1{}}
	zero := 0.0
	for i := range 3 {
		collected := to.Add(-time.Duration(3-i) * time.Minute).Truncate(time.Second)
		if collected.Before(from) || (after != "" && i == 0) {
			continue
		}
		metrics := contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &zero, Unit: "percent"}}
		refs := []contracts.LogReferenceV2{}
		if i == 1 {
			metrics.TemperatureC = &contracts.MetricV2{Unit: "celsius", MissingReason: "permission_denied"}
			refs = append(refs, contracts.LogReferenceV2{ReferenceID: "log:system", SHA256: strings.Repeat("cd", 32), ByteSize: 512,
				WindowStart: collected.Add(-time.Minute), WindowEnd: collected})
		}
		page.Samples = append(page.Samples, contracts.HistorySampleV1{Sequence: uint64(i + 2), Source: "endpoint", CollectedAt: collected,
			ReceivedAt: collected, RequestSHA256: strings.Repeat("0f", 32), Metrics: metrics, LogReferences: refs})
	}
	if after == "" && len(page.Samples) > 0 {
		next := "1.2"
		page.NextAfter = &next
		page.Samples = page.Samples[:1]
	}
	return page, nil
}

// browserPrediction builds browser-a's records: an unknown, evidence-less
// assessment and a known, expiring one. Browser-b's newest record has expired.
func browserPrediction(id uint64, deviceID string, asOf time.Time, known bool) contracts.PredictionHistoryRecordV1 {
	rec := contracts.PredictionHistoryRecordV1{ID: id, AsOf: asOf, RecordedAt: asOf, RulesVersion: "rules.v1", RuleReason: "no_telemetry_evidence",
		ModelStatus: "unavailable", Features: contracts.PredictionFeatureRefV1{FeatureVersion: "ct03.v1", Status: "missing"},
		Health: contracts.HealthV2{Status: "unknown", ProbabilityUnit: "probability", UnknownReason: "insufficient_evidence"}}
	if !known {
		return rec
	}
	probability, horizon, expires := 0.125, uint32(72), asOf.Add(time.Hour)
	rec.RuleReason, rec.ModelStatus, rec.ExpiresAt = "model_ready", "ready", &expires
	rec.Health = contracts.HealthV2{Status: "degraded", Probability: &probability, ProbabilityUnit: "probability", HorizonHours: &horizon}
	rec.ModelProvenance = &contracts.PredictionModelProvenanceV1{Version: "model:browser", SHA256: strings.Repeat("aa", 32),
		PolicyVersion: "ml05.v1", PolicySHA256: strings.Repeat("bb", 32), EvaluationSHA256: strings.Repeat("cc", 32)}
	rec.Evidence = &contracts.PredictionEvidenceRefV1{Sequence: 9, CollectedAt: asOf.Add(-time.Minute), ReceivedAt: asOf.Add(-time.Minute),
		PayloadSHA256: strings.Repeat("dd", 32), RequestSHA256: strings.Repeat("0f", 32), Source: "endpoint", TelemetrySchemaVersion: contracts.TelemetryV2Version}
	rec.Features.Status, rec.Features.FeatureCount, rec.Features.SamplesRead = contracts.FeatureStatusComplete, 12, 60
	rec.Prediction = &contracts.PredictionV2{DeviceID: deviceID, GeneratedAt: asOf, ExpiresAt: expires, Health: rec.Health,
		Forecasts: []contracts.FaultForecastV2{{Category: "storage", Probability: probability, ProbabilityUnit: "probability", HorizonHours: horizon}}}
	return rec
}

func (d *browserDevices) predictionRecords(id string, now time.Time) []contracts.PredictionHistoryRecordV1 {
	now = now.UTC().Truncate(time.Second)
	switch id {
	case "endpoint:browser-a":
		return []contracts.PredictionHistoryRecordV1{browserPrediction(1, id, now.Add(-2*time.Hour), false), browserPrediction(2, id, now.Add(-10*time.Minute), true)}
	case "endpoint:browser-b":
		return []contracts.PredictionHistoryRecordV1{browserPrediction(3, id, now.Add(-3*time.Hour), true)}
	}
	return nil
}

func (d *browserDevices) PredictionHistory(_ context.Context, id string, from, to time.Time, after string, _ int) (contracts.PredictionHistoryV1, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.fail:
		return contracts.PredictionHistoryV1{}, errors.New("synthetic inventory outage")
	case d.denied:
		return contracts.PredictionHistoryV1{}, webconsole.ErrPredictionEvidenceDenied
	case !slices.Contains(browserDeviceIDs, id):
		return contracts.PredictionHistoryV1{}, webconsole.ErrDeviceNotFound
	case !from.Before(to) || to.Sub(from) > contracts.PredictionHistoryWindowMaxV1:
		return contracts.PredictionHistoryV1{}, webconsole.ErrDeviceQueryInvalid
	}
	page := contracts.PredictionHistoryV1{From: from, To: to, Records: []contracts.PredictionHistoryRecordV1{}}
	for _, rec := range d.predictionRecords(id, time.Now()) {
		if !rec.AsOf.Before(from) && rec.AsOf.Before(to) && after == "" {
			page.Records = append(page.Records, rec)
		}
	}
	return page, nil
}

func (d *browserDevices) LatestPrediction(_ context.Context, id string) (contracts.LatestPredictionV1, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now().UTC()
	records := d.predictionRecords(id, now)
	if len(records) == 0 {
		return contracts.LatestPredictionV1{}, webconsole.ErrDeviceNotFound
	}
	rec := records[len(records)-1]
	latest := contracts.LatestPredictionV1{EvaluatedAt: now, Record: rec, CurrentHealth: rec.Health}
	if rec.ExpiresAt != nil && !now.Before(*rec.ExpiresAt) {
		latest.Stale = true
		latest.CurrentHealth = contracts.HealthV2{Status: "unknown", ProbabilityUnit: "probability", UnknownReason: "stale_evidence"}
	}
	return latest, nil
}

func (d *browserDevices) set(update func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	update()
}

// This fixture is compiled only by go test. It provides real OIDC/TLS routes
// with synthetic accounts and an in-memory auth store, never a login bypass in
// the controller binary.
func consoleBrowserFixture(t *testing.T) *httptest.Server {
	t.Helper()
	s, issuer, app, _, clock, _ := newOIDCTestBed(t)
	// The browser runs in real time. The issuer must stamp tokens from the
	// same clock as the service, or every login is rejected as not fresh.
	s.now = time.Now
	issuer.mu.Lock()
	issuer.now = time.Now
	issuer.mu.Unlock()
	issuer.SetSubject("viewer:browser")
	if err := s.EnsureBinding(context.Background(), "viewer:browser", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureBinding(context.Background(), "admin:browser", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	store := s.store.(*memoryStore)
	devices := &browserDevices{observed: map[string]time.Duration{}}
	s.devices = devices
	mux := app.Config.Handler.(*http.ServeMux)
	mux.HandleFunc("POST /__test/{action}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("action") {
		case "expire":
			store.mu.Lock()
			for key, session := range store.sessions {
				session.IdleExpiresAt = clock.Now()
				store.sessions[key] = session
			}
			store.mu.Unlock()
		case "viewer":
			issuer.SetSubject("viewer:browser")
		case "admin":
			issuer.SetSubject("admin:browser")
		case "unknown":
			issuer.SetSubject("unknown:private")
		case "outage":
			store.setFail(true)
		case "restore":
			store.setFail(false)
		case "stale-b":
			devices.set(func() { devices.observed["endpoint:browser-b"] = webconsole.StaleAfter + time.Minute })
		case "offline-b":
			devices.set(func() { devices.observed["endpoint:browser-b"] = webconsole.OfflineAfter + time.Minute })
		case "devices-outage":
			devices.set(func() { devices.fail = true })
		case "devices-restore":
			devices.set(func() { devices.fail = false })
		case "predictions-denied":
			devices.set(func() { devices.denied = true })
		case "predictions-restore":
			devices.set(func() { devices.denied = false })
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return app
}

func TestConsoleBrowser(t *testing.T) {
	if os.Getenv("CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("run make browser-check with Node and a Chromium executable")
	}
	app := consoleBrowserFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../../apps/web-console/tests/browser.mjs", app.URL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser acceptance: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestConsolePreview(t *testing.T) {
	path := os.Getenv("CONSOLE_PREVIEW_FILE")
	if path == "" {
		t.Skip("set CONSOLE_PREVIEW_FILE for a ten-minute synthetic preview")
	}
	app := consoleBrowserFixture(t)
	if err := os.WriteFile(path, []byte(app.URL), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("Synthetic console preview: %s", app.URL)
	timer := time.NewTimer(10 * time.Minute)
	defer timer.Stop()
	select {
	case <-t.Context().Done():
	case <-timer.C:
	}
}
