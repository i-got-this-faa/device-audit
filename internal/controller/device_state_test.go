package controller

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	webconsole "github.com/i-got-this-faa/device-audit/apps/web-console"
	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestDeviceStateHTTPPaginationProvenanceAndRestart(t *testing.T) {
	b := newEnrollmentTestBed(t)
	devices := []string{"device:a", "device:b", "device:c"}
	for _, id := range devices {
		token := b.issue(t, id)
		keys := newEnrollmentKeys(t)
		b.submit(t, token, admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys), http.StatusCreated)
	}
	// Commit a sample for device:b as AcceptEvidence would; its payload carries one
	// known metric, one null sensor and five metrics the endpoint did not report.
	cpu, collectedAt, receivedAt := 41.5, b.clock.Now().Add(-time.Minute), b.clock.Now()
	payload, err := json.Marshal(contracts.TelemetryV2{SchemaVersion: contracts.TelemetryV2Version, DeviceID: "device:b",
		CollectedAt: collectedAt, Source: "endpoint", LogReferences: []contracts.LogReferenceV2{},
		Metrics: contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &cpu, Unit: "percent"},
			GPUUtilization: &contracts.MetricV2{Unit: "percent", MissingReason: "sensor_unavailable"}}})
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("ab", 32)
	if _, err := b.db.Exec(`INSERT INTO device_evidence (deployment_id, device_id, sequence, envelope, payload_bytes, request_sha256, collected_at, received_at)
		VALUES ($1,'device:b',2,'{}',$2,decode($3,'hex'),$4,$5)`, b.repo.deploymentID, payload, digest, collectedAt, receivedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := b.db.Exec(`UPDATE device_enrollments SET last_sequence=2 WHERE device_id='device:b'`); err != nil {
		t.Fatal(err)
	}

	service, err := NewDeviceStateService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service}).Handler()
	viewer, _ := b.addSession(t, "viewer:test", auth.RoleViewer, 0)
	get := func(handler http.Handler, target, session string, want int) []byte {
		t.Helper()
		r := httptest.NewRequest("GET", target, nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("GET %s: %d want %d: %s", target, w.Code, want, w.Body.String())
		}
		return w.Body.Bytes()
	}
	scope := "?deployment_id=" + b.repo.deploymentID
	decodePage := func(data []byte) contracts.DeviceStatePageV1 {
		var page contracts.DeviceStatePageV1
		if err := json.Unmarshal(data, &page); err != nil {
			t.Fatal(err)
		}
		return page
	}

	first := decodePage(get(handler, "/console/api/devices"+scope+"&limit=2", viewer, 200))
	if len(first.Devices) != 2 || first.NextAfter == nil || *first.NextAfter != "device:b" || first.Devices[0].DeviceID != "device:a" {
		t.Fatalf("first page: %+v", first)
	}
	second := decodePage(get(handler, "/console/api/devices"+scope+"&limit=2&after=device:b", viewer, 200))
	if len(second.Devices) != 1 || second.NextAfter != nil || second.Devices[0].DeviceID != "device:c" {
		t.Fatalf("second page: %+v", second)
	}
	if first.Devices[0].Latest != nil || first.Devices[0].LastSequence != 1 {
		t.Fatalf("device without a sample reports one: %+v", first.Devices[0])
	}
	latest := first.Devices[1].Latest
	if latest == nil || latest.Sequence != 2 || latest.Source != "endpoint" || latest.RequestSHA256 != digest ||
		!latest.CollectedAt.Equal(collectedAt) || !latest.ReceivedAt.Equal(receivedAt) || *latest.Metrics.CPUUtilization.Value != cpu {
		t.Fatalf("latest provenance: %+v", latest)
	}
	wantSensors := map[string]contracts.SensorStateV1{
		"cpu_utilization": {Metric: "cpu_utilization", Availability: contracts.SensorAvailable},
		"gpu_utilization": {Metric: "gpu_utilization", Availability: contracts.SensorMissing, MissingReason: "sensor_unavailable"},
		"temperature_c":   {Metric: "temperature_c", Availability: contracts.SensorNotReported},
	}
	if len(latest.Sensors) != 7 {
		t.Fatalf("sensors: %+v", latest.Sensors)
	}
	for _, sensor := range latest.Sensors {
		if want, ok := wantSensors[sensor.Metric]; ok && sensor != want {
			t.Fatalf("sensor %s: %+v want %+v", sensor.Metric, sensor, want)
		}
	}
	if latest.Metrics.GPUUtilization.Value != nil || latest.Metrics.GPUUtilization.Unit != "percent" {
		t.Fatalf("nullable metric lost: %+v", latest.Metrics.GPUUtilization)
	}

	// Failures are visible, not empty pages.
	get(handler, "/console/api/devices"+scope, "", 401)
	for _, query := range []string{"", "?deployment_id=", scope + "&limit=0", scope + "&limit=101", scope + "&limit=abc", scope + "&limit=05",
		scope + "&limit=2&limit=3", scope + "&after=bad%20id", scope + "&other=x", "?deployment_id=%zz"} {
		get(handler, "/console/api/devices"+query, viewer, 400)
	}
	get(handler, "/console/api/devices?deployment_id=deployment:other", viewer, 403)
	get(handler, "/console/api/devices/device:b?deployment_id=deployment:other", viewer, 403)
	get(handler, "/console/api/devices/device:unknown"+scope, viewer, 404)
	get(handler, "/console/api/devices/device:b", viewer, 400)

	// A restarted controller returns identical identities and timestamps.
	db, err := database.Open(context.Background(), b.url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo, err := NewPostgresRepository(context.Background(), db, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := NewDeviceStateService(repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	restarted := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: reopened}).Handler()
	var detail contracts.DeviceStateV1
	if err := json.Unmarshal(get(restarted, "/console/api/devices/device:b"+scope, viewer, 200), &detail); err != nil || !reflect.DeepEqual(detail, first.Devices[1]) {
		t.Fatalf("detail after restart: %+v %v", detail, err)
	}
	if all := decodePage(get(restarted, "/console/api/devices"+scope, viewer, 200)); len(all.Devices) != 3 || all.NextAfter != nil ||
		!reflect.DeepEqual(all.Devices[:2], first.Devices) {
		t.Fatalf("list after restart: %+v", all)
	}
}

// TestConsoleFreshnessFromSignedEvidence drives two enrolled devices through
// the signed evidence path, then stops one. Only that device leaves Current,
// and the JSON API reports the same observed times.
func TestConsoleFreshnessFromSignedEvidence(t *testing.T) {
	b := newEnrollmentTestBed(t)
	ctx := context.Background()
	devices := []meshTestDevice{enrollMeshTestDevice(t, b, "endpoint:a"), enrollMeshTestDevice(t, b, "endpoint:b")}
	accept := func(d meshTestDevice, sequence uint64) {
		t.Helper()
		if _, err := b.repo.AcceptEvidence(ctx, meshReplayEvidence(t, b, d, sequence)); err != nil {
			t.Fatalf("accept %s/%d: %v", d.id, sequence, err)
		}
	}
	newHandler := func(reader *PostgresRepository) http.Handler {
		console, err := auth.NewService(auth.Config{Issuer: "https://id.example.test", PublicOrigin: "https://console.example.test", Store: b.authStore,
			Provider: auth.NewOIDCProvider("https://id.example.test", "test-client", "test-only", "https://console.example.test/auth/callback", nil),
			Now:      b.clock.Now, Logger: slog.New(slog.NewTextHandler(b.logs, nil)), Devices: reader.ConsoleDevices()})
		if err != nil {
			t.Fatal(err)
		}
		service, err := NewDeviceStateService(reader, console)
		if err != nil {
			t.Fatal(err)
		}
		return NewAPI(Config{MaxDevices: 1, Auth: console, DeviceState: service}).Handler()
	}
	handler := newHandler(b.repo)
	get := func(handler http.Handler, target string, want int) string {
		t.Helper()
		// A new session each read: the test clock outruns the idle expiry.
		session, _ := b.addSession(t, "viewer:freshness", auth.RoleViewer, 0)
		r := httptest.NewRequest("GET", target, nil)
		r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("GET %s: %d want %d: %s", target, w.Code, want, w.Body.String())
		}
		return w.Body.String()
	}
	states := func() map[string]string {
		t.Helper()
		body := get(handler, "/console/devices", 200)
		found := map[string]string{}
		for _, row := range strings.Split(body, "<li>")[1:] {
			for _, d := range devices {
				if strings.Contains(row, ">"+d.id+"</a>") {
					state := strings.SplitN(strings.SplitN(row, `class="device-status" data-state="`, 2)[1], `"`, 2)[0]
					found[d.id] = state
				}
			}
		}
		return found
	}
	requireStates := func(a, c string) {
		t.Helper()
		if got := states(); got["endpoint:a"] != a || got["endpoint:b"] != c {
			t.Fatalf("freshness: %v want endpoint:a=%s endpoint:b=%s", got, a, c)
		}
	}

	requireStates("no-sample", "no-sample")
	accept(devices[0], 2)
	accept(devices[1], 2)
	requireStates("current", "current")

	// endpoint:b stops; endpoint:a keeps reporting.
	b.clock.Advance(webconsole.StaleAfter)
	accept(devices[0], 3)
	requireStates("current", "stale")
	b.clock.Advance(webconsole.OfflineAfter - webconsole.StaleAfter)
	accept(devices[0], 4)
	requireStates("current", "offline")

	detail := get(handler, "/console/devices/endpoint:b", 200)
	for _, fragment := range []string{"Offline: the endpoint has not reported recently", `class="sensor-unit">percent</span>`, "Reported by the endpoint.", "15m0s before evaluation"} {
		if !strings.Contains(detail, fragment) {
			t.Fatalf("offline detail missing %q", fragment)
		}
	}
	if strings.Contains(detail, "Fixture source") {
		t.Fatal("endpoint sample labelled as fixture source")
	}

	var page contracts.DeviceStatePageV1
	if err := json.Unmarshal([]byte(get(handler, "/console/api/devices?deployment_id="+b.repo.deploymentID, 200)), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Devices) != 2 || page.Devices[0].Latest.Sequence != 4 || page.Devices[1].Latest.Sequence != 2 ||
		!page.Devices[1].Latest.CollectedAt.Equal(b.clock.Now().Add(-webconsole.OfflineAfter)) {
		t.Fatalf("API disagrees with console: %+v", page)
	}

	// A failed inventory read is an error page, never a stale or zero value.
	failing, err := database.Open(ctx, b.url)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := NewPostgresRepository(ctx, failing, RepositoryConfig{DeploymentID: b.repo.deploymentID, Now: b.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	failing.Close()
	handler = newHandler(broken)
	for _, target := range []string{"/console/devices", "/console/devices/endpoint:a"} {
		body := get(handler, target, 503)
		if !strings.Contains(body, "Device data could not be loaded") || strings.Contains(body, "endpoint:a</") || strings.Contains(body, "sensor-value") || strings.Contains(body, "Fixture data") {
			t.Fatalf("%s outage rendered device data", target)
		}
	}
	get(handler, "/console/devices/endpoint:missing", 503)
	handler = newHandler(b.repo)
	get(handler, "/console/devices/endpoint:missing", 404)
	get(handler, "/console/devices?after=bad%20id", 400)
	if !strings.Contains(get(handler, "/console/devices?fixture=live", 200), "Fixture data") {
		t.Fatal("explicit fixture selection lost its fixture banner")
	}
}
