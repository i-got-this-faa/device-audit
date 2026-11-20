package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

func TestTelemetryHistoryWindowCursorsAndDenials(t *testing.T) {
	b := newEnrollmentTestBed(t)
	for _, id := range []string{"device:a", "device:b"} {
		token := b.issue(t, id)
		keys := newEnrollmentKeys(t)
		b.submit(t, token, admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys), http.StatusCreated)
	}
	base := b.clock.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	insert := func(device string, seq int, collected time.Time, cpu float64, refs []contracts.LogReferenceV2) {
		t.Helper()
		payload, err := json.Marshal(contracts.TelemetryV2{SchemaVersion: contracts.TelemetryV2Version, DeviceID: device,
			CollectedAt: collected, Source: "endpoint", LogReferences: refs,
			Metrics: contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &cpu, Unit: "percent"},
				GPUUtilization: &contracts.MetricV2{Unit: "percent", MissingReason: "sensor_unavailable"}}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.db.Exec(`INSERT INTO device_evidence (deployment_id, device_id, sequence, envelope, payload_bytes, request_sha256, collected_at, received_at)
			VALUES ($1,$2,$3,'{}',$4,decode($5,'hex'),$6,$7)`, b.repo.deploymentID, device, seq, payload, strings.Repeat("ab", 32), collected, collected.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	ref := []contracts.LogReferenceV2{{ReferenceID: "log:app", SHA256: strings.Repeat("cd", 32), ByteSize: 12, WindowStart: base, WindowEnd: base.Add(time.Minute)}}
	// Sequences 2,3,4 share one timestamp; 5 is a minute later; 6 is outside the window.
	insert("device:a", 2, base, 1, ref)
	insert("device:a", 3, base, 2, []contracts.LogReferenceV2{})
	insert("device:a", 4, base, 3, []contracts.LogReferenceV2{})
	insert("device:a", 5, base.Add(time.Minute), 4, []contracts.LogReferenceV2{})
	insert("device:a", 6, base.Add(time.Hour), 5, []contracts.LogReferenceV2{})
	insert("device:b", 2, base, 9, []contracts.LogReferenceV2{})

	service, err := NewDeviceStateService(b.repo, b.admin)
	if err != nil {
		t.Fatal(err)
	}
	handler := NewAPI(Config{MaxDevices: 1, Auth: b.admin, DeviceState: service}).Handler()
	viewer, _ := b.addSession(t, "viewer:test", auth.RoleViewer, 0)
	get := func(handler http.Handler, device string, params url.Values, session string, want int) contracts.TelemetryHistoryV1 {
		t.Helper()
		if params.Get("deployment_id") == "" && params["deployment_id"] == nil {
			params.Set("deployment_id", b.repo.deploymentID)
		}
		r := httptest.NewRequest("GET", "/console/api/devices/"+device+"/history?"+params.Encode(), nil)
		if session != "" {
			r.AddCookie(&http.Cookie{Name: "__Host-device-audit-session", Value: session})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("GET %s %v: %d want %d: %s", device, params, w.Code, want, w.Body.String())
		}
		var page contracts.TelemetryHistoryV1
		if want == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
		}
		return page
	}
	window := func(from, to time.Time, extra ...string) url.Values {
		v := url.Values{"from": {from.Format(time.RFC3339Nano)}, "to": {to.Format(time.RFC3339Nano)}}
		for i := 0; i+1 < len(extra); i += 2 {
			v.Set(extra[i], extra[i+1])
		}
		return v
	}
	seqs := func(p contracts.TelemetryHistoryV1) []uint64 {
		out := []uint64{}
		for _, s := range p.Samples {
			out = append(out, s.Sequence)
		}
		return out
	}
	end := base.Add(30 * time.Minute)

	// Pages split inside the equal-timestamp group; nothing is skipped or repeated.
	var got []uint64
	var pages int
	cursor := ""
	for {
		params := window(base, end, "limit", "2")
		if cursor != "" {
			params.Set("after", cursor)
		}
		page := get(handler, "device:a", params, viewer, 200)
		pages++
		got = append(got, seqs(page)...)
		if page.NextAfter == nil {
			break
		}
		cursor = *page.NextAfter
	}
	if !reflect.DeepEqual(got, []uint64{2, 3, 4, 5}) || pages != 2 {
		t.Fatalf("paged sequences %v in %d pages", got, pages)
	}

	// Window end is exclusive, start inclusive, and a page that exactly fills the limit has no next.
	exact := get(handler, "device:a", window(base, base.Add(time.Minute), "limit", "3"), viewer, 200)
	if !reflect.DeepEqual(seqs(exact), []uint64{2, 3, 4}) || exact.NextAfter != nil {
		t.Fatalf("exact page: %+v", exact)
	}
	// Provenance, units, nulls and error references survive.
	first := get(handler, "device:a", window(base, end, "limit", "1"), viewer, 200).Samples[0]
	if first.Source != "endpoint" || first.CollectedAt != base || first.ReceivedAt != base.Add(time.Second) || len(first.RequestSHA256) != 64 ||
		first.Metrics.CPUUtilization.Unit != "percent" || first.Metrics.GPUUtilization.Value != nil || len(first.LogReferences) != 1 ||
		first.LogReferences[0].ReferenceID != "log:app" {
		t.Fatalf("sample lost fields: %+v", first)
	}
	// Empty window and another device's samples stay separate.
	if empty := get(handler, "device:a", window(base.Add(2*time.Hour), base.Add(3*time.Hour)), viewer, 200); len(empty.Samples) != 0 || empty.NextAfter != nil || empty.Samples == nil {
		t.Fatalf("empty window: %+v", empty)
	}
	if other := get(handler, "device:b", window(base, end), viewer, 200); !reflect.DeepEqual(seqs(other), []uint64{2}) {
		t.Fatalf("device b: %+v", other)
	}

	// Denials and bounds.
	get(handler, "device:a", window(base, end), "", 401)
	get(handler, "device:unknown", window(base, end), viewer, 404)
	get(handler, "device:a", url.Values{"deployment_id": {"deployment:other"}, "from": {base.Format(time.RFC3339)}, "to": {end.Format(time.RFC3339)}}, viewer, 403)
	bad := []url.Values{
		{}, {"from": {base.Format(time.RFC3339)}}, window(base, base), window(end, base), window(base, base.Add(32*24*time.Hour)),
		window(base, end, "limit", "0"), window(base, end, "limit", "101"), window(base, end, "limit", "05"),
		window(base, end, "after", "garbage"), window(base, end, "after", "1.1"), window(base, end, "other", "x"),
		{"from": {"yesterday"}, "to": {end.Format(time.RFC3339)}},
	}
	for _, params := range bad {
		get(handler, "device:a", params, viewer, 400)
	}
	get(handler, "device:a", url.Values{"deployment_id": {""}, "from": {base.Format(time.RFC3339)}, "to": {end.Format(time.RFC3339)}}, viewer, 400)

	// A restarted controller serves the same history.
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
	before := get(handler, "device:a", window(base, end), viewer, 200)
	if after := get(restarted, "device:a", window(base, end), viewer, 200); !reflect.DeepEqual(before, after) || len(after.Samples) != 4 {
		t.Fatalf("history after restart: %+v", after)
	}
}
