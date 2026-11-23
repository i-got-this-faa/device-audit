package controller

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// pagedHistory serves fixed samples in pages of two, recording each window it is asked for.
type pagedHistory struct {
	samples      []contracts.HistorySampleV1
	from, to     time.Time
	pages        int
	failOnPage   int
	badNextAfter bool
}

func (h *pagedHistory) TelemetryHistory(_ context.Context, _ string, from, to time.Time, after *historyCursor, limit int) (contracts.TelemetryHistoryV1, error) {
	h.from, h.to = from, to
	h.pages++
	if h.failOnPage == h.pages {
		return contracts.TelemetryHistoryV1{}, ErrRepositoryUnavailable
	}
	start := 0
	if after != nil {
		for start < len(h.samples) && h.samples[start].Sequence != after.sequence {
			start++
		}
		start++
	}
	end := min(start+2, len(h.samples))
	page := contracts.TelemetryHistoryV1{DeploymentID: "deployment:features", Samples: h.samples[start:end]}
	if end < len(h.samples) {
		next := historyCursor{collectedAt: h.samples[end-1].CollectedAt, sequence: h.samples[end-1].Sequence}.String()
		if h.badNextAfter {
			next = "not-a-cursor"
		}
		page.NextAfter = &next
	}
	return page, nil
}

func historySamples(base time.Time, sequences ...uint64) []contracts.HistorySampleV1 {
	var out []contracts.HistorySampleV1
	for i, seq := range sequences {
		out = append(out, contracts.HistorySampleV1{Sequence: seq, CollectedAt: base.Add(time.Duration(i) * time.Hour)})
	}
	return out
}

func TestBuildDeviceFeaturesAsksOnlyForTheSevenDayWindowEndingAtAsOf(t *testing.T) {
	asOf := time.Date(2026, 11, 20, 13, 14, 15, 678_901_234, time.FixedZone("UTC+5", 5*3600))
	history := &pagedHistory{samples: historySamples(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), 2, 3, 4, 5, 6)}
	got, err := BuildDeviceFeatures(context.Background(), history, "device:a", asOf)
	if err != nil {
		t.Fatal(err)
	}
	// 2026-11-20T13:14:15+05:00 is 08:14:15 UTC; the window starts six UTC days earlier.
	wantFrom := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 11, 20, 8, 14, 15, 678_901_000, time.UTC).Add(time.Microsecond)
	if !history.from.Equal(wantFrom) || !history.to.Equal(wantTo) {
		t.Fatalf("asked for [%s, %s), want [%s, %s)", history.from, history.to, wantFrom, wantTo)
	}
	if history.pages != 3 || got.SamplesRead != 5 || got.LastSequence != 6 || got.DeploymentID != "deployment:features" {
		t.Fatalf("pages %d, read %d, last sequence %d, deployment %q", history.pages, got.SamplesRead, got.LastSequence, got.DeploymentID)
	}
	if got.Vector.FeatureVersion != contracts.FeatureVersionHDDSMART7DV1 || got.Vector.WindowStart != "2026-11-14" || got.Vector.WindowEnd != "2026-11-20" {
		t.Fatalf("window provenance %+v", got.Vector)
	}
}

func TestBuildDeviceFeaturesNeverFillsAMissingCounter(t *testing.T) {
	for name, samples := range map[string][]contracts.HistorySampleV1{
		"no persisted evidence": nil,
		"a sample on every day": historySamples(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), 2, 3, 4, 5, 6, 7, 8),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := BuildDeviceFeatures(context.Background(), &pagedHistory{samples: samples}, "device:a", time.Date(2026, 11, 20, 23, 59, 59, 0, time.UTC))
			if err != nil {
				t.Fatal(err)
			}
			if got.Vector.Status != contracts.FeatureStatusIncomplete {
				t.Fatalf("status %q", got.Vector.Status)
			}
			for _, f := range got.Vector.Features {
				if f.Value != nil || f.MissingReason != contracts.FeatureMissingNoObservation {
					t.Fatalf("%s = %v (%s), want a missing value", f.Name, f.Value, f.MissingReason)
				}
			}
			if _, err := health.ModelInput(got.Vector); !errors.Is(err, health.ErrIncompleteFeatures) {
				t.Fatalf("a model read an incomplete vector: %v", err)
			}
		})
	}
}

func TestBuildDeviceFeaturesFailsWithoutAPartialVector(t *testing.T) {
	samples := historySamples(time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC), 2, 3, 4, 5)
	for name, history := range map[string]*pagedHistory{
		"second page unavailable": {samples: samples, failOnPage: 2},
		"corrupt next cursor":     {samples: samples, badNextAfter: true},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := BuildDeviceFeatures(context.Background(), history, "device:a", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
			if err == nil || !reflect.DeepEqual(got, DeviceFeatures{}) {
				t.Fatalf("got %+v, %v; want an error and no vector", got, err)
			}
		})
	}
}

// The controller reads persisted rows, the endpoint reads live payloads. Over the
// same payloads they must give the same vector, and the persisted window must not
// hold a sample from after as_of, from before the window or from another device.
func TestBuildDeviceFeaturesMatchesTheEndpointOverPersistedEvidence(t *testing.T) {
	b := newEnrollmentTestBed(t)
	for _, id := range []string{"device:a", "device:b"} {
		token := b.issue(t, id)
		keys := newEnrollmentKeys(t)
		b.submit(t, token, admissionForChallenge(t, b.clock, b.challenge(t, token, keys), keys), http.StatusCreated)
	}
	asOf := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cpu := 3.0
	payloadFor := func(device string, collected time.Time) contracts.TelemetryV2 {
		return contracts.TelemetryV2{SchemaVersion: contracts.TelemetryV2Version, DeviceID: device, CollectedAt: collected, Source: "endpoint",
			LogReferences: []contracts.LogReferenceV2{},
			Metrics: contracts.MetricsV2{CPUUtilization: &contracts.MetricV2{Value: &cpu, Unit: "percent"},
				GPUUtilization: &contracts.MetricV2{Unit: "percent", MissingReason: "sensor_unavailable"}}}
	}
	insert := func(device string, seq int, collected time.Time) {
		t.Helper()
		payload, err := json.Marshal(payloadFor(device, collected))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.db.Exec(`INSERT INTO device_evidence (deployment_id, device_id, sequence, envelope, payload_bytes, request_sha256, collected_at, received_at)
			VALUES ($1,$2,$3,'{}',$4,decode($5,'hex'),$6,$7)`, b.repo.deploymentID, device, seq, payload, strings.Repeat("ab", 32), collected, collected.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	inWindow := []time.Time{
		time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC), // first instant of the window
		time.Date(2026, 11, 16, 9, 30, 0, 0, time.UTC),
		time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC), // exactly as_of
	}
	// Sequence order disagrees with collection order: 4 was collected before 2 and 3.
	insert("device:a", 2, inWindow[1])
	insert("device:a", 3, inWindow[2])
	insert("device:a", 4, inWindow[0])
	insert("device:a", 5, asOf.Add(time.Microsecond))                       // after as_of
	insert("device:a", 6, asOf.Add(time.Hour))                              // future day part
	insert("device:a", 7, time.Date(2026, 11, 13, 23, 59, 59, 0, time.UTC)) // before the window
	insert("device:b", 2, inWindow[1])                                      // another device

	got, err := BuildDeviceFeatures(context.Background(), b.repo, "device:a", asOf)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeploymentID != b.repo.deploymentID || got.DeviceID != "device:a" || got.SamplesRead != 3 || got.LastSequence != 4 {
		t.Fatalf("provenance %+v", got)
	}

	var endpoint []health.SMARTReading
	for _, collected := range inWindow {
		endpoint = append(endpoint, health.ReadingFromTelemetry(payloadFor("device:a", collected)))
	}
	want, err := health.Preprocess(asOf, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Vector, want) {
		t.Fatalf("controller vector %+v\nendpoint vector   %+v", got.Vector, want)
	}
	if got.Vector.Status != contracts.FeatureStatusIncomplete || got.Vector.WindowStart != "2026-11-14" || got.Vector.WindowEnd != "2026-11-20" {
		t.Fatalf("vector %+v", got.Vector)
	}

	if _, err := BuildDeviceFeatures(context.Background(), b.repo, "device:unknown", asOf); !errors.Is(err, ErrRepositoryNotFound) {
		t.Fatalf("unknown device: %v", err)
	}
}
