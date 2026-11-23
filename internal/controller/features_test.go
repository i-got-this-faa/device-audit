package controller

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// fakeEvidence serves references like PostgresRepository: [from, to), ordered by
// (collected_at, sequence). It records the window it was asked for.
type fakeEvidence struct {
	refs     []evidenceRef
	from, to time.Time
	err      error
}

func (f *fakeEvidence) FeatureEvidence(_ context.Context, _ string, from, to time.Time) (string, []evidenceRef, error) {
	f.from, f.to = from, to
	if f.err != nil {
		return "", nil, f.err
	}
	var in []evidenceRef
	for _, r := range f.refs {
		if !r.CollectedAt.Before(from) && r.CollectedAt.Before(to) {
			in = append(in, r)
		}
	}
	slices.SortFunc(in, func(a, b evidenceRef) int {
		if c := a.CollectedAt.Compare(b.CollectedAt); c != 0 {
			return c
		}
		return cmp.Compare(a.Sequence, b.Sequence)
	})
	return "deployment:features", in, nil
}

func evidenceRefs(base time.Time, sequences ...uint64) []evidenceRef {
	var out []evidenceRef
	for i, seq := range sequences {
		out = append(out, evidenceRef{Sequence: seq, CollectedAt: base.Add(time.Duration(i) * time.Hour)})
	}
	return out
}

func TestBuildDeviceFeaturesAsksOnlyForTheSevenDayWindowEndingAtAsOf(t *testing.T) {
	asOf := time.Date(2026, 11, 20, 13, 14, 15, 678_901_234, time.FixedZone("UTC+5", 5*3600))
	evidence := &fakeEvidence{refs: evidenceRefs(time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC), 2, 3, 4, 5, 6)}
	got, err := BuildDeviceFeatures(context.Background(), evidence, "device:a", asOf)
	if err != nil {
		t.Fatal(err)
	}
	// 2026-11-20T13:14:15+05:00 is 08:14:15 UTC; the window starts six UTC days earlier.
	wantFrom := time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC)
	wantTo := time.Date(2026, 11, 20, 8, 14, 15, 678_901_000, time.UTC).Add(time.Microsecond)
	if !evidence.from.Equal(wantFrom) || !evidence.to.Equal(wantTo) {
		t.Fatalf("asked for [%s, %s), want [%s, %s)", evidence.from, evidence.to, wantFrom, wantTo)
	}
	if got.SamplesRead != 5 || got.LastSequence != 6 || got.DeploymentID != "deployment:features" {
		t.Fatalf("read %d, last sequence %d, deployment %q", got.SamplesRead, got.LastSequence, got.DeploymentID)
	}
	if got.Vector.FeatureVersion != contracts.FeatureVersionHDDSMART7DV1 || got.Vector.WindowStart != "2026-11-14" || got.Vector.WindowEnd != "2026-11-20" {
		t.Fatalf("window provenance %+v", got.Vector)
	}
}

func TestBuildDeviceFeaturesNeverFillsAMissingCounter(t *testing.T) {
	for name, refs := range map[string][]evidenceRef{
		"no persisted evidence": nil,
		"a sample on every day": evidenceRefs(time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC), 2, 3, 4, 5, 6, 7, 8),
	} {
		t.Run(name, func(t *testing.T) {
			got, err := BuildDeviceFeatures(context.Background(), &fakeEvidence{refs: refs}, "device:a", time.Date(2026, 11, 20, 23, 59, 59, 0, time.UTC))
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
	got, err := BuildDeviceFeatures(context.Background(), &fakeEvidence{err: ErrRepositoryUnavailable}, "device:a", time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrRepositoryUnavailable) || !reflect.DeepEqual(got, DeviceFeatures{}) {
		t.Fatalf("got %+v, %v; want the repository error and no vector", got, err)
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

// The shared CT03 cases run through the controller's window with known
// counters. Sequences run against collection order, so arrival order is wrong
// for every row and the vector must not depend on it.
func TestBuildDeviceFeaturesMatchesTheSharedPipelineCases(t *testing.T) {
	data, err := os.ReadFile("../../packages/contracts/fixtures/features/pipeline-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		FeatureVersion string `json:"feature_version"`
		Cases          []struct {
			Name   string `json:"name"`
			Anchor string `json:"anchor"`
			Rows   []struct {
				Date        string `json:"date"`
				SMART5Raw   *int64 `json:"smart_5_raw"`
				SMART9Raw   *int64 `json:"smart_9_raw"`
				SMART197Raw *int64 `json:"smart_197_raw"`
			} `json:"rows"`
			Expected contracts.FeatureVectorV1 `json:"expected"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.FeatureVersion != contracts.FeatureVersionHDDSMART7DV1 || len(file.Cases) == 0 {
		t.Fatal("missing or incompatible pipeline cases")
	}
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			asOf, err := time.Parse(time.RFC3339, c.Anchor+"T23:59:59Z")
			if err != nil {
				t.Fatal(err)
			}
			counters := map[uint64]health.SMARTReading{}
			var refs []evidenceRef
			for i, r := range c.Rows {
				collected, err := time.Parse(time.RFC3339, r.Date+"T12:00:00Z")
				if err != nil {
					t.Fatal(err)
				}
				seq := uint64(1000 - i)
				refs = append(refs, evidenceRef{Sequence: seq, CollectedAt: collected})
				counters[seq] = health.SMARTReading{ObservedAt: collected, SMART5Raw: r.SMART5Raw, SMART9Raw: r.SMART9Raw, SMART197Raw: r.SMART197Raw}
			}
			got, err := buildDeviceFeatures(context.Background(), &fakeEvidence{refs: refs}, "device:a", asOf,
				func(r evidenceRef) health.SMARTReading { return counters[r.Sequence] })
			if err != nil {
				t.Fatal(err)
			}
			if err := got.Vector.Validate(); err != nil {
				t.Fatal(err)
			}
			if !closeFeatureVectors(got.Vector, c.Expected) {
				t.Fatalf("got %+v\nwant %+v", got.Vector, c.Expected)
			}
		})
	}
}

// closeFeatureVectors holds values to the recorded tolerance and every other field exactly.
func closeFeatureVectors(a, b contracts.FeatureVectorV1) bool {
	if len(a.Features) != len(b.Features) {
		return false
	}
	a.Features, b.Features = slices.Clone(a.Features), slices.Clone(b.Features)
	for i := range a.Features {
		x, y := a.Features[i], b.Features[i]
		if (x.Value == nil) != (y.Value == nil) {
			return false
		}
		if x.Value != nil && math.Abs(*x.Value-*y.Value) > contracts.FeatureTolerance+contracts.FeatureTolerance*math.Abs(*y.Value) {
			return false
		}
		a.Features[i].Value, b.Features[i].Value = nil, nil
	}
	return reflect.DeepEqual(a, b)
}
