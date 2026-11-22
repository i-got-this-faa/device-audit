package health

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type pipelineRow struct {
	Date        string `json:"date"`
	SMART5Raw   *int64 `json:"smart_5_raw"`
	SMART9Raw   *int64 `json:"smart_9_raw"`
	SMART197Raw *int64 `json:"smart_197_raw"`
}

type pipelineCase struct {
	Name     string                    `json:"name"`
	Anchor   string                    `json:"anchor"`
	Rows     []pipelineRow             `json:"rows"`
	Expected contracts.FeatureVectorV1 `json:"expected"`
}

func pipelineCases(t *testing.T) []pipelineCase {
	t.Helper()
	data, err := os.ReadFile("../contracts/fixtures/features/pipeline-cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		FeatureVersion string         `json:"feature_version"`
		Tolerance      float64        `json:"tolerance"`
		Cases          []pipelineCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if file.FeatureVersion != contracts.FeatureVersionHDDSMART7DV1 || file.Tolerance != contracts.FeatureTolerance || len(file.Cases) == 0 {
		t.Fatal("missing or incompatible pipeline cases")
	}
	return file.Cases
}

func at(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// closeVectors holds values to the recorded tolerance and everything else exactly.
// It compares copies, so a caller may reuse both vectors.
func closeVectors(a, b contracts.FeatureVectorV1) bool {
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

func readings(t *testing.T, rows []pipelineRow, clock string) []SMARTReading {
	t.Helper()
	var result []SMARTReading
	for _, r := range rows {
		result = append(result, SMARTReading{ObservedAt: at(t, r.Date+"T"+clock+"Z"), SMART5Raw: r.SMART5Raw, SMART9Raw: r.SMART9Raw, SMART197Raw: r.SMART197Raw})
	}
	return result
}

// The endpoint builds its window from timestamped readings, the trainer from daily
// rows. Both must give the vector the hand-written cases expect.
func TestPreprocessMatchesSharedPipelineCases(t *testing.T) {
	for _, c := range pipelineCases(t) {
		t.Run(c.Name, func(t *testing.T) {
			asOf := at(t, c.Anchor+"T23:59:59Z")
			got, err := Preprocess(asOf, readings(t, c.Rows, "12:00:00"))
			if err != nil {
				t.Fatal(err)
			}
			if err := got.Validate(); err != nil {
				t.Fatal(err)
			}
			if !closeVectors(got, c.Expected) {
				t.Fatalf("got %+v\nwant %+v", got, c.Expected)
			}
		})
	}
}

func TestPreprocessKeepsTheLatestNonNullReadingOfEachDay(t *testing.T) {
	var base pipelineCase
	for _, c := range pipelineCases(t) {
		if c.Name == "complete week" {
			base = c
		}
	}
	all := readings(t, base.Rows, "12:00:00")
	ptr := func(v int64) *int64 { return &v }
	for _, r := range base.Rows {
		all = append(all,
			// Earlier the same day with different values, and later with nulls: neither wins.
			SMARTReading{ObservedAt: at(t, r.Date+"T03:00:00Z"), SMART5Raw: ptr(777), SMART9Raw: ptr(777), SMART197Raw: ptr(777)},
			SMARTReading{ObservedAt: at(t, r.Date+"T18:00:00Z")},
		)
	}
	asOf := at(t, base.Anchor+"T23:59:59Z")
	got, err := Preprocess(asOf, all)
	if err != nil {
		t.Fatal(err)
	}
	if !closeVectors(got, base.Expected) {
		t.Fatalf("intra-day noise changed the vector: %+v", got)
	}
	// Input order does not matter.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	reversed, err := Preprocess(asOf, all)
	if err != nil || !closeVectors(reversed, base.Expected) {
		t.Fatalf("reversed input changed the vector: %v", err)
	}
}

func TestPreprocessNeverReadsAfterAsOf(t *testing.T) {
	ptr := func(v int64) *int64 { return &v }
	for _, c := range pipelineCases(t) {
		if c.Name != "complete week" {
			continue
		}
		all := readings(t, c.Rows, "12:00:00")
		// 0.4 s after asOf lies in the same whole second but is still the future.
		all = append(all, SMARTReading{ObservedAt: at(t, c.Anchor+"T23:59:59.4Z"), SMART5Raw: ptr(9999), SMART9Raw: ptr(9999), SMART197Raw: ptr(9999)})
		got, err := Preprocess(at(t, c.Anchor+"T23:59:59.1Z"), all)
		if err != nil || !closeVectors(got, c.Expected) {
			t.Fatalf("a reading after asOf changed the vector: %v", err)
		}
	}
}

func TestPreprocessMergesCountersObservedInTheSameSecond(t *testing.T) {
	ptr := func(v int64) *int64 { return &v }
	asOf := at(t, "2013-11-07T23:59:59Z")
	var all []SMARTReading
	for day := 1; day <= 7; day++ {
		moment := time.Date(2013, 11, day, 6, 0, 0, 0, time.UTC)
		// SMART 5 and 9 come from separate readings that share one whole second.
		all = append(all,
			SMARTReading{ObservedAt: moment.Add(100 * time.Millisecond), SMART5Raw: ptr(int64(day))},
			SMARTReading{ObservedAt: moment.Add(600 * time.Millisecond), SMART9Raw: ptr(int64(100 + day))},
		)
	}
	got, err := Preprocess(asOf, all)
	if err != nil {
		t.Fatal(err)
	}
	if got.Features[0].Value == nil || got.Features[2].Value == nil || got.Features[4].Value != nil {
		t.Fatalf("counters from one second were not both read: %+v", got.Features)
	}
	if math.Abs(*got.Features[1].Value-math.Log1p(6)) > 1e-12 {
		t.Fatalf("SMART 5 delta %v", *got.Features[1].Value)
	}
}

// A 15 s sampler yields 40,320 readings in seven days; the contract caps a window
// at 10,080 samples, so the endpoint must reduce before it builds one.
func TestPreprocessAcceptsMoreReadingsThanTheWindowContractCaps(t *testing.T) {
	asOf := at(t, "2013-11-07T23:59:59Z")
	var all []SMARTReading
	for moment := asOf.AddDate(0, 0, -8); !moment.After(asOf); moment = moment.Add(15 * time.Second) {
		all = append(all, SMARTReading{ObservedAt: moment})
	}
	if len(all) <= contracts.MaxFeatureSamples {
		t.Fatalf("test needs more than %d readings, has %d", contracts.MaxFeatureSamples, len(all))
	}
	got, err := Preprocess(asOf, all)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != contracts.FeatureStatusIncomplete || got.Features[0].MissingReason != contracts.FeatureMissingNoObservation {
		t.Fatalf("all-null readings must be no_observation: %+v", got.Features[0])
	}
}

func TestPreprocessRejectsAnAsOfOutsideTheContractRange(t *testing.T) {
	if _, err := Preprocess(time.Time{}, nil); err == nil {
		t.Fatal("accepted the zero time")
	}
}

// Real endpoint telemetry carries no SMART counter, so the declared outcome is an
// incomplete vector that a model cannot read.
func TestTelemetryYieldsAnIncompleteVectorThatNeverReachesAModel(t *testing.T) {
	data, err := os.ReadFile("../contracts/fixtures/telemetry/v2-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []struct {
			Valid     bool            `json:"valid"`
			Telemetry json.RawMessage `json:"telemetry"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	var all []SMARTReading
	var latest time.Time
	for _, v := range file.Vectors {
		if !v.Valid {
			continue
		}
		var telemetry contracts.TelemetryV2
		if err := json.Unmarshal(v.Telemetry, &telemetry); err != nil {
			t.Fatal(err)
		}
		all = append(all, ReadingFromTelemetry(telemetry))
		if telemetry.CollectedAt.After(latest) {
			latest = telemetry.CollectedAt
		}
	}
	if len(all) == 0 {
		t.Fatal("no valid telemetry")
	}
	got, err := Preprocess(latest, all)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != contracts.FeatureStatusIncomplete {
		t.Fatalf("telemetry produced a %s vector", got.Status)
	}
	for _, f := range got.Features {
		if f.Value != nil || f.MissingReason != contracts.FeatureMissingNoObservation {
			t.Fatalf("%s is not no_observation: %+v", f.Name, f)
		}
	}
	if _, err := ModelInput(got); !errors.Is(err, ErrIncompleteFeatures) {
		t.Fatalf("incomplete vector reached a model: %v", err)
	}
}

func TestModelInputReturnsTheFrozenOrderOnlyForACompleteVector(t *testing.T) {
	for _, c := range pipelineCases(t) {
		values, err := ModelInput(c.Expected)
		if c.Expected.Status == contracts.FeatureStatusComplete {
			if err != nil || len(values) != len(c.Expected.Features) || values[0] != *c.Expected.Features[0].Value {
				t.Fatalf("%s: %v %v", c.Name, values, err)
			}
			continue
		}
		if !errors.Is(err, ErrIncompleteFeatures) || values != nil {
			t.Fatalf("%s: incomplete vector gave %v, %v", c.Name, values, err)
		}
	}
	reordered := pipelineCases(t)[0].Expected
	reordered.Features = append([]contracts.FeatureValueV1{reordered.Features[1], reordered.Features[0]}, reordered.Features[2:]...)
	if _, err := ModelInput(reordered); err == nil || errors.Is(err, ErrIncompleteFeatures) {
		t.Fatalf("a reordered vector was read: %v", err)
	}
}
