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

type fakePredictions struct {
	fakeReader
	history       contracts.PredictionHistoryV1
	historyErr    error
	latest        contracts.LatestPredictionV1
	latestErr     error
	from, to      time.Time
	after         string
	latestQueried bool
}

func (f *fakePredictions) PredictionHistory(_ context.Context, _ string, from, to time.Time, after string, _ int) (contracts.PredictionHistoryV1, error) {
	f.from, f.to, f.after = from, to, after
	return f.history, f.historyErr
}

func (f *fakePredictions) LatestPrediction(context.Context, string) (contracts.LatestPredictionV1, error) {
	f.latestQueried = true
	return f.latest, f.latestErr
}

func renderPredictions(t *testing.T, view *PredictionView, status int) string {
	t.Helper()
	w := httptest.NewRecorder()
	if err := Render(w, status, Page{Title: "Device predictions", Section: "devices", Subject: "viewer", Predictions: view}); err != nil {
		t.Fatal(err)
	}
	return w.Body.String()
}

func knownRecord(id uint64, asOf time.Time, probability float64) contracts.PredictionHistoryRecordV1 {
	horizon := uint32(72)
	expires := asOf.Add(time.Hour)
	sample := asOf.Add(-time.Minute)
	health := contracts.HealthV2{Status: "degraded", Probability: &probability, ProbabilityUnit: "probability", HorizonHours: &horizon}
	return contracts.PredictionHistoryRecordV1{ID: id, AsOf: asOf, RecordedAt: asOf.Add(time.Second), ExpiresAt: &expires,
		RulesVersion: "rules.v1", RuleReason: "smart_reallocated_sectors", ModelStatus: "ready",
		ModelProvenance: &contracts.PredictionModelProvenanceV1{Version: "ml06.v2", SHA256: strings.Repeat("aa", 32),
			PolicyVersion: "ml05.v1", PolicySHA256: strings.Repeat("bb", 32), EvaluationSHA256: strings.Repeat("cc", 32)},
		Evidence: &contracts.PredictionEvidenceRefV1{Sequence: 9, CollectedAt: sample, ReceivedAt: sample.Add(time.Second),
			PayloadSHA256: strings.Repeat("dd", 32), RequestSHA256: strings.Repeat("ee", 32), Source: "endpoint", TelemetrySchemaVersion: contracts.TelemetryV2Version},
		Features: contracts.PredictionFeatureRefV1{FeatureVersion: "ct03.v1", WindowStart: utc(sample.Add(-time.Hour)), WindowEnd: utc(sample),
			Status: contracts.FeatureStatusComplete, FeatureCount: 12, SamplesRead: 60, LastSequence: 9},
		FaultBaseline: contracts.PredictionFaultBaselineRefV1{Current: contracts.PredictionFaultWindowRefV1{Days: 7, SampledDays: 7, Sufficient: true},
			Baseline: contracts.PredictionFaultWindowRefV1{Days: 21, SampledDays: 20, Sufficient: true}, RecurrentTypes: 2, CurrentReports: 5},
		Health: health,
		Prediction: &contracts.PredictionV2{DeviceID: "device:a", GeneratedAt: asOf, ExpiresAt: expires, Health: health,
			Forecasts: []contracts.FaultForecastV2{{Category: "storage", Probability: probability, ProbabilityUnit: "probability", HorizonHours: horizon}}}}
}

func unknownRecord(id uint64, asOf time.Time, reason string) contracts.PredictionHistoryRecordV1 {
	return contracts.PredictionHistoryRecordV1{ID: id, AsOf: asOf, RecordedAt: asOf, RulesVersion: "rules.v1", RuleReason: "no_telemetry_evidence",
		ModelStatus: "unavailable", Features: contracts.PredictionFeatureRefV1{FeatureVersion: "ct03.v1", Status: "missing"},
		Health: contracts.HealthV2{Status: "unknown", ProbabilityUnit: "probability", UnknownReason: reason}}
}

func TestDevicePredictionsShowModelHorizonExplanationEvidence(t *testing.T) {
	asOf := evaluatedAt.Add(-30 * time.Minute)
	record := knownRecord(4, asOf, 0.125)
	next := "cursor"
	reader := &fakePredictions{history: contracts.PredictionHistoryV1{Records: []contracts.PredictionHistoryRecordV1{record}, NextAfter: &next},
		latest: contracts.LatestPredictionV1{EvaluatedAt: evaluatedAt, CurrentHealth: record.Health, Record: record}}
	view, status, err := DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
	if err != nil || status != http.StatusOK || view.State != "ready" {
		t.Fatalf("predictions: %d %v %+v", status, err, view)
	}
	if !reader.to.Equal(evaluatedAt) || reader.to.Sub(reader.from) != DefaultPredictionWindow || !reader.latestQueried {
		t.Fatalf("default window: %s..%s", reader.from, reader.to)
	}
	body := renderPredictions(t, view, status)
	for _, want := range []string{"12.5% failure probability", "72 hours", "ml06.v2", strings.Repeat("aa", 32), strings.Repeat("cc", 32),
		"smart_reallocated_sectors", "ct03.v1", "12 features from 60 samples", "2 recurrent", "storage: 12.5% failure probability within 72 hours",
		"Sequence 9", strings.Repeat("dd", 32), "/console/devices/device:a/history?from=", "Degraded", "Next page"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q in:\n%s", want, body)
		}
	}
	if strings.Contains(body, "Expired reference") || strings.Contains(body, "Stale prediction") {
		t.Fatal("current record marked stale")
	}
}

func TestDevicePredictionsNeverDrawNullRiskAsZero(t *testing.T) {
	asOf := evaluatedAt.Add(-time.Hour)
	unknown := unknownRecord(1, asOf, "insufficient_evidence")
	reader := &fakePredictions{history: contracts.PredictionHistoryV1{Records: []contracts.PredictionHistoryRecordV1{unknown}},
		latest: contracts.LatestPredictionV1{EvaluatedAt: evaluatedAt, CurrentHealth: unknown.Health, Record: unknown}}
	view, status, _ := DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
	body := renderPredictions(t, view, status)
	if strings.Contains(body, "0% failure") || strings.Contains(body, ">0<") || !strings.Contains(body, `data-known="false">Unknown`) ||
		!strings.Contains(body, "Not enough evidence") || !strings.Contains(body, "not a healthy result") || !strings.Contains(body, "No telemetry evidence existed") {
		t.Fatalf("unknown risk rendered unsafely:\n%s", body)
	}
	// A genuine zero probability stays a measurement, distinct from unknown.
	zero := knownRecord(2, asOf, 0)
	reader = &fakePredictions{history: contracts.PredictionHistoryV1{Records: []contracts.PredictionHistoryRecordV1{zero}},
		latest: contracts.LatestPredictionV1{EvaluatedAt: evaluatedAt.Add(-50 * time.Minute), CurrentHealth: zero.Health, Record: zero}}
	view, status, _ = DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt.Add(-50*time.Minute))
	if body = renderPredictions(t, view, status); !strings.Contains(body, `data-known="true">0% failure probability`) {
		t.Fatalf("measured zero lost:\n%s", body)
	}
}

func TestDevicePredictionsMarkStaleAndExpiredWithoutCurrentRisk(t *testing.T) {
	asOf := evaluatedAt.Add(-3 * time.Hour)
	record := knownRecord(3, asOf, 0.4)
	stale := unknownRecord(5, asOf.Add(time.Hour), "stale_evidence")
	reader := &fakePredictions{history: contracts.PredictionHistoryV1{Records: []contracts.PredictionHistoryRecordV1{record, stale}},
		latest: contracts.LatestPredictionV1{EvaluatedAt: evaluatedAt, Stale: true, Record: record,
			CurrentHealth: contracts.HealthV2{Status: "unknown", ProbabilityUnit: "probability", UnknownReason: "stale_evidence"}}}
	view, status, _ := DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
	if !view.Current.Expired || view.Current.RiskKnown || view.Current.Status != "unknown" || !view.Records[0].Expired || !view.Records[1].StaleEvidence {
		t.Fatalf("staleness: %+v %+v", view.Current, view.Records)
	}
	body := renderPredictions(t, view, status)
	for _, want := range []string{"Stale prediction", "Current health is unknown", "Expired reference", "Stale evidence", "too old"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	// Even a stale latest that still carries a risk must not show it as current.
	reader.latest.CurrentHealth = record.Health
	view, _, _ = DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
	if view.Current.RiskKnown || view.Current.Risk != "Unknown" || view.Current.Status != "unknown" {
		t.Fatalf("stale latest kept current risk: %+v", view.Current)
	}
}

func TestDevicePredictionsFailClosed(t *testing.T) {
	asOf := evaluatedAt.Add(-time.Hour)
	record := knownRecord(3, asOf, 0.4)
	for _, test := range []struct {
		name               string
		historyErr, latest error
		status             int
		state              string
		logged             bool
	}{
		{"unknown device", ErrDeviceNotFound, nil, 404, "not-found", false},
		{"bad cursor", ErrDeviceQueryInvalid, nil, 400, "invalid", false},
		{"denied history evidence", ErrPredictionEvidenceDenied, nil, 502, "denied", true},
		{"denied latest evidence", nil, ErrPredictionEvidenceDenied, 502, "denied", true},
		{"store outage", errors.New("down"), nil, 503, "error", true},
		{"latest outage", nil, errors.New("down"), 503, "error", true},
	} {
		reader := &fakePredictions{historyErr: test.historyErr, latestErr: test.latest,
			history: contracts.PredictionHistoryV1{Records: []contracts.PredictionHistoryRecordV1{record}},
			latest:  contracts.LatestPredictionV1{EvaluatedAt: evaluatedAt, CurrentHealth: record.Health, Record: record}}
		view, status, err := DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
		if status != test.status || view.State != test.state || (err != nil) != test.logged || view.Current != nil || view.Records != nil {
			t.Fatalf("%s: %d %s %v", test.name, status, view.State, err)
		}
		body := renderPredictions(t, view, status)
		if strings.Contains(body, "failure probability") || strings.Contains(body, "ml06.v2") {
			t.Fatalf("%s leaked risk:\n%s", test.name, body)
		}
		if test.state == "denied" && !strings.Contains(body, "Evidence denied") {
			t.Fatalf("%s: denied state not explained", test.name)
		}
	}
}

func TestDevicePredictionsWithoutAssessmentOrConfiguration(t *testing.T) {
	reader := &fakePredictions{latestErr: ErrDeviceNotFound}
	view, status, err := DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
	if err != nil || status != 200 || view.State != "empty" || view.Current != nil {
		t.Fatalf("no assessment: %d %v %+v", status, err, view)
	}
	if body := renderPredictions(t, view, status); !strings.Contains(body, "No assessment has been recorded") || !strings.Contains(body, "Unknown health") {
		t.Fatalf("no assessment body:\n%s", body)
	}
	for _, reader := range []DeviceReader{nil, &fakeReader{}} {
		view, status, err = DevicePredictions(context.Background(), reader, nil, "device:a", evaluatedAt)
		if err != nil || status != 200 || view.State != "not-configured" {
			t.Fatalf("not configured: %d %v %s", status, err, view.State)
		}
	}
}

func TestDevicePredictionsQueryValidationAndPaging(t *testing.T) {
	from, to := evaluatedAt.Add(-2*time.Hour), evaluatedAt
	for _, query := range []url.Values{{"from": {from.Format(time.RFC3339)}}, {"after": {"x"}}, {"x": {"1"}},
		{"from": {"bad"}, "to": {to.Format(time.RFC3339)}}, {"from": {"a", "b"}, "to": {"c"}}} {
		view, status, _ := DevicePredictions(context.Background(), &fakePredictions{}, query, "device:a", evaluatedAt)
		if status != 400 || view.State != "invalid" {
			t.Fatalf("query %v: %d", query, status)
		}
	}
	reader := &fakePredictions{latestErr: ErrDeviceNotFound}
	query := url.Values{"from": {from.Format(time.RFC3339)}, "to": {to.Format(time.RFC3339)}, "after": {"cur"}}
	view, _, _ := DevicePredictions(context.Background(), reader, query, "device:a", evaluatedAt)
	if !reader.from.Equal(from) || !reader.to.Equal(to) || reader.after != "cur" || !view.Paged {
		t.Fatalf("paging: %s %s %q", reader.from, reader.to, reader.after)
	}
	if !IsDevicePredictionsPath("/console/devices/device:a/predictions") || IsDevicePredictionsPath("/console/devices/device:a/predictions/x") ||
		IsDevicePredictionsPath("/console/devices/bad id/predictions") {
		t.Fatal("predictions path allowlist")
	}
}
