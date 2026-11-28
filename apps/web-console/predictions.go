package webconsole

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ErrPredictionEvidenceDenied reports that a persisted prediction's evidence
// or model reference was missing, out of scope or failed its integrity check.
// The console then shows no risk value from that page.
var ErrPredictionEvidenceDenied = errors.New("prediction evidence reference denied")

// PredictionReader is the durable prediction history the console reads.
type PredictionReader interface {
	// PredictionHistory pages one device's records with from <= as_of < to.
	PredictionHistory(ctx context.Context, deviceID string, from, to time.Time, after string, limit int) (contracts.PredictionHistoryV1, error)
	// LatestPrediction returns the newest record; ErrDeviceNotFound means
	// the device has none (the history read checks the device first).
	LatestPrediction(ctx context.Context, deviceID string) (contracts.LatestPredictionV1, error)
}

// DefaultPredictionWindow is the window shown when the URL names none.
const DefaultPredictionWindow = 7 * 24 * time.Hour

type PredictionEvidence struct {
	Sequence                     uint64
	CollectedAt, ReceivedAt      string
	PayloadSHA256, RequestSHA256 string
	Source, TelemetrySchema      string
	FixtureSource                bool
	HistoryURL                   string
}

type PredictionForecast struct {
	Category, Risk, Horizon string
}

// PredictionRecord is one persisted assessment. Risk is "Unknown" whenever
// the record's probability is null; it is never rendered as zero.
type PredictionRecord struct {
	ID                                uint64
	AsOf, RecordedAt, ExpiresAt       string
	Status, StatusLabel               string
	RiskKnown                         bool
	Risk, Horizon                     string
	UnknownReason, UnknownExplanation string
	Expired, StaleEvidence            bool
	RuleReason, RulesVersion          string
	ModelStatus, ModelError           string
	Model                             *contracts.PredictionModelProvenanceV1
	Evidence                          *PredictionEvidence
	Features                          contracts.PredictionFeatureRefV1
	FeatureExplanation                string
	Fault                             contracts.PredictionFaultBaselineRefV1
	FaultExplanation                  string
	Forecasts                         []PredictionForecast
}

// PredictionCurrent is the controller-clock view of the newest record.
type PredictionCurrent struct {
	EvaluatedAt         string
	Status, StatusLabel string
	RiskKnown           bool
	Risk, Horizon       string
	UnknownReason       string
	UnknownExplanation  string
	Expired             bool
	Record              PredictionRecord
}

// PredictionView is the per-device prediction presentation. State is one of
// ready, empty, not-configured, not-found, invalid, denied or error.
type PredictionView struct {
	State, DeviceID, DeviceURL string
	From, To, MaxWindow        string
	Presets                    []HistoryPreset
	Current                    *PredictionCurrent
	Records                    []PredictionRecord
	NextURL                    string
	Paged                      bool
}

// IsDevicePredictionsPath extends the login return allowlist to prediction pages.
func IsDevicePredictionsPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/console/devices/")
	id, tail, found := strings.Cut(rest, "/")
	return ok && found && tail == "predictions" && deviceIDPattern.MatchString(id)
}

// DevicePredictions renders one bounded page of a device's persisted
// prediction history plus its current controller-clock assessment. Any denied
// or unreadable reference withholds every risk value on the page.
func DevicePredictions(ctx context.Context, reader DeviceReader, query url.Values, deviceID string, now time.Time) (*PredictionView, int, error) {
	now = now.UTC().Truncate(time.Second)
	view := &PredictionView{DeviceID: deviceID, DeviceURL: "/console/devices/" + url.PathEscape(deviceID),
		MaxWindow: contracts.PredictionHistoryWindowMaxV1.String()}
	for key, values := range query {
		if (key != "from" && key != "to" && key != "after") || len(values) != 1 || values[0] == "" {
			view.State = "invalid"
			return view, http.StatusBadRequest, nil
		}
	}
	if query.Has("from") != query.Has("to") || (query.Has("after") && !query.Has("from")) {
		view.State = "invalid"
		return view, http.StatusBadRequest, nil
	}
	from, to := now.Add(-DefaultPredictionWindow), now
	if query.Has("from") {
		var errFrom, errTo error
		from, errFrom = time.Parse(time.RFC3339Nano, query.Get("from"))
		to, errTo = time.Parse(time.RFC3339Nano, query.Get("to"))
		if errFrom != nil || errTo != nil {
			view.State = "invalid"
			return view, http.StatusBadRequest, nil
		}
		from, to = from.UTC(), to.UTC()
	}
	view.From, view.To = from.Format(time.RFC3339Nano), to.Format(time.RFC3339Nano)
	for _, preset := range []struct {
		label string
		span  time.Duration
	}{{"Last 24 hours", 24 * time.Hour}, {"Last 7 days", 7 * 24 * time.Hour}, {"Last 31 days", contracts.PredictionHistoryWindowMaxV1}} {
		view.Presets = append(view.Presets, HistoryPreset{preset.label, predictionsURL(view.DeviceURL, now.Add(-preset.span), now, "")})
	}
	predictions, ok := reader.(PredictionReader)
	if reader == nil || !ok {
		view.State = "not-configured"
		return view, http.StatusOK, nil
	}
	after := query.Get("after")
	page, err := predictions.PredictionHistory(ctx, deviceID, from, to, after, contracts.PredictionHistoryPageDefaultV1)
	if err != nil {
		return predictionFailure(view, err)
	}
	latest, err := predictions.LatestPrediction(ctx, deviceID)
	switch {
	case errors.Is(err, ErrDeviceNotFound):
		// The history read already found the device: it has no assessment.
	case err != nil:
		return predictionFailure(view, err)
	default:
		view.Current = currentPrediction(latest, view.DeviceURL)
	}
	for _, record := range page.Records {
		view.Records = append(view.Records, predictionRecord(record, now, view.DeviceURL))
	}
	view.State, view.Paged = "ready", after != ""
	if len(view.Records) == 0 {
		view.State = "empty"
	}
	if page.NextAfter != nil {
		view.NextURL = predictionsURL(view.DeviceURL, from, to, *page.NextAfter)
	}
	return view, http.StatusOK, nil
}

func predictionFailure(view *PredictionView, err error) (*PredictionView, int, error) {
	view.Current, view.Records, view.NextURL = nil, nil, ""
	switch {
	case errors.Is(err, ErrDeviceNotFound):
		view.State = "not-found"
		return view, http.StatusNotFound, nil
	case errors.Is(err, ErrDeviceQueryInvalid):
		view.State = "invalid"
		return view, http.StatusBadRequest, nil
	case errors.Is(err, ErrPredictionEvidenceDenied):
		view.State = "denied"
		return view, http.StatusBadGateway, err
	}
	view.State = "error"
	return view, http.StatusServiceUnavailable, err
}

func predictionsURL(deviceURL string, from, to time.Time, after string) string {
	values := url.Values{"from": {from.UTC().Format(time.RFC3339Nano)}, "to": {to.UTC().Format(time.RFC3339Nano)}}
	if after != "" {
		values.Set("after", after)
	}
	return deviceURL + "/predictions?" + values.Encode()
}

var statusLabels = map[string]string{"healthy": "Healthy", "degraded": "Degraded", "critical": "Critical", "unknown": "Unknown health"}

var unknownReasons = map[string]string{
	"insufficient_evidence": "Not enough evidence for an assessment. This is not a healthy result.",
	"model_unavailable":     "No approved prediction model was available. This is not a healthy result.",
	"stale_evidence":        "The evidence was too old to assess current health. This is not a healthy result.",
}

func riskText(h contracts.HealthV2) (bool, string, string) {
	if h.Probability == nil {
		return false, "Unknown", "Unknown"
	}
	horizon := "Unknown"
	if h.HorizonHours != nil {
		horizon = strconv.FormatUint(uint64(*h.HorizonHours), 10) + " hours"
	}
	return true, formatProbability(*h.Probability), horizon
}

func formatProbability(p float64) string {
	return strconv.FormatFloat(p*100, 'f', -1, 64) + "% failure probability"
}

func unknownExplanation(reason string) string {
	if text, ok := unknownReasons[reason]; ok {
		return text
	}
	if reason == "" {
		return ""
	}
	return "Health is unknown (" + reason + "). This is not a healthy result."
}

func predictionRecord(r contracts.PredictionHistoryRecordV1, now time.Time, deviceURL string) PredictionRecord {
	row := PredictionRecord{ID: r.ID, AsOf: utc(r.AsOf), RecordedAt: utc(r.RecordedAt), Status: r.Health.Status,
		StatusLabel: statusLabels[r.Health.Status], UnknownReason: r.Health.UnknownReason,
		UnknownExplanation: unknownExplanation(r.Health.UnknownReason), RuleReason: r.RuleReason, RulesVersion: r.RulesVersion,
		ModelStatus: r.ModelStatus, ModelError: r.ModelError, Model: r.ModelProvenance, Features: r.Features, Fault: r.FaultBaseline,
		StaleEvidence: r.Health.UnknownReason == "stale_evidence"}
	if row.StatusLabel == "" {
		row.StatusLabel = "Unknown health"
	}
	row.RiskKnown, row.Risk, row.Horizon = riskText(r.Health)
	if r.ExpiresAt != nil {
		row.ExpiresAt = utc(*r.ExpiresAt)
		row.Expired = !now.Before(*r.ExpiresAt)
	}
	if r.Evidence != nil {
		e := r.Evidence
		window := e.CollectedAt.UTC().Truncate(time.Second)
		row.Evidence = &PredictionEvidence{Sequence: e.Sequence, CollectedAt: utc(e.CollectedAt), ReceivedAt: utc(e.ReceivedAt),
			PayloadSHA256: e.PayloadSHA256, RequestSHA256: e.RequestSHA256, Source: e.Source, TelemetrySchema: e.TelemetrySchemaVersion,
			FixtureSource: e.Source != "endpoint", HistoryURL: historyURL(deviceURL, window, window.Add(time.Second), "")}
	}
	row.FeatureExplanation = fmt.Sprintf("Feature set %s, window %s to %s: %s, %d features from %d samples.",
		r.Features.FeatureVersion, r.Features.WindowStart, r.Features.WindowEnd, r.Features.Status, r.Features.FeatureCount, r.Features.SamplesRead)
	f := r.FaultBaseline
	sufficiency := "sufficient"
	if !f.Current.Sufficient {
		sufficiency = "insufficient"
	}
	row.FaultExplanation = fmt.Sprintf("Current %d-day fault window had %d of %d days sampled (%s): %d recurrent, %d isolated, %d baseline-only and %d insufficient-history fault types across %d reports (%d duplicates) against a %d-day baseline.",
		f.Current.Days, f.Current.SampledDays, f.Current.Days, sufficiency, f.RecurrentTypes, f.IsolatedTypes, f.BaselineOnlyTypes,
		f.InsufficientHistoryTypes, f.CurrentReports, f.DuplicateReports, f.Baseline.Days)
	if f.ObservationNote != "" {
		row.FaultExplanation += " " + f.ObservationNote
	}
	if r.Prediction != nil {
		for _, forecast := range r.Prediction.Forecasts {
			row.Forecasts = append(row.Forecasts, PredictionForecast{Category: forecast.Category,
				Risk: formatProbability(forecast.Probability), Horizon: strconv.FormatUint(uint64(forecast.HorizonHours), 10) + " hours"})
		}
	}
	return row
}

func currentPrediction(latest contracts.LatestPredictionV1, deviceURL string) *PredictionCurrent {
	now := latest.EvaluatedAt.UTC()
	current := &PredictionCurrent{EvaluatedAt: utc(now), Status: latest.CurrentHealth.Status,
		StatusLabel: statusLabels[latest.CurrentHealth.Status], UnknownReason: latest.CurrentHealth.UnknownReason,
		UnknownExplanation: unknownExplanation(latest.CurrentHealth.UnknownReason), Expired: latest.Stale,
		Record: predictionRecord(latest.Record, now, deviceURL)}
	if current.StatusLabel == "" {
		current.StatusLabel = "Unknown health"
	}
	current.RiskKnown, current.Risk, current.Horizon = riskText(latest.CurrentHealth)
	// An expired record never supplies a current risk, even if the payload
	// still carries one.
	if latest.Stale {
		current.RiskKnown, current.Risk, current.Horizon = false, "Unknown", "Unknown"
		if current.Status != "unknown" {
			current.Status, current.StatusLabel = "unknown", statusLabels["unknown"]
		}
		if current.UnknownExplanation == "" {
			current.UnknownReason, current.UnknownExplanation = "stale_evidence", unknownReasons["stale_evidence"]
		}
	}
	return current
}
