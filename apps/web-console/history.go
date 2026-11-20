package webconsole

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// DefaultHistoryWindow is the window shown when the URL names none.
const DefaultHistoryWindow = 24 * time.Hour

type HistoryPreset struct {
	Label, URL string
}

type HistoryLogRef struct {
	ID, SHA256, WindowStart, WindowEnd string
	ByteSize                           int64
}

type HistorySample struct {
	Sequence               uint64
	Source                 string
	FixtureSource          bool
	ObservedAt, ReceivedAt string
	RequestSHA256          string
	Sensors                []Sensor
	Denied                 []string
	LogRefs                []HistoryLogRef
}

// HistoryView is the per-device history presentation. State is one of ready,
// empty, not-configured, not-found, invalid or error.
type HistoryView struct {
	State, DeviceID, DeviceURL string
	From, To                   string
	Presets                    []HistoryPreset
	Samples                    []HistorySample
	NextURL                    string
	Paged                      bool
	MaxWindow                  string
}

// IsDeviceHistoryPath extends the login return allowlist to history paths.
func IsDeviceHistoryPath(path string) bool {
	rest, ok := strings.CutPrefix(path, "/console/devices/")
	id, tail, found := strings.Cut(rest, "/")
	return ok && found && tail == "history" && deviceIDPattern.MatchString(id)
}

// DeviceHistory renders one bounded page of a device's durable samples. With
// no from and to it shows the last DefaultHistoryWindow ending at now. A read
// failure returns the error for logging and a view with no measurements.
func DeviceHistory(ctx context.Context, reader DeviceReader, query url.Values, deviceID string, now time.Time) (*HistoryView, int, error) {
	now = now.UTC().Truncate(time.Second)
	view := &HistoryView{DeviceID: deviceID, DeviceURL: "/console/devices/" + url.PathEscape(deviceID),
		MaxWindow: contracts.TelemetryHistoryWindowMaxV1.String()}
	for key, values := range query {
		if (key != "from" && key != "to" && key != "after") || len(values) != 1 || values[0] == "" {
			view.State = "invalid"
			return view, http.StatusBadRequest, nil
		}
	}
	from, to := now.Add(-DefaultHistoryWindow), now
	if query.Has("from") != query.Has("to") || (query.Has("after") && !query.Has("from")) {
		view.State = "invalid"
		return view, http.StatusBadRequest, nil
	}
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
	}{{"Last hour", time.Hour}, {"Last 24 hours", 24 * time.Hour}, {"Last 7 days", 7 * 24 * time.Hour}} {
		view.Presets = append(view.Presets, HistoryPreset{preset.label, historyURL(view.DeviceURL, now.Add(-preset.span), now, "")})
	}
	if reader == nil {
		view.State = "not-configured"
		return view, http.StatusOK, nil
	}
	after := query.Get("after")
	page, err := reader.TelemetryHistory(ctx, deviceID, from, to, after, contracts.TelemetryHistoryPageDefaultV1)
	if err != nil {
		switch {
		case errors.Is(err, ErrDeviceNotFound):
			view.State = "not-found"
			return view, http.StatusNotFound, nil
		case errors.Is(err, ErrDeviceQueryInvalid):
			view.State = "invalid"
			return view, http.StatusBadRequest, nil
		}
		view.State = "error"
		return view, http.StatusServiceUnavailable, err
	}
	for _, sample := range page.Samples {
		view.Samples = append(view.Samples, historySample(sample))
	}
	view.State, view.Paged = "ready", after != ""
	if len(view.Samples) == 0 {
		view.State = "empty"
	}
	if page.NextAfter != nil {
		view.NextURL = historyURL(view.DeviceURL, from, to, *page.NextAfter)
	}
	return view, http.StatusOK, nil
}

func historyURL(deviceURL string, from, to time.Time, after string) string {
	values := url.Values{"from": {from.UTC().Format(time.RFC3339Nano)}, "to": {to.UTC().Format(time.RFC3339Nano)}}
	if after != "" {
		values.Set("after", after)
	}
	return deviceURL + "/history?" + values.Encode()
}

func historySample(sample contracts.HistorySampleV1) HistorySample {
	row := HistorySample{Sequence: sample.Sequence, Source: sample.Source, FixtureSource: sample.Source != "endpoint",
		ObservedAt: utc(sample.CollectedAt), ReceivedAt: utc(sample.ReceivedAt), RequestSHA256: sample.RequestSHA256}
	measured := "Reported by the endpoint."
	if row.FixtureSource {
		measured = "Reported by a fixture source, not endpoint collection."
	}
	row.Sensors = sensorRows(sample.Metrics, measured)
	for _, sensor := range row.Sensors {
		if sensor.Denied {
			row.Denied = append(row.Denied, sensor.Name)
		}
	}
	for _, ref := range sample.LogReferences {
		row.LogRefs = append(row.LogRefs, HistoryLogRef{ID: ref.ReferenceID, SHA256: ref.SHA256, ByteSize: ref.ByteSize,
			WindowStart: utc(ref.WindowStart), WindowEnd: utc(ref.WindowEnd)})
	}
	return row
}
