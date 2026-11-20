package webconsole

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

var (
	ErrDeviceNotFound     = errors.New("enrolled device not found")
	ErrDeviceQueryInvalid = errors.New("invalid enrolled device query")
)

// DeviceReader reads enrolled devices and their latest durable samples.
// It returns ErrDeviceNotFound for an unknown device and ErrDeviceQueryInvalid
// for a malformed device ID or cursor; any other error is a read failure.
type DeviceReader interface {
	DeviceStates(ctx context.Context, after string, limit int) (contracts.DeviceStatePageV1, error)
	DeviceState(ctx context.Context, deviceID string) (contracts.DeviceStateV1, error)
}

// Freshness classifies a device by the observation time of its latest sample.
type Freshness string

const (
	FreshnessCurrent  Freshness = "current"
	FreshnessStale    Freshness = "stale"
	FreshnessOffline  Freshness = "offline"
	FreshnessNoSample Freshness = "no-sample"
)

// Provisional console thresholds. Endpoints emit every 60 s by default and
// back off delivery retries up to 60 s, so three minutes covers one missed
// emit plus a full retry. The controller does not know each endpoint's
// configured cadence; these are display policy, not a liveness guarantee.
const (
	StaleAfter   = 3 * time.Minute
	OfflineAfter = 15 * time.Minute
)

// ClassifyFreshness uses the sample's observed (collected) time, not its
// receipt time: a drained backlog must not make an old observation current.
// Each threshold is exclusive of current: an age equal to it is already late.
func ClassifyFreshness(latest *contracts.LatestSampleV1, now time.Time) Freshness {
	if latest == nil {
		return FreshnessNoSample
	}
	switch age := now.Sub(latest.CollectedAt); {
	case age >= OfflineAfter:
		return FreshnessOffline
	case age >= StaleAfter:
		return FreshnessStale
	default:
		return FreshnessCurrent
	}
}

var freshnessLabels = map[Freshness]string{
	FreshnessCurrent: "Current", FreshnessStale: "Stale", FreshnessOffline: "Offline", FreshnessNoSample: "No sample",
}

type InventoryRow struct {
	ID, URL                     string
	Freshness                   Freshness
	FreshnessLabel, Age         string
	Source                      string
	FixtureSource               bool
	ObservedAt, ReceivedAt      string
	EnrolledAt, RevokedAt       string
	SigningKeyID, RequestSHA256 string
	Sequence, LastSequence      uint64
	HasSample                   bool
	Sensors                     []Sensor
}

// InventoryView is the enrolled-device presentation. State is one of ready,
// empty, not-configured, not-found, invalid or error.
type InventoryView struct {
	State                    string
	EvaluatedAt              string
	StaleAfter, OfflineAfter string
	Rows                     []InventoryRow
	Detail                   *InventoryRow
	IsDetail                 bool
	NextURL                  string
	Paged                    bool
}

// EnrolledDevices renders one page of the durable inventory, or one device
// when deviceID is set. A nil reader means no deployment is configured. A read
// failure returns the error for logging and a view with no measurements.
func EnrolledDevices(ctx context.Context, reader DeviceReader, query url.Values, deviceID string, now time.Time) (*InventoryView, int, error) {
	view := &InventoryView{EvaluatedAt: utc(now), IsDetail: deviceID != "",
		StaleAfter: StaleAfter.String(), OfflineAfter: OfflineAfter.String()}
	allowed := map[string]bool{"after": !view.IsDetail}
	for key, values := range query {
		if !allowed[key] || len(values) != 1 || values[0] == "" {
			view.State = "invalid"
			return view, http.StatusBadRequest, nil
		}
	}
	if reader == nil {
		view.State = "not-configured"
		return view, http.StatusOK, nil
	}
	var err error
	if view.IsDetail {
		var state contracts.DeviceStateV1
		if state, err = reader.DeviceState(ctx, deviceID); err == nil {
			row := inventoryRow(state, now)
			view.Detail, view.State = &row, "ready"
			return view, http.StatusOK, nil
		}
	} else {
		var page contracts.DeviceStatePageV1
		after := query.Get("after")
		if page, err = reader.DeviceStates(ctx, after, contracts.DeviceStatePageDefaultV1); err == nil {
			for _, state := range page.Devices {
				view.Rows = append(view.Rows, inventoryRow(state, now))
			}
			view.State, view.Paged = "ready", after != ""
			if len(view.Rows) == 0 {
				view.State = "empty"
			}
			if page.NextAfter != nil {
				view.NextURL = "/console/devices?after=" + url.QueryEscape(*page.NextAfter)
			}
			return view, http.StatusOK, nil
		}
	}
	switch {
	case errors.Is(err, ErrDeviceNotFound):
		view.State = "not-found"
		return view, http.StatusNotFound, nil
	case errors.Is(err, ErrDeviceQueryInvalid):
		view.State = "invalid"
		return view, http.StatusBadRequest, nil
	default:
		view.State = "error"
		return view, http.StatusServiceUnavailable, err
	}
}

func inventoryRow(state contracts.DeviceStateV1, now time.Time) InventoryRow {
	freshness := ClassifyFreshness(state.Latest, now)
	row := InventoryRow{ID: state.DeviceID, URL: "/console/devices/" + url.PathEscape(state.DeviceID),
		Freshness: freshness, FreshnessLabel: freshnessLabels[freshness], SigningKeyID: state.SigningKeyID,
		EnrolledAt: utc(state.EnrolledAt), LastSequence: state.LastSequence}
	if state.RevokedAt != nil {
		row.RevokedAt = utc(*state.RevokedAt)
	}
	latest := state.Latest
	if latest == nil {
		row.Sensors = sensorRows(contracts.MetricsV2{}, "")
		return row
	}
	row.HasSample, row.Sequence, row.Source = true, latest.Sequence, latest.Source
	row.FixtureSource = latest.Source != "endpoint"
	row.ObservedAt, row.ReceivedAt = utc(latest.CollectedAt), utc(latest.ReceivedAt)
	row.RequestSHA256 = latest.RequestSHA256
	if age := now.Sub(latest.CollectedAt); age < 0 {
		row.Age = "observed time is ahead of the controller clock"
	} else {
		row.Age = age.Truncate(time.Second).String() + " before evaluation"
	}
	measured := "Reported by the endpoint."
	if row.FixtureSource {
		measured = "Reported by a fixture source, not endpoint collection."
	}
	row.Sensors = sensorRows(latest.Metrics, measured)
	return row
}

// utc keeps every console time in one zone so ages can be compared by eye.
func utc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

var missingReasons = map[string]string{
	"sensor_unavailable": "Sensor unavailable on this device.",
	"not_applicable":     "Sensor does not apply to this device.",
	"permission_denied":  "Collection permission denied.",
	"collection_error":   "Collection failed; no measurement is available.",
}

// sensorRows lists every telemetry v2 metric with its unit. A missing or
// unreported metric stays Unknown with its reason; it is never shown as zero.
func sensorRows(metrics contracts.MetricsV2, measured string) []Sensor {
	var sensors []Sensor
	for _, item := range []struct {
		name, unit string
		metric     *contracts.MetricV2
	}{
		{"CPU utilization", "percent", metrics.CPUUtilization}, {"GPU utilization", "percent", metrics.GPUUtilization},
		{"Memory utilization", "percent", metrics.MemoryPercent}, {"Disk space used", "percent", metrics.DiskUsedPercent},
		{"Battery charge", "percent", metrics.BatteryPercent}, {"Temperature", "celsius", metrics.TemperatureC},
		{"Network latency", "milliseconds", metrics.NetworkLatencyMS},
	} {
		sensor := Sensor{Name: item.name, Value: "Unknown", Unit: item.unit, Explanation: "Not reported in this sample."}
		switch {
		case item.metric == nil:
		case item.metric.Value != nil:
			sensor.Value, sensor.Unit = strconv.FormatFloat(*item.metric.Value, 'f', -1, 64), item.metric.Unit
			sensor.Explanation = measured
		default:
			sensor.Unit = item.metric.Unit
			sensor.Explanation = missingReasons[item.metric.MissingReason]
			if sensor.Explanation == "" {
				sensor.Explanation = "Missing: " + item.metric.MissingReason + "."
			}
		}
		sensors = append(sensors, sensor)
	}
	return sensors
}
