package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// telemetryHistory is the persisted-evidence read a feature window needs.
// PostgresRepository implements it.
type telemetryHistory interface {
	TelemetryHistory(ctx context.Context, deviceID string, from, to time.Time, after *historyCursor, limit int) (contracts.TelemetryHistoryV1, error)
}

// DeviceFeatures is a controller-built CT03 vector with what it was built from.
// The vector names the feature version and its window dates. SamplesRead and
// LastSequence let a caller see which persisted evidence the window held; they
// are not a wire contract, and no endpoint serves this yet.
type DeviceFeatures struct {
	DeploymentID string
	DeviceID     string
	Vector       contracts.FeatureVectorV1
	// SamplesRead counts persisted samples with collected_at inside the window.
	SamplesRead int
	// LastSequence is the highest evidence sequence read, or 0 for none.
	LastSequence uint64
}

// BuildDeviceFeatures reads one device's persisted samples for the seven UTC
// days ending on the day of asOf and runs the same health.Preprocess the
// endpoint runs. A sample collected after asOf is never read, whatever order
// it arrived in. Missing counters stay missing: telemetry v2 holds no SMART
// counter, so every persisted window gives an incomplete vector today.
func BuildDeviceFeatures(ctx context.Context, history telemetryHistory, deviceID string, asOf time.Time) (DeviceFeatures, error) {
	asOf = asOf.UTC()
	end := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	from := end.AddDate(0, 0, -(contracts.FeatureWindowDays - 1))
	// The history window excludes its end, in microseconds. Add one to keep asOf.
	to := asOf.Truncate(time.Microsecond).Add(time.Microsecond)

	result := DeviceFeatures{DeviceID: deviceID}
	var readings []health.SMARTReading
	var after *historyCursor
	for {
		page, err := history.TelemetryHistory(ctx, deviceID, from, to, after, contracts.TelemetryHistoryPageMaxV1)
		if err != nil {
			return DeviceFeatures{}, fmt.Errorf("read feature window: %w", err)
		}
		result.DeploymentID = page.DeploymentID
		for _, sample := range page.Samples {
			readings = append(readings, health.ReadingFromHistory(sample))
			result.LastSequence = max(result.LastSequence, sample.Sequence)
		}
		result.SamplesRead += len(page.Samples)
		if page.NextAfter == nil {
			break
		}
		cursor, err := parseHistoryCursor(*page.NextAfter)
		if err != nil {
			return DeviceFeatures{}, fmt.Errorf("read feature window: %w", err)
		}
		after = &cursor
	}
	vector, err := health.Preprocess(asOf, readings)
	if err != nil {
		return DeviceFeatures{}, err
	}
	result.Vector = vector
	return result, nil
}
