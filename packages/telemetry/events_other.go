//go:build !windows

package telemetry

import (
	"context"
	"time"
)

// unselectedEventReader reports every log unavailable. V1 selects only the
// Windows endpoint (#14); no other OS log source is implemented or claimed.
type unselectedEventReader struct{}

func platformEventReader() EventLogReader { return unselectedEventReader{} }

func (unselectedEventReader) Bounds(context.Context, string) (LogBounds, error) {
	return LogBounds{}, sensorErr(ErrSensorUnavailable, "platform_not_selected")
}

func (unselectedEventReader) RecordTime(context.Context, string, uint64) (time.Time, bool, error) {
	return time.Time{}, false, sensorErr(ErrSensorUnavailable, "platform_not_selected")
}

func (unselectedEventReader) ReadErrors(context.Context, string, uint64, time.Time, int) ([]RawEvent, error) {
	return nil, sensorErr(ErrSensorUnavailable, "platform_not_selected")
}
