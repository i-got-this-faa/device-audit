package telemetry

import (
	"errors"
	"fmt"
	"time"
)

const (
	// CandidateFast and CandidateSlow are the TEL04 cadence candidates.
	// A measurement at another interval does not replace them.
	CandidateFast = 15 * time.Second
	CandidateSlow = 60 * time.Second

	// MaxSamples, MaxInterval and MaxWorkerDeadline match the Windows probe bounds.
	MaxSamples        = 30
	MaxInterval       = 300 * time.Second
	MaxWorkerDeadline = 30 * time.Second
	// DefaultWorkerDeadline is the probe default. It is not a measured provider timeout.
	DefaultWorkerDeadline = 10 * time.Second
	MaxRepeats            = 5
	MaxBaseline           = 30 * time.Second
)

// Cadence is a start-to-start sampling schedule. Late sweeps do not catch up.
type Cadence struct {
	Interval       time.Duration
	Samples        int
	WorkerDeadline time.Duration
}

// Validate checks the schedule bounds. Intervals shorter than the candidates
// are allowed so tests can exercise the scheduler without waiting 15 seconds.
func (c Cadence) Validate() error {
	if c.Samples < 1 || c.Samples > MaxSamples {
		return fmt.Errorf("telemetry: samples must be from 1 to %d", MaxSamples)
	}
	if c.Interval < time.Millisecond || c.Interval > MaxInterval || c.Interval%time.Millisecond != 0 {
		return fmt.Errorf("telemetry: interval must be a whole number of milliseconds from 1 to %s", MaxInterval)
	}
	if c.WorkerDeadline <= 0 || c.WorkerDeadline > MaxWorkerDeadline {
		return fmt.Errorf("telemetry: worker deadline must be positive and at most %s", MaxWorkerDeadline)
	}
	return nil
}

// IsCandidate reports whether the interval is one of the two published candidates.
func (c Cadence) IsCandidate() bool {
	return c.Interval == CandidateFast || c.Interval == CandidateSlow
}

// Due returns the start-to-start time of sweep index. Index 0 is origin.
// There is no skipped-sweep list: a late caller still runs this one index.
func (c Cadence) Due(origin time.Time, index int) (time.Time, error) {
	if err := c.Validate(); err != nil {
		return time.Time{}, err
	}
	if index < 0 || index >= c.Samples {
		return time.Time{}, fmt.Errorf("telemetry: sweep index %d is outside 0..%d", index, c.Samples-1)
	}
	if origin.IsZero() {
		return time.Time{}, errors.New("telemetry: cadence origin is required")
	}
	return origin.Add(time.Duration(index) * c.Interval), nil
}
