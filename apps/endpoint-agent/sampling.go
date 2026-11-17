package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

// maxSamplingRun bounds one --sample invocation.
const maxSamplingRun = 24 * time.Hour

// errBudgetExceeded means the run finished but measured more CPU or RSS than
// the configuration declared.
var errBudgetExceeded = errors.New("sampling exceeded its declared CPU or RSS budget")

// loadSamplingConfig reads a configuration file, or returns the built-in
// default when path is empty. Either way the result is validated.
func loadSamplingConfig(path string) (telemetry.SamplingConfig, error) {
	if path == "" {
		cfg := telemetry.DefaultSamplingConfig()
		return cfg, cfg.Validate()
	}
	f, err := os.Open(path)
	if err != nil {
		return telemetry.SamplingConfig{}, errors.New("open sampling config")
	}
	defer f.Close()
	return telemetry.ParseSamplingConfig(f)
}

// runSampling runs the scheduler for duration and writes one telemetry v2
// payload per snapshot to out. A snapshot without any known metric is not a
// valid payload; it is counted on errOut instead of being padded.
func runSampling(ctx context.Context, scheduler telemetry.Scheduler, deviceID string, duration time.Duration, out, errOut io.Writer) (telemetry.SamplingReport, error) {
	if duration < time.Second || duration > maxSamplingRun {
		return telemetry.SamplingReport{}, fmt.Errorf("sampling duration must be from 1s to %s", maxSamplingRun)
	}
	ctx, cancel := context.WithTimeout(ctx, duration)
	defer cancel()
	encoder := json.NewEncoder(out)
	return scheduler.Run(ctx, func(sample telemetry.SensorSample) error {
		payload, err := telemetry.EndpointTelemetryV2(sample, deviceID)
		if err != nil {
			fmt.Fprintf(errOut, "snapshot at %s not emitted: %s\n", sample.CollectedAt.Format(time.RFC3339), err)
			return nil
		}
		if err := encoder.Encode(payload); err != nil {
			return errors.New("write sampled telemetry")
		}
		return nil
	})
}

// writeSamplingReport writes a new report file; an existing file is kept.
func writeSamplingReport(path string, report telemetry.SamplingReport) error {
	encoded, err := telemetry.MarshalSamplingReport(report)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return errors.New("create sampling report; the file must not exist")
	}
	_, writeErr := f.Write(encoded)
	if closeErr := f.Close(); writeErr == nil {
		writeErr = closeErr
	}
	return writeErr
}

// budgetSummary is the one-line verdict printed after a run.
func budgetSummary(report telemetry.SamplingReport) string {
	b, limit := report.Budget, report.Config.Budget
	return fmt.Sprintf("sampling budget: cpu %.3f%% of one core (limit %.3f%%), rss peak %d bytes (limit %d), within=%v",
		b.CPUPercentOneCore, limit.MaxCPUPercentOneCore, b.RSSPeakBytes, limit.MaxRSSBytes, b.Within())
}
