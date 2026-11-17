// Command sensoravailability records which battery, thermal and GPU readings
// this host returns through the TEL06 #92 collector. It reads only; it does not
// elevate, change ACLs, install drivers or tools, or attest its token.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "sensoravailability: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("sensoravailability", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "new JSON file; the parent directory must exist")
	samples := flags.Int("samples", 3, "sweeps, from 1 to 30")
	interval := flags.Duration("interval", telemetry.CandidateFast, "start-to-start interval, up to 300s")
	deadline := flags.Duration("deadline", telemetry.DefaultSensorDeadline, "per-source deadline, up to 30s")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *output == "" {
		return errors.New("output path is required")
	}
	if *deadline <= 0 {
		return errors.New("deadline must be positive")
	}
	if info, err := os.Stat(filepath.Dir(*output)); err != nil || !info.IsDir() {
		return errors.New("output parent directory must exist")
	}
	if _, err := os.Stat(*output); err == nil {
		return errors.New("output already exists; choose a new path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	collector := telemetry.NewSensorCollector()
	collector.Deadline = *deadline
	report, err := telemetry.SensorRun{Collector: collector, Samples: *samples, Interval: *interval}.Measure(context.Background())
	if err != nil {
		return err
	}
	encoded, err := telemetry.MarshalSensorReport(report)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(encoded)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	for _, a := range report.Availability {
		fmt.Fprintf(stdout, "%s %s unit=%s known=%d null=%d reasons=%v details=%v max_query_ms=%.3f\n",
			a.Source, a.Metric, a.Unit, a.Known, a.Null, a.Reasons, a.Details, a.MaxQueryMS)
	}
	fmt.Fprintf(stdout, "schema=%s qualification=%s samples=%d interval=%s\n", report.Schema, report.Qualification, len(report.Samples), time.Duration(report.IntervalMS)*time.Millisecond)
	return nil
}
