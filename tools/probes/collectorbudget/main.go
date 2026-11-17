// Command collectorbudget measures the synthetic collector sampler.
// It does not read Windows sensors and it does not attest a service token.
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
		fmt.Fprintf(os.Stderr, "collectorbudget: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("collectorbudget", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "", "new JSON file; the parent directory must exist")
	interval := flags.Duration("interval", telemetry.CandidateFast, "cadence interval, 15s or 60s unless -allow-non-candidate")
	samples := flags.Int("samples", 3, "sweeps per probe window, from 1 to 30")
	repeats := flags.Int("repeats", 1, "baseline/probe repeats, from 1 to 5")
	baseline := flags.Duration("baseline", 2*time.Second, "idle window before each probe window")
	deadline := flags.Duration("deadline", telemetry.DefaultWorkerDeadline, "per-source deadline")
	iterations := flags.Int("iterations", 200000, "identical integer work per successful source")
	tokenName := flags.String("token", "planned", "planned or denied")
	allowNonCandidate := flags.Bool("allow-non-candidate", false, "allow an interval other than 15s or 60s")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	if *output == "" {
		return errors.New("output path is required")
	}
	if *iterations < 1 || *iterations > 50_000_000 {
		return errors.New("iterations must be from 1 to 50000000")
	}
	cadence := telemetry.Cadence{Interval: *interval, Samples: *samples, WorkerDeadline: *deadline}
	if err := cadence.Validate(); err != nil {
		return err
	}
	if !*allowNonCandidate && !cadence.IsCandidate() {
		return errors.New("interval must be 15s or 60s; other intervals are not cadence candidates")
	}
	token, err := selectToken(*tokenName)
	if err != nil {
		return err
	}
	parent := filepath.Dir(*output)
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("output parent directory must exist")
	}
	if _, err := os.Stat(*output); err == nil {
		return errors.New("output already exists; choose a new path")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	runner := telemetry.Runner{
		Cadence:  cadence,
		Repeats:  *repeats,
		Baseline: *baseline,
		Token:    token,
		Sources:  syntheticSources(*iterations),
	}
	report, err := runner.Measure(context.Background())
	if err != nil {
		return err
	}
	encoded, err := telemetry.MarshalReport(report)
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
	fmt.Fprintf(stdout, "schema=%s qualification=%s cadence_ms=%d sweeps=%d max_query_ms=%.3f rss_peak_bytes=%d production_budget_approved=%t\n",
		report.Schema, report.Qualification, report.IntervalMS, report.Summary.Sweeps, report.Summary.MaxQueryMS,
		report.Summary.RSSPeakBytes, report.Recommendation.ProductionBudgetApproved)
	return nil
}

func selectToken(name string) (telemetry.Token, error) {
	switch name {
	case "planned":
		return telemetry.PlanningToken(), nil
	case "denied":
		return telemetry.DeniedToken(), nil
	default:
		return telemetry.Token{}, errors.New("token must be planned or denied")
	}
}

func syntheticSources(iterations int) []telemetry.BoundSource {
	sources := make([]telemetry.BoundSource, 0, len(telemetry.Catalog()))
	for _, spec := range telemetry.Catalog() {
		sources = append(sources, telemetry.BoundSource{
			Spec:       spec,
			Provenance: telemetry.ProvenanceHarness,
			Sample: func(context.Context) (telemetry.SampleResult, error) {
				value := burn(iterations)
				return telemetry.SampleResult{Metric: "synthetic_work", Unit: "iteration", Value: &value}, nil
			},
		})
	}
	return sources
}

func burn(iterations int) float64 {
	var x int
	for i := 0; i < iterations; i++ {
		x += i*31 ^ (i << 1)
	}
	if x == -1 {
		return 0
	}
	return float64(iterations)
}
