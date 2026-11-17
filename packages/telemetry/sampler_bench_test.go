package telemetry

import (
	"context"
	"testing"
	"time"
)

func BenchmarkPermissionCompare(b *testing.B) {
	planned := PlanningToken()
	denied := DeniedToken()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rows, err := Compare(planned, denied)
		if err != nil || len(rows) != 8 {
			b.Fatal(err)
		}
	}
}

func BenchmarkSyntheticSweep(b *testing.B) {
	sources := make([]BoundSource, 0, 8)
	for _, spec := range Catalog() {
		sources = append(sources, BoundSource{
			Spec: spec, Provenance: ProvenanceHarness,
			Sample: func(context.Context) (SampleResult, error) {
				v := burnIterations(1000)
				return SampleResult{Metric: "synthetic_work", Unit: "iteration", Value: &v}, nil
			},
		})
	}
	runner := Runner{
		Cadence:  Cadence{Interval: time.Millisecond, Samples: 1, WorkerDeadline: DefaultWorkerDeadline},
		Repeats:  1,
		Baseline: 0,
		Token:    PlanningToken(),
		Sources:  sources,
		// The benchmark measures one sweep. It does not wait out the interval.
		Sleep: func(time.Duration) {},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := runner.Measure(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func burnIterations(iterations int) float64 {
	var x int
	for i := 0; i < iterations; i++ {
		x += i*31 ^ (i << 1)
	}
	if x == -1 {
		return 0
	}
	return float64(iterations)
}
