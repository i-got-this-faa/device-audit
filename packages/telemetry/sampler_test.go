package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(d time.Duration) {
	if d > 0 {
		c.now = c.now.Add(d)
	}
}

type scriptedUsage struct {
	rss   []uint64
	index int
	cpu   time.Duration
}

func (s *scriptedUsage) Sample() (ProcessUsage, error) {
	s.cpu += time.Millisecond
	rss := s.rss[len(s.rss)-1]
	if s.index < len(s.rss) {
		rss = s.rss[s.index]
		s.index++
	}
	return ProcessUsage{CPU: s.cpu, RSS: rss, HeapAlloc: rss, CoreCount: 4}, nil
}

func specNamed(name string) SourceSpec {
	for _, spec := range Catalog() {
		if spec.Source == name {
			return spec
		}
	}
	panic("missing spec " + name)
}

func successSample(ctx context.Context) (SampleResult, error) {
	v := 3.0
	return SampleResult{Metric: "synthetic_work", Unit: "iteration", Value: &v}, nil
}

func TestDeniedAndFailedSourcesContinue(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	usage := &scriptedUsage{rss: []uint64{10, 50, 20, 40, 5}}
	token := PlanningToken()
	kept := token.Capabilities[:0]
	for _, cap := range token.Capabilities {
		if cap != CapACPIThermal {
			kept = append(kept, cap)
		}
	}
	token.Capabilities = kept
	calls := map[string]int{}
	runner := Runner{
		Cadence:  Cadence{Interval: 20 * time.Millisecond, Samples: 1, WorkerDeadline: time.Second},
		Repeats:  1,
		Baseline: 0,
		Token:    token,
		Now:      clock.Now,
		Sleep:    clock.Sleep,
		Usage:    usage.Sample,
		Sources: []BoundSource{
			{Spec: specNamed("thermal"), Provenance: ProvenanceHarness, Sample: func(context.Context) (SampleResult, error) {
				calls["thermal"]++
				return successSample(context.Background())
			}},
			{Spec: specNamed("cpu"), Provenance: ProvenanceHarness, Sample: func(context.Context) (SampleResult, error) {
				calls["cpu"]++
				clock.Sleep(time.Millisecond)
				return SampleResult{}, errors.New("sensor failed")
			}},
			{Spec: specNamed("memory"), Provenance: ProvenanceHarness, Sample: func(context.Context) (SampleResult, error) {
				calls["memory"]++
				clock.Sleep(time.Millisecond)
				v := 0.0
				return SampleResult{Metric: "synthetic_work", Unit: "iteration", Value: &v}, nil
			}},
		},
	}
	report, err := runner.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if calls["thermal"] != 0 || calls["cpu"] != 1 || calls["memory"] != 1 {
		t.Fatalf("calls = %#v", calls)
	}
	sources := report.Windows[1].Sweeps[0].Sources
	if sources[0].Outcome != "permission_denied" || sources[0].Invoked || sources[0].Value != nil {
		t.Fatalf("thermal = %#v", sources[0])
	}
	if sources[1].Outcome != "collection_error" || sources[1].Value != nil {
		t.Fatalf("cpu = %#v", sources[1])
	}
	if sources[2].Outcome != "success" || sources[2].Value == nil || *sources[2].Value != 0 {
		t.Fatalf("memory = %#v", sources[2])
	}
	probe := report.Windows[1]
	if probe.RSSPeakBytes != maxUint(probe.RSSSamplesBytes) {
		t.Fatalf("peak %d is not max %v", probe.RSSPeakBytes, probe.RSSSamplesBytes)
	}
	if len(probe.RSSSamplesBytes) < 2 || probe.RSSPeakBytes == sumUint(probe.RSSSamplesBytes) {
		t.Fatalf("sequential rss samples were summed: peak %d samples %v", probe.RSSPeakBytes, probe.RSSSamplesBytes)
	}
	if report.ServiceAccessQualified || report.Recommendation.ProductionBudgetApproved || report.CandidateCadence {
		t.Fatalf("report claimed qualification: %#v", report.Recommendation)
	}
	encoded, err := MarshalReport(report)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"value": 0`) {
		t.Fatalf("zero was dropped from JSON: %s", encoded)
	}
	assertNoPrivateKeys(t, encoded)
}

func TestTimeoutDoesNotBlockTheNextSource(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	calls := 0
	runner := Runner{
		Cadence: Cadence{Interval: time.Second, Samples: 1, WorkerDeadline: 30 * time.Millisecond},
		Repeats: 1,
		Token:   PlanningToken(),
		Sources: []BoundSource{
			{Spec: specNamed("cpu"), Provenance: ProvenanceHarness, Sample: func(ctx context.Context) (SampleResult, error) {
				<-ctx.Done()
				return SampleResult{}, ctx.Err()
			}},
			{Spec: specNamed("memory"), Provenance: ProvenanceHarness, Sample: func(context.Context) (SampleResult, error) {
				calls++
				return successSample(context.Background())
			}},
		},
	}
	report, err := runner.Measure(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sources := report.Windows[1].Sweeps[0].Sources
	if sources[0].Outcome != "timeout" || sources[0].Value != nil || !sources[0].Invoked {
		t.Fatalf("cpu = %#v", sources[0])
	}
	if calls != 1 || sources[1].Outcome != "success" {
		t.Fatalf("memory calls=%d observation=%#v", calls, sources[1])
	}
	if report.Windows[1].Sweeps[0].Overrun {
		t.Fatal("a 30ms timeout overran a 1s cadence")
	}
}

func TestOverrunDoesNotInsertCatchUpSweeps(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	usage := &scriptedUsage{rss: []uint64{10, 50, 20}}
	runner := Runner{
		Cadence: Cadence{Interval: 15 * time.Second, Samples: 3, WorkerDeadline: 30 * time.Second},
		Repeats: 1,
		Token:   PlanningToken(),
		Now:     clock.Now,
		Sleep:   clock.Sleep,
		Usage:   usage.Sample,
		Sources: []BoundSource{{
			Spec: specNamed("cpu"), Provenance: ProvenanceHarness,
			Sample: func(context.Context) (SampleResult, error) {
				clock.Sleep(20 * time.Second)
				return successSample(context.Background())
			},
		}},
	}
	started := clock.now
	report, err := runner.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	probe := report.Windows[1]
	if len(probe.Sweeps) != 3 || report.Summary.Overruns != 3 || report.Summary.Sweeps != 3 {
		t.Fatalf("sweeps=%d summary=%#v", len(probe.Sweeps), report.Summary)
	}
	if clock.now.Sub(started) != 60*time.Second {
		t.Fatalf("elapsed = %s; catch-up or padding changed the overrun schedule", clock.now.Sub(started))
	}
}

func TestCanceledRunReturnsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	runner := Runner{
		Cadence: Cadence{Interval: time.Millisecond, Samples: 1, WorkerDeadline: time.Second},
		Repeats: 1,
		Token:   PlanningToken(),
		Sources: []BoundSource{{Spec: specNamed("cpu"), Provenance: ProvenanceHarness, Sample: successSample}},
	}
	if _, err := runner.Measure(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestUnmovedClockRecordsZeroPercents(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	runner := Runner{
		Cadence: Cadence{Interval: time.Second, Samples: 1, WorkerDeadline: time.Second},
		Repeats: 1,
		Token:   PlanningToken(),
		Now:     clock.Now,
		Sleep:   func(time.Duration) {},
		Usage: func() (ProcessUsage, error) {
			return ProcessUsage{CPU: time.Second, RSS: 4096, CoreCount: 2}, nil
		},
		Sources: []BoundSource{{Spec: specNamed("cpu"), Provenance: ProvenanceHarness, Sample: successSample}},
	}
	report, err := runner.Measure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	probe := report.Windows[1]
	if probe.WallMS != 0 || probe.CPUTimeMS != 0 || probe.CPUPercentOneCore != 0 || probe.CPUPercentMachine != 0 {
		t.Fatalf("probe = %#v", probe)
	}
}

func TestCPUWithoutWallTimeIsRejected(t *testing.T) {
	calls := 0
	runner := Runner{
		Cadence: Cadence{Interval: time.Second, Samples: 1, WorkerDeadline: time.Second},
		Repeats: 1,
		Token:   PlanningToken(),
		Now:     func() time.Time { return time.Unix(1_700_000_000, 0).UTC() },
		Sleep:   func(time.Duration) {},
		Usage: func() (ProcessUsage, error) {
			calls++
			return ProcessUsage{CPU: time.Duration(calls) * time.Millisecond, RSS: 4096, CoreCount: 2}, nil
		},
		Sources: []BoundSource{{Spec: specNamed("cpu"), Provenance: ProvenanceHarness, Sample: successSample}},
	}
	if _, err := runner.Measure(context.Background()); err == nil {
		t.Fatal("cpu advanced while wall time stayed at zero")
	}
}

func TestRealProvenanceIsRejected(t *testing.T) {
	runner := Runner{
		Cadence: Cadence{Interval: time.Millisecond, Samples: 1, WorkerDeadline: time.Second},
		Repeats: 1,
		Token:   PlanningToken(),
		Sources: []BoundSource{{Spec: specNamed("cpu"), Provenance: "real", Sample: successSample}},
	}
	if _, err := runner.Measure(context.Background()); err == nil {
		t.Fatal("real provenance was accepted")
	}
}

func TestSampleProcessMonotonic(t *testing.T) {
	first, err := SampleProcess()
	if errors.Is(err, ErrProcessUsageUnsupported) {
		t.Skip(err.Error())
	}
	if err != nil {
		t.Fatal(err)
	}
	var sink int
	for i := 0; i < 2_000_000; i++ {
		sink += i
	}
	if sink == 0 {
		t.Fatal("work was removed")
	}
	second, err := SampleProcess()
	if err != nil {
		t.Fatal(err)
	}
	if second.CPU < first.CPU || second.RSS == 0 || second.CoreCount < 1 {
		t.Fatalf("first=%#v second=%#v", first, second)
	}
	delta, err := cpuDelta(first.CPU, second.CPU)
	if err != nil || delta < 0 {
		t.Fatal(err)
	}
}

func sumUint(values []uint64) uint64 {
	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}

func assertNoPrivateKeys(t *testing.T, encoded []byte) {
	t.Helper()
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			for key, child := range typed {
				switch key {
				case "hostname", "device_id", "serial", "user", "username", "event_payload":
					t.Fatalf("private key %s", key)
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
}
