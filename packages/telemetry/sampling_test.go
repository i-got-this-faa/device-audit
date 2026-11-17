package telemetry

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func validSamplingConfig() SamplingConfig {
	return SamplingConfig{
		SchemaVersion: SamplingConfigSchema,
		EmitInterval:  Duration(time.Minute),
		Budget:        SamplingBudget{MaxCPUPercentOneCore: 2, MaxRSSBytes: 64 << 20},
		Sources:       []SourceSchedule{{Source: SensorCPU, Interval: Duration(15 * time.Second), Deadline: Duration(5 * time.Second)}},
	}
}

func TestSamplingConfigValidation(t *testing.T) {
	if err := DefaultSamplingConfig().Validate(); err != nil {
		t.Fatalf("default config: %v", err)
	}
	if n := len(DefaultSamplingConfig().Sources); n != len(SensorSourceSpecs()) {
		t.Fatalf("default schedules %d of %d sources", n, len(SensorSourceSpecs()))
	}
	for name, mutate := range map[string]func(*SamplingConfig){
		"schema":            func(c *SamplingConfig) { c.SchemaVersion = "v0" },
		"no sources":        func(c *SamplingConfig) { c.Sources = nil },
		"unknown source":    func(c *SamplingConfig) { c.Sources[0].Source = "keyboard" },
		"duplicate source":  func(c *SamplingConfig) { c.Sources = append(c.Sources, c.Sources[0]) },
		"interval too fast": func(c *SamplingConfig) { c.Sources[0].Interval = Duration(time.Second) },
		"interval too slow": func(c *SamplingConfig) { c.Sources[0].Interval = Duration(10 * time.Minute) },
		"zero deadline":     func(c *SamplingConfig) { c.Sources[0].Deadline = 0 },
		"deadline > max": func(c *SamplingConfig) {
			c.Sources[0].Interval, c.Sources[0].Deadline = Duration(time.Minute), Duration(31*time.Second)
		},
		"deadline > interval": func(c *SamplingConfig) {
			c.Sources[0].Interval, c.Sources[0].Deadline = Duration(6*time.Second), Duration(7*time.Second)
		},
		"emit too fast": func(c *SamplingConfig) { c.EmitInterval = Duration(time.Second) },
		"zero cpu":      func(c *SamplingConfig) { c.Budget.MaxCPUPercentOneCore = 0 },
		"cpu above 100": func(c *SamplingConfig) { c.Budget.MaxCPUPercentOneCore = 101 },
		"rss too small": func(c *SamplingConfig) { c.Budget.MaxRSSBytes = 1 << 20 },
		"rss too large": func(c *SamplingConfig) { c.Budget.MaxRSSBytes = 2 << 30 },
	} {
		cfg := validSamplingConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestParseSamplingConfigIsStrict(t *testing.T) {
	good := `{"schema_version":"device-audit.sampling-config.v1","emit_interval":"60s",
		"budget":{"max_cpu_percent_one_core":2,"max_rss_bytes":67108864},
		"sources":[{"source":"cpu","interval":"15s","deadline":"5s"},{"source":"gpu_vendor","interval":"1m","deadline":"5s"}]}`
	cfg, err := ParseSamplingConfig(strings.NewReader(good))
	if err != nil {
		t.Fatal(err)
	}
	if time.Duration(cfg.Sources[1].Interval) != time.Minute || len(cfg.Sources) != 2 {
		t.Fatalf("cfg = %+v", cfg)
	}
	for name, doc := range map[string]string{
		"unknown field":  strings.Replace(good, `"emit_interval"`, `"shell":"x","emit_interval"`, 1),
		"numeric time":   strings.Replace(good, `"60s"`, `60`, 1),
		"bad duration":   strings.Replace(good, `"60s"`, `"soon"`, 1),
		"trailing data":  good + `{}`,
		"invalid bounds": strings.Replace(good, `"5s"}`, `"20s"}`, 1),
		"oversized":      strings.Repeat(" ", MaxSamplingConfigBytes+1) + good,
	} {
		if _, err := ParseSamplingConfig(strings.NewReader(doc)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func fakeUsage() func() (ProcessUsage, error) {
	var mu sync.Mutex
	var cpu time.Duration
	return func() (ProcessUsage, error) {
		mu.Lock()
		defer mu.Unlock()
		cpu += time.Microsecond
		return ProcessUsage{CPU: cpu, RSS: 10 << 20, CoreCount: 4}, nil
	}
}

// Acceptance: a hung provider and a denied provider do not stall a healthy
// source, the hung provider never holds more than one goroutine, and every
// snapshot keeps each source's missing reason.
func TestSchedulerSlowProviderDoesNotStallOthers(t *testing.T) {
	defer func(old time.Duration) { minSourceInterval = old }(minSourceInterval)
	minSourceInterval = time.Millisecond

	release := make(chan struct{})
	defer close(release)
	var hungEntered, hungRunning, hungMax atomic.Int32
	var fastReads atomic.Int32
	cfg := SamplingConfig{
		SchemaVersion: SamplingConfigSchema,
		EmitInterval:  Duration(40 * time.Millisecond),
		Budget:        SamplingBudget{MaxCPUPercentOneCore: 100, MaxRSSBytes: 64 << 20},
		Sources: []SourceSchedule{
			{Source: SensorCPU, Interval: Duration(10 * time.Millisecond), Deadline: Duration(5 * time.Millisecond)},
			{Source: SensorMemory, Interval: Duration(10 * time.Millisecond), Deadline: Duration(5 * time.Millisecond)},
			{Source: SensorDisk, Interval: Duration(10 * time.Millisecond), Deadline: Duration(5 * time.Millisecond)},
		},
	}
	s := Scheduler{Config: cfg, Usage: fakeUsage(), Sources: []SensorSource{
		sourceWith(SensorCPU, func(context.Context) ([]SensorReading, error) {
			fastReads.Add(1)
			return CPUReadings(SystemTimes{Kernel: 100}, SystemTimes{Kernel: 200, Idle: 50})
		}),
		sourceWith(SensorMemory, func(context.Context) ([]SensorReading, error) {
			hungEntered.Add(1)
			n := hungRunning.Add(1)
			for { // record the most concurrent provider calls
				m := hungMax.Load()
				if n <= m || hungMax.CompareAndSwap(m, n) {
					break
				}
			}
			<-release // ignores its context, like a blocked system call
			hungRunning.Add(-1)
			return MemoryReadings(8, 4)
		}),
		sourceWith(SensorDisk, func(context.Context) ([]SensorReading, error) {
			return nil, sensorErr(ErrPermissionDenied, "volume_access_denied")
		}),
	}}
	var mu sync.Mutex
	var samples []SensorSample
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	report, err := s.Run(ctx, func(sample SensorSample) error {
		mu.Lock()
		samples = append(samples, sample)
		mu.Unlock()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fastReads.Load() < 10 {
		t.Fatalf("fast source read %d times in 400 ms at 10 ms; it was stalled", fastReads.Load())
	}
	if hungEntered.Load() != 1 || hungMax.Load() != 1 {
		t.Fatalf("hung provider started %d times, %d at once", hungEntered.Load(), hungMax.Load())
	}
	stats := map[string]SourceRunStats{}
	for _, st := range report.Sources {
		stats[st.Source] = st
	}
	if mem := stats[SensorMemory]; mem.BusySkips == 0 || !mem.ProviderBusy || mem.Details["timeout"] != 1 || mem.Details["provider_busy"] != mem.BusySkips {
		t.Fatalf("memory stats = %+v", mem)
	}
	if disk := stats[SensorDisk]; disk.KnownReads != 0 || disk.Reasons[ReasonPermissionDenied] != disk.Reads {
		t.Fatalf("disk stats = %+v", disk)
	}
	if report.Emits < 5 || len(samples) != report.Emits {
		t.Fatalf("emits = %d, samples = %d", report.Emits, len(samples))
	}
	for _, sample := range samples[1:] {
		m := sample.MetricsV2()
		if m.CPUUtilization == nil || m.CPUUtilization.Value == nil || *m.CPUUtilization.Value != 50 {
			t.Fatalf("cpu = %+v", m.CPUUtilization)
		}
		if m.MemoryPercent.Value != nil || m.MemoryPercent.MissingReason != ReasonCollectionError {
			t.Fatalf("memory = %+v", m.MemoryPercent)
		}
		if m.DiskUsedPercent.Value != nil || m.DiskUsedPercent.MissingReason != ReasonPermissionDenied {
			t.Fatalf("disk = %+v", m.DiskUsedPercent)
		}
	}
	if report.Schema != SamplingReportSchema || report.Budget.RSSPeakBytes != 10<<20 || !report.Budget.Within() {
		t.Fatalf("report = %+v", report.Budget)
	}
	if _, err := MarshalSamplingReport(report); err != nil {
		t.Fatal(err)
	}
}

func TestSchedulerSnapshotMarksMissingAndStaleResults(t *testing.T) {
	st := &sourceState{schedule: SourceSchedule{Source: SensorCPU, Interval: Duration(15 * time.Second), Deadline: Duration(5 * time.Second)},
		source: sourceWith(SensorCPU, nil)}
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	if r := st.snapshot(at); r.Readings[0].Detail != "not_yet_sampled" || r.Readings[0].Value != nil {
		t.Fatalf("empty = %+v", r)
	}
	st.record(SourceResult{Source: SensorCPU, ObservedAt: at.Add(-20 * time.Second), Readings: []SensorReading{{Metric: MetricCPUUtilization, Value: f64(10)}}})
	if r := st.snapshot(at); r.Readings[0].Value == nil {
		t.Fatalf("fresh result hidden: %+v", r)
	}
	if r := st.snapshot(at.Add(2 * time.Second)); r.Readings[0].Value != nil || r.Readings[0].Detail != "stale_result" || r.Readings[0].MissingReason != ReasonCollectionError {
		t.Fatalf("stale result shown as current: %+v", r)
	}
}

func TestEvaluateBudget(t *testing.T) {
	budget := SamplingBudget{MaxCPUPercentOneCore: 2, MaxRSSBytes: 32 << 20}
	ok, err := evaluateBudget(budget, 1200*time.Millisecond, time.Minute, 30<<20, 9)
	if err != nil || !ok.Within() || ok.CPUPercentOneCore != 2 {
		t.Fatalf("at limit = %+v %v", ok, err)
	}
	over, _ := evaluateBudget(budget, 1300*time.Millisecond, time.Minute, 33<<20, 9)
	if over.CPUWithinBudget || over.RSSWithinBudget || over.Within() {
		t.Fatalf("over limit = %+v", over)
	}
	if _, err := evaluateBudget(budget, time.Second, 0, 1, 1); err == nil {
		t.Fatal("zero wall time accepted")
	}
}

// The report names what ran just before the RSS peak, so a spike can be
// traced to a source.
func TestUsageMeterAttributesPeak(t *testing.T) {
	rss := []uint64{10, 12, 40, 15, 11}
	call := 0
	meter, err := newUsageMeter(func() (ProcessUsage, error) {
		u := ProcessUsage{CPU: time.Duration(call) * time.Millisecond, RSS: rss[call], CoreCount: 1}
		call++
		return u, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	meter.sampleRSS(SensorCPU)
	meter.sampleRSS(SensorGPUEngine)
	meter.sampleRSS("emit")
	time.Sleep(time.Millisecond)
	got, err := meter.finish(SamplingBudget{MaxCPUPercentOneCore: 100, MaxRSSBytes: 30})
	if err != nil {
		t.Fatal(err)
	}
	if got.RSSPeakBytes != 40 || got.RSSPeakAfter != SensorGPUEngine || got.RSSSamples != 5 || got.RSSWithinBudget {
		t.Fatalf("budget = %+v", got)
	}
}

func TestSchedulerRejectsUnboundSource(t *testing.T) {
	s := Scheduler{Config: validSamplingConfig(), Usage: fakeUsage(), Sources: nil}
	if _, err := s.Run(context.Background(), func(SensorSample) error { return nil }); err == nil {
		t.Fatal("scheduled source without a reader accepted")
	}
}
