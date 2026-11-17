package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// TEL08 #94: bounded, configurable telemetry sampling.
//
// Each configured source runs on its own goroutine at its own start-to-start
// interval, with no catch-up after an overrun. A provider still blocked from
// its previous read is not started again: that tick is a provider_busy null.
// One hung provider therefore holds at most one goroutine and cannot delay
// any other source. An emitter publishes the latest result of every source at
// a fixed interval; a result older than its schedule allows is published as a
// null, never as a current value.

const (
	// SamplingConfigSchema identifies a sampling configuration document.
	SamplingConfigSchema = "device-audit.sampling-config.v1"
	// SamplingReportSchema identifies a sampling run report. It is not
	// telemetry v1 or v2 and carries no device identifier.
	SamplingReportSchema = "device-audit.sampling-report.v1"
	// MaxSamplingConfigBytes bounds a configuration file.
	MaxSamplingConfigBytes = 16 << 10
	// MaxSamplingCPUPercent and the RSS bounds limit what a budget may declare.
	MaxSamplingCPUPercent = 100.0
	MinSamplingRSSBytes   = 4 << 20
	MaxSamplingRSSBytes   = 1 << 30
)

// minSourceInterval is the shortest configurable interval. Tests lower it.
var minSourceInterval = 5 * time.Second

// Duration is a time.Duration written as a Go duration string, such as "15s".
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return errors.New("duration must be a string such as \"15s\"")
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// SamplingBudget is the declared cost ceiling of the sampling process. CPU is
// percent of one core over the whole run; RSS is the peak working set.
type SamplingBudget struct {
	MaxCPUPercentOneCore float64 `json:"max_cpu_percent_one_core"`
	MaxRSSBytes          uint64  `json:"max_rss_bytes"`
}

// SourceSchedule is one source's cadence. A source that is not listed is not
// sampled.
type SourceSchedule struct {
	Source   string   `json:"source"`
	Interval Duration `json:"interval"`
	Deadline Duration `json:"deadline"`
}

// SamplingConfig is the validated sampling configuration.
type SamplingConfig struct {
	SchemaVersion string           `json:"schema_version"`
	EmitInterval  Duration         `json:"emit_interval"`
	Budget        SamplingBudget   `json:"budget"`
	Sources       []SourceSchedule `json:"sources"`
}

// DefaultSamplingConfig samples every source at the 15-second candidate
// cadence, except the NVIDIA tool, which starts a process and runs at the
// 60-second candidate. The budget is a declared ceiling, not an approved
// production budget.
func DefaultSamplingConfig() SamplingConfig {
	cfg := SamplingConfig{
		SchemaVersion: SamplingConfigSchema,
		EmitInterval:  Duration(CandidateSlow),
		Budget:        SamplingBudget{MaxCPUPercentOneCore: 2, MaxRSSBytes: 64 << 20},
	}
	for _, src := range SensorSourceSpecs() {
		interval := CandidateFast
		if src.Name == SensorGPUVendor {
			interval = CandidateSlow
		}
		cfg.Sources = append(cfg.Sources, SourceSchedule{Source: src.Name, Interval: Duration(interval), Deadline: Duration(DefaultSensorDeadline)})
	}
	return cfg
}

// ParseSamplingConfig strictly decodes and validates one JSON document.
func ParseSamplingConfig(r io.Reader) (SamplingConfig, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxSamplingConfigBytes+1))
	if err != nil {
		return SamplingConfig{}, err
	}
	if len(data) > MaxSamplingConfigBytes {
		return SamplingConfig{}, fmt.Errorf("telemetry: sampling config exceeds %d bytes", MaxSamplingConfigBytes)
	}
	var cfg SamplingConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return SamplingConfig{}, fmt.Errorf("telemetry: sampling config: %w", err)
	}
	if decoder.More() {
		return SamplingConfig{}, errors.New("telemetry: sampling config has trailing data")
	}
	return cfg, cfg.Validate()
}

// Validate checks the schema, source names, cadences, deadlines and budget.
func (c SamplingConfig) Validate() error {
	if c.SchemaVersion != SamplingConfigSchema {
		return fmt.Errorf("telemetry: sampling config schema must be %s", SamplingConfigSchema)
	}
	if err := checkInterval("emit_interval", time.Duration(c.EmitInterval)); err != nil {
		return err
	}
	b := c.Budget
	if math.IsNaN(b.MaxCPUPercentOneCore) || b.MaxCPUPercentOneCore <= 0 || b.MaxCPUPercentOneCore > MaxSamplingCPUPercent {
		return fmt.Errorf("telemetry: budget max_cpu_percent_one_core must be above 0 and at most %v", MaxSamplingCPUPercent)
	}
	if b.MaxRSSBytes < MinSamplingRSSBytes || b.MaxRSSBytes > MaxSamplingRSSBytes {
		return fmt.Errorf("telemetry: budget max_rss_bytes must be from %d to %d", MinSamplingRSSBytes, MaxSamplingRSSBytes)
	}
	if len(c.Sources) == 0 {
		return errors.New("telemetry: at least one source must be scheduled")
	}
	known := map[string]bool{}
	for _, src := range SensorSourceSpecs() {
		known[src.Name] = true
	}
	seen := map[string]bool{}
	for _, s := range c.Sources {
		if !known[s.Source] || seen[s.Source] {
			return fmt.Errorf("telemetry: scheduled source %q is unknown or duplicated", s.Source)
		}
		seen[s.Source] = true
		interval, deadline := time.Duration(s.Interval), time.Duration(s.Deadline)
		if err := checkInterval(s.Source+" interval", interval); err != nil {
			return err
		}
		if deadline <= 0 || deadline > MaxSensorDeadline || deadline > interval {
			return fmt.Errorf("telemetry: %s deadline must be positive, at most %s and at most its interval", s.Source, MaxSensorDeadline)
		}
	}
	return nil
}

func checkInterval(name string, d time.Duration) error {
	if d < minSourceInterval || d > MaxInterval {
		return fmt.Errorf("telemetry: %s must be from %s to %s", name, minSourceInterval, MaxInterval)
	}
	return nil
}

// SourceRunStats counts one source's reads over a run.
type SourceRunStats struct {
	Source       string         `json:"source"`
	IntervalMS   int64          `json:"interval_ms"`
	DeadlineMS   int64          `json:"deadline_ms"`
	Reads        int            `json:"reads"`
	BusySkips    int            `json:"busy_skips"`
	Overruns     int            `json:"overruns"`
	KnownReads   int            `json:"known_readings"`
	NullReads    int            `json:"null_readings"`
	Reasons      map[string]int `json:"reasons,omitempty"`
	Details      map[string]int `json:"details,omitempty"`
	MaxQueryMS   float64        `json:"max_query_ms"`
	ProviderBusy bool           `json:"provider_busy_at_end"`
}

// BudgetResult compares measured process cost with the declared budget.
// Process CPU excludes child processes such as nvidia-smi.
type BudgetResult struct {
	WallMS            float64 `json:"wall_ms"`
	CPUTimeMS         float64 `json:"cpu_ms"`
	CPUPercentOneCore float64 `json:"cpu_percent_one_core"`
	RSSPeakBytes      uint64  `json:"rss_peak_bytes"`
	RSSSamples        int     `json:"rss_samples"`
	// RSSPeakAfter names what ran just before the peak sample: a source read,
	// an emit, or start/end. RSSPeakAtMS is that sample's offset into the run.
	RSSPeakAfter    string  `json:"rss_peak_after"`
	RSSPeakAtMS     float64 `json:"rss_peak_at_ms"`
	CPUWithinBudget bool    `json:"cpu_within_budget"`
	RSSWithinBudget bool    `json:"rss_within_budget"`
}

// Within reports whether both limits held.
func (b BudgetResult) Within() bool { return b.CPUWithinBudget && b.RSSWithinBudget }

// SamplingReport records one scheduler run. It has no device identifier.
type SamplingReport struct {
	Schema        string           `json:"schema"`
	Provenance    string           `json:"provenance"`
	Qualification string           `json:"qualification"`
	Host          HostInfo         `json:"host"`
	Config        SamplingConfig   `json:"config"`
	StartedAt     time.Time        `json:"started_at"`
	EndedAt       time.Time        `json:"ended_at"`
	Emits         int              `json:"emits"`
	Sources       []SourceRunStats `json:"sources"`
	Budget        BudgetResult     `json:"budget"`
}

// Scheduler runs Sources on the schedule in Config.
type Scheduler struct {
	Config  SamplingConfig
	Sources []SensorSource
	Usage   func() (ProcessUsage, error)
	Now     func() time.Time
}

// NewScheduler binds cfg to the platform sources.
func NewScheduler(cfg SamplingConfig) Scheduler {
	return Scheduler{Config: cfg, Sources: PlatformSensorSources()}
}

type sourceState struct {
	schedule SourceSchedule
	source   SensorSource
	busy     atomic.Bool
	mu       sync.Mutex
	latest   *SourceResult
	stats    SourceRunStats
}

// Run samples until ctx ends and calls emit with each snapshot. An emit error
// stops the run. Run returns the report when ctx ends; it returns an error
// only for invalid configuration, a usage-sampling failure or an emit error.
func (s Scheduler) Run(ctx context.Context, emit func(SensorSample) error) (SamplingReport, error) {
	if err := s.Config.Validate(); err != nil {
		return SamplingReport{}, err
	}
	now, usage := s.Now, s.Usage
	if now == nil {
		now = time.Now
	}
	if usage == nil {
		usage = SampleProcess
	}
	bySource := map[string]SensorSource{}
	for _, src := range s.Sources {
		bySource[src.Name] = src
	}
	states := make([]*sourceState, 0, len(s.Config.Sources))
	for _, sched := range s.Config.Sources {
		src, ok := bySource[sched.Source]
		if !ok || src.Read == nil {
			return SamplingReport{}, fmt.Errorf("telemetry: scheduled source %s has no reader", sched.Source)
		}
		states = append(states, &sourceState{schedule: sched, source: src, stats: SourceRunStats{
			Source: sched.Source, IntervalMS: time.Duration(sched.Interval).Milliseconds(), DeadlineMS: time.Duration(sched.Deadline).Milliseconds(),
		}})
	}
	meter, err := newUsageMeter(usage)
	if err != nil {
		return SamplingReport{}, err
	}
	report := SamplingReport{
		Schema: SamplingReportSchema, Provenance: ProvenanceEndpointSensor, Qualification: SensorQualificationNone,
		Host: CurrentHost(), Config: s.Config, StartedAt: now().UTC(),
	}
	runCtx, stop := context.WithCancel(ctx)
	defer stop()
	var wg sync.WaitGroup
	for _, st := range states {
		wg.Add(1)
		go func() {
			defer wg.Done()
			st.loop(runCtx, now, meter)
		}()
	}
	emitErr := s.emitLoop(runCtx, states, now, meter, emit, &report.Emits)
	stop()
	wg.Wait()
	if emitErr != nil {
		return SamplingReport{}, emitErr
	}
	report.EndedAt = now().UTC()
	for _, st := range states {
		st.mu.Lock()
		st.stats.ProviderBusy = st.busy.Load()
		report.Sources = append(report.Sources, st.stats)
		st.mu.Unlock()
	}
	report.Budget, err = meter.finish(s.Config.Budget)
	if err != nil {
		return SamplingReport{}, err
	}
	return report, nil
}

// loop reads one source at its own start-to-start interval.
func (st *sourceState) loop(ctx context.Context, now func() time.Time, meter *usageMeter) {
	interval := time.Duration(st.schedule.Interval)
	next := now()
	for {
		result := st.readOnce(ctx, now)
		if ctx.Err() != nil {
			return
		}
		meter.sampleRSS(st.source.Name)
		st.record(result)
		next = next.Add(interval)
		if late := now(); !late.Before(next) {
			st.mu.Lock()
			st.stats.Overruns++
			st.mu.Unlock()
			for !late.Before(next) {
				next = next.Add(interval)
			}
		}
		if sleepContext(ctx, next.Sub(now())) != nil {
			return
		}
	}
}

func (st *sourceState) readOnce(ctx context.Context, now func() time.Time) SourceResult {
	if !st.busy.CompareAndSwap(false, true) {
		st.mu.Lock()
		st.stats.BusySkips++
		st.mu.Unlock()
		return SourceResult{
			Source: st.source.Name, Provenance: ProvenanceEndpointSensor, ObservedAt: now().UTC(), Outcome: "null",
			Readings: nullReadings(st.source, ReasonCollectionError, "provider_busy"),
		}
	}
	return readSource(ctx, st.source, time.Duration(st.schedule.Deadline), now, func() { st.busy.Store(false) })
}

func (st *sourceState) record(result SourceResult) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.latest = &result
	st.stats.Reads++
	if result.QueryMS > st.stats.MaxQueryMS {
		st.stats.MaxQueryMS = result.QueryMS
	}
	for _, r := range result.Readings {
		if r.Value != nil {
			st.stats.KnownReads++
			continue
		}
		st.stats.NullReads++
		if st.stats.Reasons == nil {
			st.stats.Reasons, st.stats.Details = map[string]int{}, map[string]int{}
		}
		st.stats.Reasons[r.MissingReason]++
		if r.Detail != "" {
			st.stats.Details[r.Detail]++
		}
	}
}

// snapshot returns the latest result, or a null when there is none yet or it
// is older than one interval plus the deadline plus one second of slack.
func (st *sourceState) snapshot(at time.Time) SourceResult {
	st.mu.Lock()
	latest := st.latest
	st.mu.Unlock()
	null := func(detail string) SourceResult {
		return SourceResult{Source: st.source.Name, Provenance: ProvenanceEndpointSensor, ObservedAt: at.UTC(), Outcome: "null",
			Readings: nullReadings(st.source, ReasonCollectionError, detail)}
	}
	if latest == nil {
		return null("not_yet_sampled")
	}
	maxAge := time.Duration(st.schedule.Interval) + time.Duration(st.schedule.Deadline) + time.Second
	if at.Sub(latest.ObservedAt) > maxAge {
		return null("stale_result")
	}
	return *latest
}

func (s Scheduler) emitLoop(ctx context.Context, states []*sourceState, now func() time.Time, meter *usageMeter, emit func(SensorSample) error, count *int) error {
	interval := time.Duration(s.Config.EmitInterval)
	next := now().Add(interval)
	for {
		if sleepContext(ctx, next.Sub(now())) != nil {
			return nil
		}
		at := now()
		for !at.Before(next) {
			next = next.Add(interval)
		}
		sample := SensorSample{CollectedAt: at.UTC()}
		for _, st := range states {
			sample.Sources = append(sample.Sources, st.snapshot(at))
		}
		meter.sampleRSS("emit")
		if err := emit(sample); err != nil {
			return err
		}
		*count++
	}
}

// usageMeter tracks this process's CPU over the run and its peak RSS.
type usageMeter struct {
	usage     func() (ProcessUsage, error)
	start     ProcessUsage
	began     time.Time
	mu        sync.Mutex
	peak      uint64
	peakAfter string
	peakAt    time.Duration
	count     int
	err       error
}

func newUsageMeter(usage func() (ProcessUsage, error)) (*usageMeter, error) {
	start, err := usage()
	if err != nil {
		return nil, err
	}
	return &usageMeter{usage: usage, start: start, began: time.Now(), peak: start.RSS, peakAfter: "start", count: 1}, nil
}

func (m *usageMeter) sampleRSS(after string) {
	u, err := m.usage()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.err = err
		return
	}
	m.count++
	m.note(u.RSS, after)
}

// note records rss if it is a new peak. The caller holds mu.
func (m *usageMeter) note(rss uint64, after string) {
	if rss > m.peak {
		m.peak, m.peakAfter, m.peakAt = rss, after, time.Since(m.began)
	}
}

func (m *usageMeter) finish(budget SamplingBudget) (BudgetResult, error) {
	end, err := m.usage()
	wall := time.Since(m.began)
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		err = m.err
	}
	if err != nil {
		return BudgetResult{}, err
	}
	m.count++
	m.note(end.RSS, "end")
	cpu, err := cpuDelta(m.start.CPU, end.CPU)
	if err != nil {
		return BudgetResult{}, err
	}
	result, err := evaluateBudget(budget, cpu, wall, m.peak, m.count)
	result.RSSPeakAfter, result.RSSPeakAtMS = m.peakAfter, ms(m.peakAt)
	return result, err
}

// evaluateBudget turns measured cost into a verdict against the budget.
func evaluateBudget(budget SamplingBudget, cpu, wall time.Duration, peak uint64, samples int) (BudgetResult, error) {
	oneCore, _, err := cpuPercents(cpu, wall, 1)
	if err != nil {
		return BudgetResult{}, err
	}
	return BudgetResult{
		WallMS: ms(wall), CPUTimeMS: ms(cpu), CPUPercentOneCore: oneCore, RSSPeakBytes: peak, RSSSamples: samples,
		CPUWithinBudget: oneCore <= budget.MaxCPUPercentOneCore,
		RSSWithinBudget: peak <= budget.MaxRSSBytes,
	}, nil
}

// MarshalSamplingReport encodes a report, indented.
func MarshalSamplingReport(report SamplingReport) ([]byte, error) {
	if report.Schema != SamplingReportSchema || report.Qualification != SensorQualificationNone {
		return nil, errors.New("telemetry: refusing to encode a report that is not the sampling schema")
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
