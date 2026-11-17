package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

const (
	// ReportSchema identifies harness output. It is not telemetry v1 or v2.
	ReportSchema = "device-audit.collector-budget.harness.v1"
	// ProvenanceHarness marks synthetic work. It is not a Windows sensor reading.
	ProvenanceHarness = "harness_synthetic"
	// QualificationNotService is the only qualification label this harness emits.
	QualificationNotService = "not_windows_service_or_physical_target"
)

// SampleResult is the value a source function measured. A nil Value is not a zero.
type SampleResult struct {
	Metric string
	Unit   string
	Value  *float64
}

// SourceFunc reads one source. The runner supplies a deadline context.
type SourceFunc func(context.Context) (SampleResult, error)

// BoundSource is a catalog source plus the function that reads it.
// Provenance "real" and "endpoint" are rejected so this runner cannot relabel
// synthetic or fixture work as a device reading.
type BoundSource struct {
	Spec       SourceSpec
	Sample     SourceFunc
	Provenance string
}

// Runner measures permission checks, cadence and this process's overhead.
type Runner struct {
	Cadence  Cadence
	Repeats  int
	Baseline time.Duration
	Token    Token
	Sources  []BoundSource
	Now      func() time.Time
	Sleep    func(time.Duration)
	Usage    func() (ProcessUsage, error)
}

// Report is the harness record. It contains no hostname, serial or device ID.
type Report struct {
	Schema                 string             `json:"schema"`
	Provenance             string             `json:"provenance"`
	Qualification          string             `json:"qualification"`
	ServiceAccessQualified bool               `json:"service_access_qualified"`
	CandidateCadence       bool               `json:"candidate_cadence"`
	Host                   HostInfo           `json:"host"`
	IntervalMS             int64              `json:"interval_ms"`
	Samples                int                `json:"samples"`
	Repeats                int                `json:"repeats"`
	BaselineMS             int64              `json:"baseline_ms"`
	WorkerDeadlineMS       int64              `json:"worker_deadline_ms"`
	RunToken               string             `json:"run_token"`
	Access                 []AccessComparison `json:"access"`
	Windows                []WindowResult     `json:"windows"`
	Summary                Summary            `json:"summary"`
	Recommendation         Recommendation     `json:"recommendation"`
}

// WindowResult is one baseline or probe interval. RSS fields describe this
// process. rss_peak_bytes is the maximum sample, not the sum of samples.
type WindowResult struct {
	Kind              string             `json:"kind"`
	Repeat            int                `json:"repeat"`
	WallMS            float64            `json:"wall_ms"`
	CPUTimeMS         float64            `json:"cpu_ms"`
	CoreCount         int                `json:"core_count"`
	CPUPercentOneCore float64            `json:"cpu_percent_one_core"`
	CPUPercentMachine float64            `json:"cpu_percent_machine"`
	RSSStartBytes     uint64             `json:"rss_start_bytes"`
	RSSEndBytes       uint64             `json:"rss_end_bytes"`
	RSSPeakBytes      uint64             `json:"rss_peak_bytes"`
	RSSSamplesBytes   []uint64           `json:"rss_samples_bytes"`
	HeapAllocEndBytes uint64             `json:"heap_alloc_end_bytes"`
	Sweeps            []SweepObservation `json:"sweeps,omitempty"`
}

// SweepObservation is one start-to-start sample. CPU excludes the wait before it.
type SweepObservation struct {
	Index     int                 `json:"index"`
	Overrun   bool                `json:"overrun"`
	WallMS    float64             `json:"wall_ms"`
	CPUTimeMS float64             `json:"cpu_ms"`
	RSSBytes  uint64              `json:"rss_bytes"`
	Sources   []SourceObservation `json:"sources"`
}

// SourceObservation is one source inside a sweep. Invoked is false when the
// permission gate denies the source before calling it.
type SourceObservation struct {
	Source     string   `json:"source"`
	Metric     string   `json:"metric"`
	Unit       string   `json:"unit"`
	Provenance string   `json:"provenance"`
	Outcome    string   `json:"outcome"`
	Value      *float64 `json:"value"`
	QueryMS    float64  `json:"query_ms"`
	Invoked    bool     `json:"invoked"`
}

// Summary aggregates probe windows. ProductionBudgetApproved is always false.
type Summary struct {
	Sweeps                     int     `json:"sweeps"`
	Overruns                   int     `json:"overruns"`
	Succeeded                  int     `json:"succeeded"`
	PermissionDenied           int     `json:"permission_denied"`
	TimedOut                   int     `json:"timed_out"`
	CollectionErrors           int     `json:"collection_errors"`
	MaxQueryMS                 float64 `json:"max_query_ms"`
	RSSPeakBytes               uint64  `json:"rss_peak_bytes"`
	RSSSteadyBytes             uint64  `json:"rss_steady_bytes"`
	BaselineCPUPercentOneCore  float64 `json:"baseline_cpu_percent_one_core_mean"`
	ProbeCPUPercentOneCore     float64 `json:"probe_cpu_percent_one_core_mean"`
	ProbeCPUPercentOneCoreMax  float64 `json:"probe_cpu_percent_one_core_max"`
	ProbeCPUPercentMachineMean float64 `json:"probe_cpu_percent_machine_mean"`
	CPUDeltaOneCoreMean        float64 `json:"cpu_delta_one_core_mean"`
}

// Recommendation is a harness ceiling derived from this run. It does not approve
// a Windows collector budget.
type Recommendation struct {
	Status                      string  `json:"status"`
	AppliesTo                   string  `json:"applies_to"`
	CandidateCadenceMS          []int64 `json:"candidate_cadence_ms"`
	ObservedMaxQueryMS          float64 `json:"observed_max_query_ms"`
	RecommendedWorkerDeadlineMS int64   `json:"recommended_worker_deadline_ms"`
	ObservedRSSPeakBytes        uint64  `json:"observed_rss_peak_bytes"`
	ProductionBudgetApproved    bool    `json:"production_budget_approved"`
	Reason                      string  `json:"reason"`
}

// Measure runs repeated baseline and probe windows. A denied or timed-out source
// does not skip later sources. Overrun sweeps are not followed by catch-up sweeps.
func (r Runner) Measure(ctx context.Context) (Report, error) {
	if err := r.prepare(); err != nil {
		return Report{}, err
	}
	access, err := Compare(PlanningToken(), DeniedToken())
	if err != nil {
		return Report{}, err
	}
	report := Report{
		Schema:                 ReportSchema,
		Provenance:             ProvenanceHarness,
		Qualification:          QualificationNotService,
		ServiceAccessQualified: QualifiesServiceAccess(r.Token, DeniedToken(), 0),
		CandidateCadence:       r.Cadence.IsCandidate(),
		Host:                   CurrentHost(),
		IntervalMS:             r.Cadence.Interval.Milliseconds(),
		Samples:                r.Cadence.Samples,
		Repeats:                r.Repeats,
		BaselineMS:             r.Baseline.Milliseconds(),
		WorkerDeadlineMS:       r.Cadence.WorkerDeadline.Milliseconds(),
		RunToken:               r.Token.Name,
		Access:                 access,
	}
	for repeat := 0; repeat < r.Repeats; repeat++ {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		baseline, err := r.measureIdle(ctx, repeat)
		if err != nil {
			return Report{}, err
		}
		probe, err := r.measureProbe(ctx, repeat)
		if err != nil {
			return Report{}, err
		}
		report.Windows = append(report.Windows, baseline, probe)
	}
	report.Summary = summarize(report.Windows)
	report.Recommendation = recommend(report.Summary.MaxQueryMS, report.Summary.RSSPeakBytes)
	if report.ServiceAccessQualified || report.Recommendation.ProductionBudgetApproved {
		return Report{}, errors.New("telemetry: harness report claimed a qualification it cannot make")
	}
	return report, nil
}

func (r *Runner) prepare() error {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Sleep == nil {
		r.Sleep = time.Sleep
	}
	if r.Usage == nil {
		r.Usage = SampleProcess
	}
	if err := r.Cadence.Validate(); err != nil {
		return err
	}
	if r.Repeats < 1 || r.Repeats > MaxRepeats {
		return fmt.Errorf("telemetry: repeats must be from 1 to %d", MaxRepeats)
	}
	if r.Baseline < 0 || r.Baseline > MaxBaseline {
		return fmt.Errorf("telemetry: baseline must be from 0 to %s", MaxBaseline)
	}
	if err := r.Token.Validate(); err != nil {
		return err
	}
	if len(r.Sources) == 0 {
		return errors.New("telemetry: at least one source is required")
	}
	catalog := map[string]SourceSpec{}
	for _, spec := range Catalog() {
		catalog[spec.Source] = spec
	}
	seen := map[string]bool{}
	for _, src := range r.Sources {
		if seen[src.Spec.Source] {
			return fmt.Errorf("telemetry: duplicate source %s", src.Spec.Source)
		}
		seen[src.Spec.Source] = true
		spec, ok := catalog[src.Spec.Source]
		if !ok || spec.Metric != src.Spec.Metric || spec.Unit != src.Spec.Unit || spec.Provider != src.Spec.Provider {
			return fmt.Errorf("telemetry: source %s is not the fixed catalog entry", src.Spec.Source)
		}
		if !slices.Equal(spec.Required, src.Spec.Required) || spec.Nullable != src.Spec.Nullable {
			return fmt.Errorf("telemetry: source %s does not match the catalog permission", src.Spec.Source)
		}
		if src.Provenance == "" || src.Provenance == "real" || src.Provenance == "endpoint" {
			return fmt.Errorf("telemetry: source %s provenance cannot be empty, real or endpoint", src.Spec.Source)
		}
		if src.Sample == nil {
			return fmt.Errorf("telemetry: source %s is missing a sample function", src.Spec.Source)
		}
	}
	return nil
}

func (r Runner) measureIdle(ctx context.Context, repeat int) (WindowResult, error) {
	startUse, err := r.Usage()
	if err != nil {
		return WindowResult{}, err
	}
	start := r.Now()
	if r.Baseline > 0 {
		r.Sleep(r.Baseline)
	}
	if err := ctx.Err(); err != nil {
		return WindowResult{}, err
	}
	end := r.Now()
	endUse, err := r.Usage()
	if err != nil {
		return WindowResult{}, err
	}
	wall := end.Sub(start)
	if r.Baseline == 0 {
		wall = 0
	}
	return finishWindow("baseline", repeat, wall, startUse, endUse, []uint64{startUse.RSS, endUse.RSS}, nil)
}

func (r Runner) measureProbe(ctx context.Context, repeat int) (WindowResult, error) {
	startUse, err := r.Usage()
	if err != nil {
		return WindowResult{}, err
	}
	origin := r.Now()
	samples := []uint64{startUse.RSS}
	var sweeps []SweepObservation
	for index := 0; index < r.Cadence.Samples; index++ {
		if err := ctx.Err(); err != nil {
			return WindowResult{}, err
		}
		sweepStart := r.Now()
		sweepUse, err := r.Usage()
		if err != nil {
			return WindowResult{}, err
		}
		observations := make([]SourceObservation, 0, len(r.Sources))
		for _, src := range r.Sources {
			if err := ctx.Err(); err != nil {
				return WindowResult{}, err
			}
			obs, err := r.observe(ctx, src)
			if err != nil {
				return WindowResult{}, err
			}
			observations = append(observations, obs)
			use, err := r.Usage()
			if err != nil {
				return WindowResult{}, err
			}
			samples = append(samples, use.RSS)
		}
		sweepEnd := r.Now()
		sweepEndUse, err := r.Usage()
		if err != nil {
			return WindowResult{}, err
		}
		samples = append(samples, sweepEndUse.RSS)
		wall := sweepEnd.Sub(sweepStart)
		cpu, err := cpuDelta(sweepUse.CPU, sweepEndUse.CPU)
		if err != nil {
			return WindowResult{}, err
		}
		// Match the Windows probe: one sweep per index, overrun when that sweep
		// exceeds the interval, and no extra sweep is inserted to catch up.
		sweeps = append(sweeps, SweepObservation{
			Index:     index,
			Overrun:   wall > r.Cadence.Interval,
			WallMS:    ms(wall),
			CPUTimeMS: ms(cpu),
			RSSBytes:  sweepEndUse.RSS,
			Sources:   observations,
		})
		if index < r.Cadence.Samples-1 && wall < r.Cadence.Interval {
			r.Sleep(r.Cadence.Interval - wall)
		}
	}
	end := r.Now()
	endUse, err := r.Usage()
	if err != nil {
		return WindowResult{}, err
	}
	samples = append(samples, endUse.RSS)
	return finishWindow("probe", repeat, end.Sub(origin), startUse, endUse, samples, sweeps)
}

func (r Runner) observe(ctx context.Context, src BoundSource) (SourceObservation, error) {
	obs := SourceObservation{
		Source:     src.Spec.Source,
		Metric:     src.Spec.Metric,
		Unit:       src.Spec.Unit,
		Provenance: "not_read",
		Value:      nil,
	}
	if err := r.Token.Allows(src.Spec); err != nil {
		if errors.Is(err, ErrPermissionDenied) {
			obs.Outcome = "permission_denied"
			return obs, nil
		}
		return SourceObservation{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, r.Cadence.WorkerDeadline)
	defer cancel()
	start := r.Now()
	result, err := src.Sample(ctx)
	elapsed := r.Now().Sub(start)
	obs.Invoked = true
	obs.QueryMS = ms(elapsed)
	obs.Provenance = src.Provenance
	if err != nil {
		obs.Value = nil
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
			obs.Outcome = "timeout"
			obs.Metric = src.Spec.Metric
			obs.Unit = src.Spec.Unit
			return obs, nil
		}
		if errors.Is(err, context.Canceled) {
			return SourceObservation{}, err
		}
		obs.Outcome = "collection_error"
		obs.Metric = src.Spec.Metric
		obs.Unit = src.Spec.Unit
		return obs, nil
	}
	if result.Value == nil || result.Metric == "" || result.Unit == "" {
		obs.Outcome = "collection_error"
		obs.Value = nil
		obs.Metric = src.Spec.Metric
		obs.Unit = src.Spec.Unit
		return obs, nil
	}
	obs.Outcome = "success"
	obs.Metric = result.Metric
	obs.Unit = result.Unit
	obs.Value = result.Value
	return obs, nil
}

func finishWindow(kind string, repeat int, wall time.Duration, start, end ProcessUsage, samples []uint64, sweeps []SweepObservation) (WindowResult, error) {
	if start.CoreCount != end.CoreCount || start.CoreCount < 1 {
		return WindowResult{}, errors.New("telemetry: core count changed or is missing")
	}
	cpu, err := cpuDelta(start.CPU, end.CPU)
	if err != nil {
		return WindowResult{}, err
	}
	peak := maxUint(samples)
	window := WindowResult{
		Kind:              kind,
		Repeat:            repeat,
		WallMS:            ms(wall),
		CPUTimeMS:         ms(cpu),
		CoreCount:         start.CoreCount,
		RSSStartBytes:     start.RSS,
		RSSEndBytes:       end.RSS,
		RSSPeakBytes:      peak,
		RSSSamplesBytes:   samples,
		HeapAllocEndBytes: end.HeapAlloc,
		Sweeps:            sweeps,
	}
	// A zero baseline is an empty interval, so it has no CPU rate. A probe that
	// finishes before the OS clock moves can be recorded only when the process
	// CPU counter also stayed still. CPU without wall time cannot be a percent.
	if wall == 0 && (kind == "baseline" || cpu == 0) {
		window.CPUPercentOneCore = 0
		window.CPUPercentMachine = 0
		return window, nil
	}
	one, machine, err := cpuPercents(cpu, wall, start.CoreCount)
	if err != nil {
		return WindowResult{}, err
	}
	window.CPUPercentOneCore = one
	window.CPUPercentMachine = machine
	return window, nil
}

func summarize(windows []WindowResult) Summary {
	var summary Summary
	var baseSum, probeSum float64
	var baseN, probeN int
	var steady uint64
	for _, window := range windows {
		if window.Kind == "baseline" {
			baseSum += window.CPUPercentOneCore
			baseN++
			continue
		}
		probeSum += window.CPUPercentOneCore
		probeN++
		if window.CPUPercentOneCore > summary.ProbeCPUPercentOneCoreMax {
			summary.ProbeCPUPercentOneCoreMax = window.CPUPercentOneCore
		}
		summary.ProbeCPUPercentMachineMean += window.CPUPercentMachine
		if window.RSSPeakBytes > summary.RSSPeakBytes {
			summary.RSSPeakBytes = window.RSSPeakBytes
		}
		steady = window.RSSEndBytes
		for _, sweep := range window.Sweeps {
			summary.Sweeps++
			if sweep.Overrun {
				summary.Overruns++
			}
			for _, src := range sweep.Sources {
				switch src.Outcome {
				case "success":
					summary.Succeeded++
				case "permission_denied":
					summary.PermissionDenied++
				case "timeout":
					summary.TimedOut++
				default:
					summary.CollectionErrors++
				}
				if src.Invoked && src.QueryMS > summary.MaxQueryMS {
					summary.MaxQueryMS = src.QueryMS
				}
			}
		}
	}
	if baseN > 0 {
		summary.BaselineCPUPercentOneCore = baseSum / float64(baseN)
	}
	if probeN > 0 {
		summary.ProbeCPUPercentOneCore = probeSum / float64(probeN)
		summary.ProbeCPUPercentMachineMean = summary.ProbeCPUPercentMachineMean / float64(probeN)
	}
	summary.CPUDeltaOneCoreMean = summary.ProbeCPUPercentOneCore - summary.BaselineCPUPercentOneCore
	summary.RSSSteadyBytes = steady
	return summary
}

// recommendDeadline scales the longest observed query by ten and clamps it to
// the probe default floor and the 30-second probe ceiling.
func recommendDeadline(maxQuery time.Duration) time.Duration {
	deadline := maxQuery * 10
	if deadline < DefaultWorkerDeadline {
		deadline = DefaultWorkerDeadline
	}
	if deadline > MaxWorkerDeadline {
		deadline = MaxWorkerDeadline
	}
	return deadline
}

func recommend(maxQueryMS float64, rssPeak uint64) Recommendation {
	maxQuery := time.Duration(maxQueryMS * float64(time.Millisecond))
	deadline := recommendDeadline(maxQuery)
	return Recommendation{
		Status:                      "not_approved",
		AppliesTo:                   ProvenanceHarness,
		CandidateCadenceMS:          []int64{CandidateFast.Milliseconds(), CandidateSlow.Milliseconds()},
		ObservedMaxQueryMS:          maxQueryMS,
		RecommendedWorkerDeadlineMS: deadline.Milliseconds(),
		ObservedRSSPeakBytes:        rssPeak,
		ProductionBudgetApproved:    false,
		Reason:                      "Synthetic sampler cost on this host. Provider-host CPU, LocalService and denied tokens, and both physical Windows machines are not in this run. No production cadence or memory budget is approved.",
	}
}

func ms(d time.Duration) float64 {
	return float64(d) / float64(time.Millisecond)
}

func maxUint(values []uint64) uint64 {
	var peak uint64
	for _, value := range values {
		if value > peak {
			peak = value
		}
	}
	return peak
}

// MarshalReport encodes a report without HTML escaping. The result is indented.
func MarshalReport(report Report) ([]byte, error) {
	if report.Schema != ReportSchema || report.Provenance != ProvenanceHarness || report.Qualification != QualificationNotService {
		return nil, errors.New("telemetry: refusing to encode a report that is not the harness schema")
	}
	if report.ServiceAccessQualified || report.Recommendation.ProductionBudgetApproved {
		return nil, errors.New("telemetry: refusing to encode an approved production budget")
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
