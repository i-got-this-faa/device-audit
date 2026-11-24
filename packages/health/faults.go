package health

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// ML10 #106: fault type, count and recurrence against bounded history.
const (
	// FaultCurrentDays is the current window: the seven UTC days ending on the
	// day of asOf, the same days as the CT03 feature window.
	FaultCurrentDays = contracts.FeatureWindowDays
	// FaultBaselineDays is the history window immediately before the current
	// one. Both together are 28 days, inside the 31-day history read bound.
	FaultBaselineDays = 21
)

// FaultRecurrence classifies one fault type. It is never a health state.
type FaultRecurrence string

const (
	// FaultRecurrent: reported on two or more UTC days of the current window,
	// or reported in the current window and in the baseline.
	FaultRecurrent FaultRecurrence = "recurrent"
	// FaultIsolated: one UTC day of reports in the current window, none in the
	// baseline, and both windows are sufficiently sampled.
	FaultIsolated FaultRecurrence = "isolated"
	// FaultBaselineOnly: reported in the baseline, not in a sufficiently
	// sampled current window.
	FaultBaselineOnly FaultRecurrence = "baseline_only"
	// FaultInsufficientHistory: the sampled days cannot separate the other
	// classes. Missing history is never read as an absence of faults.
	FaultInsufficientHistory FaultRecurrence = "insufficient_history"
)

// FaultCountChange compares the current report rate with the baseline rate.
type FaultCountChange string

const (
	FaultCountIncreased FaultCountChange = "increased"
	FaultCountUnchanged FaultCountChange = "unchanged"
	FaultCountDecreased FaultCountChange = "decreased"
	// FaultCountUnknown: either window is insufficiently sampled.
	FaultCountUnknown FaultCountChange = "unknown"
)

// FaultReport is one fault reported by one persisted sample. EvidenceSHA256
// identifies the reported evidence; a second report of the same digest is a
// duplicate, not a second fault.
type FaultReport struct {
	Type           string
	ReportedAt     time.Time
	EvidenceSHA256 string
	// Sequence is the evidence sequence of the sample that carried the report.
	Sequence uint64
}

// FaultEvidence is what a device's persisted samples held over both windows.
// SampleDays are the UTC days with at least one sample, whether or not it
// reported a fault: a day without a sample is unobserved, not fault-free.
type FaultEvidence struct {
	SampleDays []time.Time
	Reports    []FaultReport
}

// FaultWindow is one bounded window, from <= t < to, and how much of it was sampled.
type FaultWindow struct {
	From, To    time.Time
	Days        int
	SampledDays int
	// Sufficient means at least two thirds of the window's UTC days were sampled.
	Sufficient bool
}

// FaultComparison is one fault type across both windows. Report counts exclude
// duplicates; days are distinct UTC days with a report.
type FaultComparison struct {
	Type             string
	Recurrence       FaultRecurrence
	CountChange      FaultCountChange
	CurrentReports   int
	BaselineReports  int
	CurrentDays      int
	BaselineDays     int
	DuplicateReports int
	// Evidence is every distinct report, ordered by time and sequence.
	Evidence []FaultReport
}

// FaultHistory is the comparison for one device at asOf. Faults is sorted by
// type. An empty Faults with an insufficient window is not a healthy baseline.
type FaultHistory struct {
	AsOf     time.Time
	Current  FaultWindow
	Baseline FaultWindow
	Faults   []FaultComparison
}

var faultTypePattern = regexp.MustCompile(contracts.OpaqueIDPattern)
var faultDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// FaultWindows returns the current and baseline windows for asOf. The current
// window ends just after asOf, so a report collected later is never read.
func FaultWindows(asOf time.Time) (current, baseline FaultWindow) {
	asOf = asOf.UTC()
	day := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	current.From = day.AddDate(0, 0, -(FaultCurrentDays - 1))
	current.To = asOf.Truncate(time.Microsecond).Add(time.Microsecond)
	current.Days = FaultCurrentDays
	baseline.From = current.From.AddDate(0, 0, -FaultBaselineDays)
	baseline.To = current.From
	baseline.Days = FaultBaselineDays
	return current, baseline
}

// CompareFaultHistory classifies each reported fault type. It returns an error
// for a report or sample day outside both windows, a malformed report, a report
// on a day with no sample, or one digest reported under two types.
func CompareFaultHistory(asOf time.Time, evidence FaultEvidence) (FaultHistory, error) {
	current, baseline := FaultWindows(asOf)
	in := func(w FaultWindow, t time.Time) bool { return !t.Before(w.From) && t.Before(w.To) }
	utcDay := func(t time.Time) time.Time { return t.UTC().Truncate(24 * time.Hour) }

	sampled := map[time.Time]bool{}
	for _, at := range evidence.SampleDays {
		day := utcDay(at)
		if day.Before(baseline.From) || !day.Before(current.To) {
			return FaultHistory{}, fmt.Errorf("sample day %s is outside the fault windows", day.Format(time.DateOnly))
		}
		sampled[day] = true
	}
	for day := range sampled {
		if !day.Before(current.From) {
			current.SampledDays++
		} else {
			baseline.SampledDays++
		}
	}
	current.Sufficient = current.SampledDays*3 >= current.Days*2
	baseline.Sufficient = baseline.SampledDays*3 >= baseline.Days*2

	reports := slices.Clone(evidence.Reports)
	slices.SortStableFunc(reports, func(a, b FaultReport) int {
		return cmp.Or(a.ReportedAt.Compare(b.ReportedAt), cmp.Compare(a.Sequence, b.Sequence))
	})
	type tally struct {
		comparison                FaultComparison
		currentDays, baselineDays map[time.Time]bool
	}
	byType := map[string]*tally{}
	typeOf := map[string]string{}
	for _, r := range reports {
		if !faultTypePattern.MatchString(r.Type) || !faultDigestPattern.MatchString(r.EvidenceSHA256) || r.ReportedAt.IsZero() {
			return FaultHistory{}, fmt.Errorf("invalid fault report from sequence %d", r.Sequence)
		}
		inCurrent := in(current, r.ReportedAt)
		if !inCurrent && !in(baseline, r.ReportedAt) {
			return FaultHistory{}, fmt.Errorf("fault report from sequence %d is outside the fault windows", r.Sequence)
		}
		day := utcDay(r.ReportedAt)
		if !sampled[day] {
			return FaultHistory{}, fmt.Errorf("fault report from sequence %d is on a day with no sample", r.Sequence)
		}
		t := byType[r.Type]
		if t == nil {
			t = &tally{comparison: FaultComparison{Type: r.Type}, currentDays: map[time.Time]bool{}, baselineDays: map[time.Time]bool{}}
			byType[r.Type] = t
		}
		if seen, ok := typeOf[r.EvidenceSHA256]; ok {
			if seen != r.Type {
				return FaultHistory{}, fmt.Errorf("evidence %s is reported as both %s and %s", r.EvidenceSHA256, seen, r.Type)
			}
			t.comparison.DuplicateReports++
			continue
		}
		typeOf[r.EvidenceSHA256] = r.Type
		r.ReportedAt = r.ReportedAt.UTC()
		t.comparison.Evidence = append(t.comparison.Evidence, r)
		if inCurrent {
			t.comparison.CurrentReports++
			t.currentDays[day] = true
		} else {
			t.comparison.BaselineReports++
			t.baselineDays[day] = true
		}
	}

	history := FaultHistory{AsOf: asOf.UTC(), Current: current, Baseline: baseline, Faults: make([]FaultComparison, 0, len(byType))}
	for _, t := range byType {
		c := t.comparison
		c.CurrentDays, c.BaselineDays = len(t.currentDays), len(t.baselineDays)
		c.Recurrence = classifyFault(c, current.Sufficient, baseline.Sufficient)
		c.CountChange = FaultCountUnknown
		if current.Sufficient && baseline.Sufficient {
			// Rates per day, cross-multiplied to stay in integers.
			c.CountChange = [...]FaultCountChange{FaultCountDecreased, FaultCountUnchanged, FaultCountIncreased}[1+cmp.Compare(c.CurrentReports*baseline.Days, c.BaselineReports*current.Days)]
		}
		history.Faults = append(history.Faults, c)
	}
	slices.SortFunc(history.Faults, func(a, b FaultComparison) int { return cmp.Compare(a.Type, b.Type) })
	return history, nil
}

func classifyFault(c FaultComparison, currentSufficient, baselineSufficient bool) FaultRecurrence {
	switch {
	case c.CurrentDays >= 2, c.CurrentReports > 0 && c.BaselineReports > 0:
		return FaultRecurrent
	case c.CurrentReports > 0 && currentSufficient && baselineSufficient:
		return FaultIsolated
	case c.CurrentReports == 0 && currentSufficient:
		return FaultBaselineOnly
	default:
		return FaultInsufficientHistory
	}
}
