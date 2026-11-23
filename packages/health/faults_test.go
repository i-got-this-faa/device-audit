package health

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// faultAsOf is a Wednesday afternoon. The current window is 18-24 November,
// the baseline 28 October-17 November.
var faultAsOf = time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)

func faultDay(offset int) time.Time {
	return time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC).AddDate(0, 0, offset)
}

func digest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// sampledDays returns one sample time per day for offsets in [from, to].
func sampledDays(from, to int) []time.Time {
	var days []time.Time
	for offset := from; offset <= to; offset++ {
		days = append(days, faultDay(offset))
	}
	return days
}

func report(kind string, offset int, label string, sequence uint64) FaultReport {
	return FaultReport{Type: kind, ReportedAt: faultDay(offset), EvidenceSHA256: digest(label), Sequence: sequence}
}

func compareFaults(t *testing.T, evidence FaultEvidence) FaultHistory {
	t.Helper()
	history, err := CompareFaultHistory(faultAsOf, evidence)
	if err != nil {
		t.Fatal(err)
	}
	return history
}

func faultFor(t *testing.T, history FaultHistory, kind string) FaultComparison {
	t.Helper()
	for _, f := range history.Faults {
		if f.Type == kind {
			return f
		}
	}
	t.Fatalf("no comparison for %s in %+v", kind, history.Faults)
	return FaultComparison{}
}

func TestFaultWindowsAreBoundedAndAdjacent(t *testing.T) {
	current, baseline := FaultWindows(faultAsOf)
	if want := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC); !current.From.Equal(want) || !baseline.To.Equal(want) {
		t.Fatalf("current from %s, baseline to %s", current.From, baseline.To)
	}
	if want := time.Date(2026, 10, 28, 0, 0, 0, 0, time.UTC); !baseline.From.Equal(want) {
		t.Fatalf("baseline from %s", baseline.From)
	}
	if !current.To.Equal(faultAsOf.Add(time.Microsecond)) {
		t.Fatalf("current to %s", current.To)
	}
	if current.To.Sub(baseline.From) > 31*24*time.Hour {
		t.Fatal("fault windows exceed the history read bound")
	}
}

func TestCompareFaultHistoryClassifiesRecurrence(t *testing.T) {
	fullHistory := sampledDays(-27, 0)
	cases := []struct {
		name       string
		days       []time.Time
		reports    []FaultReport
		recurrence FaultRecurrence
		change     FaultCountChange
		current    int
		baseline   int
	}{
		{"two current days", fullHistory, []FaultReport{report("storage", -3, "a", 10), report("storage", -1, "b", 20)}, FaultRecurrent, FaultCountIncreased, 2, 0},
		{"current and baseline", fullHistory, []FaultReport{report("storage", -20, "a", 10), report("storage", -1, "b", 20)}, FaultRecurrent, FaultCountIncreased, 1, 1},
		// A burst on one day is counted, but it is one day, not recurrence.
		{"burst on one day", fullHistory, []FaultReport{report("storage", -1, "a", 10), report("storage", -1, "b", 11), report("storage", -1, "c", 12)}, FaultIsolated, FaultCountIncreased, 3, 0},
		{"isolated incident", fullHistory, []FaultReport{report("thermal", -2, "a", 10)}, FaultIsolated, FaultCountIncreased, 1, 0},
		{"baseline only", fullHistory, []FaultReport{report("thermal", -15, "a", 10)}, FaultBaselineOnly, FaultCountDecreased, 0, 1},
		// Three baseline reports in 21 days is the same rate as one in seven.
		{"steady rate", fullHistory, []FaultReport{report("thermal", -25, "a", 1), report("thermal", -16, "b", 2), report("thermal", -9, "c", 3), report("thermal", -2, "d", 4)}, FaultRecurrent, FaultCountUnchanged, 1, 3},
		// No baseline samples: one report cannot be called isolated.
		{"no history", sampledDays(-6, 0), []FaultReport{report("storage", -1, "a", 10)}, FaultInsufficientHistory, FaultCountUnknown, 1, 0},
		// Thirteen of 21 baseline days is under two thirds.
		{"thin history", sampledDays(-19, 0), []FaultReport{report("storage", -1, "a", 10)}, FaultInsufficientHistory, FaultCountUnknown, 1, 0},
		// Recurrence inside the current window needs no baseline.
		{"recurrent without history", sampledDays(-6, 0), []FaultReport{report("storage", -3, "a", 10), report("storage", -1, "b", 20)}, FaultRecurrent, FaultCountUnknown, 2, 0},
		// The current window is mostly unsampled, so absence there is unknown.
		{"baseline report, unsampled present", sampledDays(-27, -7), []FaultReport{report("thermal", -15, "a", 10)}, FaultInsufficientHistory, FaultCountUnknown, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			history := compareFaults(t, FaultEvidence{SampleDays: tc.days, Reports: tc.reports})
			if len(history.Faults) != 1 {
				t.Fatalf("faults = %+v", history.Faults)
			}
			f := history.Faults[0]
			if f.Recurrence != tc.recurrence || f.CountChange != tc.change || f.CurrentReports != tc.current || f.BaselineReports != tc.baseline {
				t.Fatalf("got %s/%s current=%d baseline=%d, want %s/%s %d/%d", f.Recurrence, f.CountChange, f.CurrentReports, f.BaselineReports, tc.recurrence, tc.change, tc.current, tc.baseline)
			}
		})
	}
}

func TestCompareFaultHistoryCountsDuplicateReportsOnce(t *testing.T) {
	// The same evidence re-sent by three later samples is one isolated fault.
	history := compareFaults(t, FaultEvidence{SampleDays: sampledDays(-27, 0), Reports: []FaultReport{
		report("storage", 0, "same", 30), report("storage", -2, "same", 12), report("storage", -1, "same", 20),
	}})
	f := faultFor(t, history, "storage")
	if f.Recurrence != FaultIsolated || f.CurrentReports != 1 || f.CurrentDays != 1 || f.DuplicateReports != 2 {
		t.Fatalf("duplicates were counted as faults: %+v", f)
	}
	// The earliest report is kept as the evidence.
	if len(f.Evidence) != 1 || f.Evidence[0].Sequence != 12 {
		t.Fatalf("evidence = %+v", f.Evidence)
	}
}

func TestCompareFaultHistoryKeepsTypesApart(t *testing.T) {
	history := compareFaults(t, FaultEvidence{SampleDays: sampledDays(-27, 0), Reports: []FaultReport{
		report("thermal", -1, "t", 3), report("storage", -20, "s1", 1), report("storage", -1, "s2", 2),
	}})
	if len(history.Faults) != 2 || history.Faults[0].Type != "storage" || history.Faults[1].Type != "thermal" {
		t.Fatalf("faults = %+v", history.Faults)
	}
	if history.Faults[0].Recurrence != FaultRecurrent || history.Faults[1].Recurrence != FaultIsolated {
		t.Fatalf("one type's history leaked into another: %+v", history.Faults)
	}
}

func TestCompareFaultHistoryNoFaultsIsNotAHealthyBaseline(t *testing.T) {
	// Without samples there are no faults, but neither window is sufficient.
	empty := compareFaults(t, FaultEvidence{})
	if len(empty.Faults) != 0 || empty.Current.Sufficient || empty.Baseline.Sufficient || empty.Current.SampledDays != 0 {
		t.Fatalf("missing history read as complete: %+v", empty)
	}
	full := compareFaults(t, FaultEvidence{SampleDays: sampledDays(-27, 0)})
	if !full.Current.Sufficient || !full.Baseline.Sufficient || full.Current.SampledDays != 7 || full.Baseline.SampledDays != 21 {
		t.Fatalf("sampled windows = %+v / %+v", full.Current, full.Baseline)
	}
}

func TestCompareFaultHistoryRejectsInconsistentEvidence(t *testing.T) {
	days := sampledDays(-27, 0)
	cases := map[string]FaultEvidence{
		"report after asOf":       {SampleDays: days, Reports: []FaultReport{{Type: "storage", ReportedAt: faultAsOf.Add(time.Second), EvidenceSHA256: digest("a"), Sequence: 2}}},
		"report before baseline":  {SampleDays: days, Reports: []FaultReport{report("storage", -28, "a", 2)}},
		"sample before baseline":  {SampleDays: append(days, faultDay(-28))},
		"report on unsampled day": {SampleDays: sampledDays(-27, -2), Reports: []FaultReport{report("storage", -1, "a", 2)}},
		"one digest, two types":   {SampleDays: days, Reports: []FaultReport{report("storage", -2, "a", 2), report("thermal", -1, "a", 3)}},
		"uppercase digest":        {SampleDays: days, Reports: []FaultReport{{Type: "storage", ReportedAt: faultDay(-1), EvidenceSHA256: strings.ToUpper(digest("a")), Sequence: 2}}},
		"invalid type":            {SampleDays: days, Reports: []FaultReport{report("bad type", -1, "a", 2)}},
	}
	for name, evidence := range cases {
		if _, err := CompareFaultHistory(faultAsOf, evidence); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
