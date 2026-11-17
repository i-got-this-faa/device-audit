package telemetry

import (
	"testing"
	"time"
)

func TestCandidateCadences(t *testing.T) {
	fast := Cadence{Interval: CandidateFast, Samples: 30, WorkerDeadline: DefaultWorkerDeadline}
	slow := Cadence{Interval: CandidateSlow, Samples: 1, WorkerDeadline: MaxWorkerDeadline}
	if err := fast.Validate(); err != nil || !fast.IsCandidate() {
		t.Fatal(err)
	}
	if err := slow.Validate(); err != nil || !slow.IsCandidate() {
		t.Fatal(err)
	}
	short := Cadence{Interval: 20 * time.Millisecond, Samples: 2, WorkerDeadline: time.Second}
	if err := short.Validate(); err != nil {
		t.Fatal(err)
	}
	if short.IsCandidate() {
		t.Fatal("20ms was treated as a candidate cadence")
	}
}

func TestCadenceBounds(t *testing.T) {
	base := Cadence{Interval: CandidateFast, Samples: 3, WorkerDeadline: DefaultWorkerDeadline}
	cases := []Cadence{
		{Interval: 0, Samples: 1, WorkerDeadline: time.Second},
		{Interval: 500 * time.Microsecond, Samples: 1, WorkerDeadline: time.Second},
		{Interval: MaxInterval + time.Millisecond, Samples: 1, WorkerDeadline: time.Second},
		{Interval: CandidateFast, Samples: 0, WorkerDeadline: time.Second},
		{Interval: CandidateFast, Samples: MaxSamples + 1, WorkerDeadline: time.Second},
		{Interval: CandidateFast, Samples: 1, WorkerDeadline: 0},
		{Interval: CandidateFast, Samples: 1, WorkerDeadline: MaxWorkerDeadline + time.Millisecond},
	}
	for _, cadence := range cases {
		if err := cadence.Validate(); err == nil {
			t.Fatalf("accepted %#v", cadence)
		}
	}
	origin := time.Unix(1_700_000_000, 0).UTC()
	due, err := base.Due(origin, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !due.Equal(origin.Add(2 * CandidateFast)) {
		t.Fatalf("due = %s", due)
	}
	if _, err := base.Due(origin, 3); err == nil {
		t.Fatal("index past samples was accepted")
	}
}

func TestDeadlineRecommendationClamp(t *testing.T) {
	if got := recommendDeadline(0); got != DefaultWorkerDeadline {
		t.Fatalf("floor = %s", got)
	}
	if got := recommendDeadline(1500 * time.Millisecond); got != 15*time.Second {
		t.Fatalf("scaled = %s", got)
	}
	if got := recommendDeadline(4 * time.Second); got != MaxWorkerDeadline {
		t.Fatalf("ceiling = %s", got)
	}
}

func TestCPUNormalizationAndFiletime(t *testing.T) {
	one, machine, err := cpuPercents(500*time.Millisecond, time.Second, 4)
	if err != nil {
		t.Fatal(err)
	}
	if one != 50 || machine != 12.5 {
		t.Fatalf("one=%v machine=%v", one, machine)
	}
	if _, _, err := cpuPercents(time.Second, 0, 4); err == nil {
		t.Fatal("zero wall was accepted")
	}
	if got := filetimeTicksToDuration(0, 10); got != 1000*time.Nanosecond {
		t.Fatalf("filetime = %s", got)
	}
}
