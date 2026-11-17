//go:build windows

package telemetry

import (
	"context"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// The real System and Application logs: every record is bounded, and a second
// poll from the first poll's positions returns no record at or below them.
func TestWindowsErrorCollectorRepeatedPoll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	c := NewErrorCollector()
	first, err := c.Collect(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	positions := first.Positions(nil)
	for _, l := range first.Logs {
		t.Logf("%s outcome=%s detail=%s continuity=%s records=%d skipped=%d more=%v next=%+v",
			l.Log, l.Outcome, l.Detail, l.Continuity, len(l.Records), l.Skipped, l.More, l.Next)
		if l.Outcome != LogRead || l.Next == nil {
			continue
		}
		for _, r := range l.Records {
			if r.Level != 1 && r.Level != 2 || r.RecordID == 0 || r.TimeCreated.IsZero() || len(r.Message) > MaxEventMessageBytes || len(r.Provider) > MaxEventProviderBytes || r.MessageStatus == "" {
				t.Fatalf("unbounded record %+v", r)
			}
			if r.RecordID > l.Next.RecordID {
				t.Fatalf("record %d beyond next position %d", r.RecordID, l.Next.RecordID)
			}
		}
	}
	second, err := c.Collect(ctx, positions)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range second.Logs {
		t.Logf("repeat %s outcome=%s continuity=%s records=%d", l.Log, l.Outcome, l.Continuity, len(l.Records))
		saved, ok := positions[l.Log]
		if !ok || l.Outcome != LogRead {
			continue
		}
		if l.Continuity != PositionContinued {
			t.Fatalf("%s continuity = %s", l.Log, l.Continuity)
		}
		for _, r := range l.Records {
			if r.RecordID <= saved.RecordID {
				t.Fatalf("%s record %d duplicated at or below position %d", l.Log, r.RecordID, saved.RecordID)
			}
		}
	}
}

// A standard token cannot read the Security log. The real OS denial must
// classify as permission_denied, not as an empty log.
func TestWindowsEventLogDenialIsPermissionDenied(t *testing.T) {
	if windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("elevated token can read the Security log")
	}
	_, err := windowsEventReader{}.Bounds(context.Background(), "Security")
	if reason, detail := ClassifySensorError(err); reason != ReasonPermissionDenied || detail != "event_log_access_denied" {
		t.Fatalf("Security bounds err=%v reason=%s detail=%s", err, reason, detail)
	}
	_, err = windowsEventReader{}.ReadErrors(context.Background(), "Security", 0, time.Time{}, 1)
	if reason, _ := ClassifySensorError(err); reason != ReasonPermissionDenied {
		t.Fatalf("Security query err=%v reason=%s", err, reason)
	}
	_, err = windowsEventReader{}.Bounds(context.Background(), "Device-Audit-Absent-Log")
	if reason, detail := ClassifySensorError(err); reason != ReasonSensorUnavailable || detail != "event_log_absent" {
		t.Fatalf("absent log err=%v reason=%s detail=%s", err, reason, detail)
	}
}
