//go:build windows

package telemetry

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
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

// wevtutilRecordID returns the record ID of the first event wevtutil prints,
// newest first when reverse. It is an oracle independent of this reader.
func wevtutilRecordID(t *testing.T, log string, reverse bool) uint64 {
	t.Helper()
	system, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(filepath.Join(system, "wevtutil.exe"), "qe", log, "/c:1", fmt.Sprintf("/rd:%v", reverse), "/f:xml").Output()
	if err != nil {
		t.Fatalf("wevtutil %s: %v", log, err)
	}
	m := regexp.MustCompile(`<EventRecordID>(\d+)</EventRecordID>`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("wevtutil %s printed no record ID", log)
	}
	id, err := strconv.ParseUint(string(m[1]), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Bounds must be the real first and last records. Hosted images have logs
// whose IDs have gaps, where oldest + count - 1 is below the real newest ID
// and made a repeated poll reset and return collected records again.
func TestWindowsBoundsMatchRealRecords(t *testing.T) {
	for _, log := range []string{LogSystem, LogApplication} {
		newestBefore := wevtutilRecordID(t, log, true)
		bounds, err := windowsEventReader{}.Bounds(context.Background(), log)
		if err != nil {
			t.Fatal(err)
		}
		newestAfter := wevtutilRecordID(t, log, true)
		if bounds.Empty || bounds.Newest < newestBefore || bounds.Newest > newestAfter || bounds.NewestTime.IsZero() {
			t.Fatalf("%s bounds %+v, wevtutil newest %d..%d", log, bounds, newestBefore, newestAfter)
		}
		if oldest := wevtutilRecordID(t, log, false); bounds.Oldest > oldest {
			t.Fatalf("%s oldest %d above wevtutil oldest %d", log, bounds.Oldest, oldest)
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
