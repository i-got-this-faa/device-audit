package telemetry

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

var eventEpoch = time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)

// fakeLog is an in-memory event log. Records are kept oldest first.
type fakeLog struct {
	events []RawEvent
	err    error
}

type fakeEventReader struct {
	logs     map[string]*fakeLog
	disorder bool
}

func (f *fakeEventReader) log(name string) (*fakeLog, error) {
	l, ok := f.logs[name]
	if !ok {
		return nil, sensorErr(ErrSensorUnavailable, "event_log_absent")
	}
	return l, l.err
}

func (f *fakeEventReader) Bounds(_ context.Context, name string) (LogBounds, error) {
	l, err := f.log(name)
	if err != nil {
		return LogBounds{}, err
	}
	if len(l.events) == 0 {
		return LogBounds{Empty: true}, nil
	}
	return LogBounds{Oldest: l.events[0].RecordID, Newest: l.events[len(l.events)-1].RecordID}, nil
}

func (f *fakeEventReader) RecordTime(_ context.Context, name string, id uint64) (time.Time, bool, error) {
	l, err := f.log(name)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, e := range l.events {
		if e.RecordID == id {
			return e.TimeCreated, true, nil
		}
	}
	return time.Time{}, false, nil
}

func (f *fakeEventReader) ReadErrors(ctx context.Context, name string, after uint64, since time.Time, limit int) ([]RawEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	l, err := f.log(name)
	if err != nil {
		return nil, err
	}
	var out []RawEvent
	for _, e := range l.events {
		if len(out) == limit {
			break
		}
		if e.RecordID > after && (e.Level == 1 || e.Level == 2 || e.Malformed) && (since.IsZero() || !e.TimeCreated.Before(since)) {
			out = append(out, e)
		}
	}
	if f.disorder && len(out) > 1 {
		out[0], out[1] = out[1], out[0]
	}
	return out, nil
}

// appendEvents adds records with consecutive IDs one minute apart. Level 4
// (information) records are present so positions also cross non-error events.
func (l *fakeLog) appendEvents(levels ...uint8) {
	next := uint64(1)
	if n := len(l.events); n > 0 {
		next = l.events[n-1].RecordID + 1
	}
	for _, level := range levels {
		l.events = append(l.events, RawEvent{
			RecordID: next, Provider: "Fixture-Provider", EventID: uint16(1000 + next), Level: level,
			TimeCreated: eventEpoch.Add(time.Duration(next) * time.Minute), Message: "event message", MessageStatus: MessageComplete,
		})
		next++
	}
}

func errorCollector(reader EventLogReader, logs ...string) ErrorCollector {
	return ErrorCollector{Reader: reader, Logs: logs, Limit: MaxErrorRecordsPerLog, Lookback: 365 * 24 * time.Hour,
		Now: func() time.Time { return eventEpoch.Add(48 * time.Hour) }}
}

func logResult(t *testing.T, batch ErrorBatch, name string) LogResult {
	t.Helper()
	for _, l := range batch.Logs {
		if l.Log == name {
			return l
		}
	}
	t.Fatalf("log %s missing", name)
	return LogResult{}
}

func recordIDs(l LogResult) []uint64 {
	var ids []uint64
	for _, r := range l.Records {
		ids = append(ids, r.RecordID)
	}
	return ids
}

func equalIDs(got []uint64, want ...uint64) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// Acceptance: repeated polling does not return an already collected event,
// including across non-error records and after new events arrive.
func TestErrorCollectorRepeatedPollingDoesNotDuplicate(t *testing.T) {
	system := &fakeLog{}
	system.appendEvents(4, 2, 4, 1, 3, 2) // errors at 2, 4, 6
	reader := &fakeEventReader{logs: map[string]*fakeLog{LogSystem: system}}
	c := errorCollector(reader, LogSystem)

	first, err := c.Collect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	l := logResult(t, first, LogSystem)
	if l.Outcome != LogRead || l.Continuity != PositionStarted || !equalIDs(recordIDs(l), 2, 4, 6) || l.Next.RecordID != 6 {
		t.Fatalf("first = %+v", l)
	}
	positions := first.Positions(nil)

	second, err := c.Collect(context.Background(), positions)
	if err != nil {
		t.Fatal(err)
	}
	if l := logResult(t, second, LogSystem); l.Continuity != PositionContinued || len(l.Records) != 0 {
		t.Fatalf("repeat poll = %+v", l)
	}
	positions = second.Positions(positions)

	system.appendEvents(4, 4, 2, 4) // error at 9; position must move to 10
	third, err := c.Collect(context.Background(), positions)
	if err != nil {
		t.Fatal(err)
	}
	l = logResult(t, third, LogSystem)
	if !equalIDs(recordIDs(l), 9) || l.Next.RecordID != 10 || !l.Next.TimeCreated.Equal(eventEpoch.Add(10*time.Minute)) {
		t.Fatalf("third = %+v next=%+v", l, l.Next)
	}
	positions = third.Positions(positions)
	fourth, _ := c.Collect(context.Background(), positions)
	if l := logResult(t, fourth, LogSystem); len(l.Records) != 0 || l.Continuity != PositionContinued {
		t.Fatalf("fourth = %+v", l)
	}
}

// A full batch reports More and the next poll continues where it stopped.
func TestErrorCollectorBatchLimitContinues(t *testing.T) {
	app := &fakeLog{}
	app.appendEvents(2, 2, 4, 2, 2, 2)
	c := errorCollector(&fakeEventReader{logs: map[string]*fakeLog{LogApplication: app}}, LogApplication)
	c.Limit = 2
	var positions map[string]EventPosition
	var all []uint64
	for poll, want := range [][]uint64{{1, 2}, {4, 5}, {6}, nil} {
		batch, err := c.Collect(context.Background(), positions)
		if err != nil {
			t.Fatal(err)
		}
		l := logResult(t, batch, LogApplication)
		if !equalIDs(recordIDs(l), want...) || l.More != (poll < 2) {
			t.Fatalf("poll %d = %v more=%v", poll, recordIDs(l), l.More)
		}
		all = append(all, recordIDs(l)...)
		positions = batch.Positions(positions)
	}
	if !equalIDs(all, 1, 2, 4, 5, 6) {
		t.Fatalf("collected %v", all)
	}
}

// Acceptance: log rollover and a cleared or replaced log give explicit
// continuity, and none of them skips or repeats an existing record.
func TestErrorCollectorRolloverAndReset(t *testing.T) {
	system := &fakeLog{}
	system.appendEvents(2, 4, 4)
	reader := &fakeEventReader{logs: map[string]*fakeLog{LogSystem: system}}
	c := errorCollector(reader, LogSystem)
	batch, _ := c.Collect(context.Background(), nil)
	positions := batch.Positions(nil) // record 3

	// Rollover: records 1-5 were overwritten while more were written.
	system.appendEvents(4, 2, 4, 2, 4)
	system.events = system.events[5:] // oldest is now 6
	batch, _ = c.Collect(context.Background(), positions)
	l := logResult(t, batch, LogSystem)
	if l.Continuity != PositionRollover || !equalIDs(recordIDs(l), 7) || l.Next.RecordID != 8 {
		t.Fatalf("rollover = %+v", l)
	}
	positions = batch.Positions(positions)

	// Cleared: IDs restart at 1, below the saved position.
	system.events = nil
	system.appendEvents(2, 4)
	batch, _ = c.Collect(context.Background(), positions)
	l = logResult(t, batch, LogSystem)
	if l.Continuity != PositionReset || !equalIDs(recordIDs(l), 1) || l.Next.RecordID != 2 {
		t.Fatalf("reset by clear = %+v", l)
	}
	positions = batch.Positions(positions)

	// Replaced: the saved ID exists again but with a different time.
	system.events = nil
	system.appendEvents(1, 1, 4)
	for i := range system.events {
		system.events[i].TimeCreated = system.events[i].TimeCreated.Add(time.Hour)
	}
	batch, _ = c.Collect(context.Background(), positions)
	l = logResult(t, batch, LogSystem)
	if l.Continuity != PositionReset || !equalIDs(recordIDs(l), 1, 2) {
		t.Fatalf("reset by replacement = %+v", l)
	}

	// Empty log after a clear.
	system.events = nil
	batch, _ = c.Collect(context.Background(), batch.Positions(positions))
	l = logResult(t, batch, LogSystem)
	if l.Continuity != PositionReset || len(l.Records) != 0 || l.Next == nil || l.Next.RecordID != 0 {
		t.Fatalf("empty = %+v", l)
	}
}

// Acceptance: permission denial, an absent log and a timeout are explicit
// outcomes on their own log, keep that log's saved position and do not stop
// the next log.
func TestErrorCollectorFailuresAreBoundedPerLog(t *testing.T) {
	app := &fakeLog{}
	app.appendEvents(2)
	reader := &fakeEventReader{logs: map[string]*fakeLog{
		LogSystem:      {err: sensorErr(ErrPermissionDenied, "event_log_access_denied")},
		LogApplication: app,
	}}
	saved := map[string]EventPosition{LogSystem: {RecordID: 41, TimeCreated: eventEpoch}}
	batch, err := errorCollector(reader, LogSystem, LogApplication).Collect(context.Background(), saved)
	if err != nil {
		t.Fatal(err)
	}
	sys := logResult(t, batch, LogSystem)
	if sys.Outcome != LogPermissionDenied || sys.Detail != "event_log_access_denied" || sys.Next != nil || sys.Records == nil || len(sys.Records) != 0 {
		t.Fatalf("system = %+v", sys)
	}
	if got := batch.Positions(saved)[LogSystem]; got.RecordID != 41 {
		t.Fatalf("denied log position moved to %+v", got)
	}
	if a := logResult(t, batch, LogApplication); a.Outcome != LogRead || len(a.Records) != 1 {
		t.Fatalf("application = %+v", a)
	}

	delete(reader.logs, LogSystem)
	batch, _ = errorCollector(reader, LogSystem, LogApplication).Collect(context.Background(), nil)
	if sys := logResult(t, batch, LogSystem); sys.Outcome != LogUnavailable || sys.Detail != "event_log_absent" {
		t.Fatalf("absent = %+v", sys)
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	batch, err = errorCollector(reader, LogApplication).Collect(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a := logResult(t, batch, LogApplication); a.Outcome != LogCollectionError || a.Detail != "timeout" || a.Next != nil {
		t.Fatalf("timeout = %+v", a)
	}

	cancelled, stop := context.WithCancel(context.Background())
	stop()
	if _, err := errorCollector(reader, LogApplication).Collect(cancelled, nil); err == nil {
		t.Fatal("cancelled collection returned a batch")
	}

	reader.disorder = true
	app.appendEvents(2)
	batch, _ = errorCollector(reader, LogApplication).Collect(context.Background(), nil)
	if a := logResult(t, batch, LogApplication); a.Outcome != LogCollectionError || a.Detail != "record_order_invalid" || a.Next != nil {
		t.Fatalf("disorder = %+v", a)
	}
}

// Acceptance: malformed and oversized events and messages are bounded with an
// explicit status, and a skipped event still advances the position.
func TestErrorCollectorMalformedAndOversized(t *testing.T) {
	long := strings.Repeat("é", MaxEventMessageBytes) // two bytes per rune
	app := &fakeLog{events: []RawEvent{
		{RecordID: 1, Malformed: true},
		{RecordID: 2, Level: 2, TimeCreated: eventEpoch, Provider: "P", Message: long, MessageStatus: MessageComplete},
		{RecordID: 3, Level: 2, TimeCreated: eventEpoch, Provider: "P", Message: "bad \x00 nul\r\nline\xff", MessageStatus: MessageComplete},
		{RecordID: 4, Level: 1, TimeCreated: eventEpoch, Provider: "P", MessageStatus: MessageOversized},
		{RecordID: 5, Level: 2, TimeCreated: eventEpoch, Provider: "P", MessageStatus: MessageUnavailable},
		{RecordID: 6, Level: 2, TimeCreated: eventEpoch, Provider: strings.Repeat("p", 1000), Message: "lone surrogate", MessageStatus: MessageMalformed},
		{RecordID: 7, Level: 2, Provider: "P", MessageStatus: MessageComplete},
	}}
	batch, err := errorCollector(&fakeEventReader{logs: map[string]*fakeLog{LogApplication: app}}, LogApplication).
		Collect(context.Background(), map[string]EventPosition{LogApplication: {}})
	if err != nil {
		t.Fatal(err)
	}
	l := logResult(t, batch, LogApplication)
	if l.Skipped != 2 || !equalIDs(recordIDs(l), 2, 3, 4, 5, 6) || l.Next.RecordID != 7 {
		t.Fatalf("result = %+v", l)
	}
	truncated, malformed, oversized, unavailable, surrogate := l.Records[0], l.Records[1], l.Records[2], l.Records[3], l.Records[4]
	if truncated.MessageStatus != MessageTruncated || len(truncated.Message) > MaxEventMessageBytes || !utf8.ValidString(truncated.Message) || truncated.MessageBytes != len(long) {
		t.Fatalf("truncated = %s %d %d", truncated.MessageStatus, len(truncated.Message), truncated.MessageBytes)
	}
	if malformed.MessageStatus != MessageMalformed || strings.ContainsAny(malformed.Message, "\x00\r") || !utf8.ValidString(malformed.Message) || !strings.Contains(malformed.Message, "\nline") {
		t.Fatalf("malformed = %q %s", malformed.Message, malformed.MessageStatus)
	}
	if oversized.MessageStatus != MessageOversized || oversized.Message != "" || unavailable.MessageStatus != MessageUnavailable || unavailable.Message != "" {
		t.Fatalf("oversized=%+v unavailable=%+v", oversized, unavailable)
	}
	if surrogate.MessageStatus != MessageMalformed || len(surrogate.Provider) != MaxEventProviderBytes {
		t.Fatalf("surrogate = %+v", surrogate)
	}
	encoded, err := json.Marshal(batch)
	if err != nil || !json.Valid(encoded) {
		t.Fatalf("batch does not encode: %v", err)
	}
}

func TestErrorCollectorLookbackAndConfiguration(t *testing.T) {
	system := &fakeLog{}
	system.appendEvents(2, 2, 2)
	c := errorCollector(&fakeEventReader{logs: map[string]*fakeLog{LogSystem: system}}, LogSystem)
	c.Now = func() time.Time { return eventEpoch.Add(3 * time.Minute) }
	c.Lookback = 90 * time.Second // records 2 and 3 only
	batch, _ := c.Collect(context.Background(), nil)
	if l := logResult(t, batch, LogSystem); !equalIDs(recordIDs(l), 2, 3) {
		t.Fatalf("lookback = %v", recordIDs(l))
	}
	for _, logs := range [][]string{{"Security"}, {LogSystem, LogSystem}, nil} {
		bad := errorCollector(c.Reader, logs...)
		if _, err := bad.Collect(context.Background(), nil); err == nil {
			t.Fatalf("logs %v accepted", logs)
		}
	}
	bad := errorCollector(c.Reader, LogSystem)
	bad.Limit = MaxErrorRecordsPerLog + 1
	if _, err := bad.Collect(context.Background(), nil); err == nil {
		t.Fatal("limit above ceiling accepted")
	}
	bad = errorCollector(c.Reader, LogSystem)
	bad.Lookback = 0
	if _, err := bad.Collect(context.Background(), nil); err == nil {
		t.Fatal("zero lookback accepted")
	}
}

func TestDecodeUTF16(t *testing.T) {
	if s, ok := DecodeUTF16([]uint16{'o', 'k', 0xd83d, 0xde00, 0, 'x'}); !ok || s != "ok😀" {
		t.Fatalf("valid = %q %v", s, ok)
	}
	for _, units := range [][]uint16{{'a', 0xd83d}, {0xde00, 'b'}, {0xd83d, 'c'}} {
		if s, ok := DecodeUTF16(units); ok || !utf8.ValidString(s) || !strings.Contains(s, "�") {
			t.Fatalf("%v = %q %v", units, s, ok)
		}
	}
}

func TestBoundTextCutsAtRuneBoundary(t *testing.T) {
	s, status := boundText("ab€", 4) // € is three bytes
	if s != "ab" || status != MessageTruncated {
		t.Fatalf("%q %s", s, status)
	}
	if s, status := boundText("fine\ttext\r\n", 100); s != "fine\ttext" || status != MessageComplete {
		t.Fatalf("%q %s", s, status)
	}
}
