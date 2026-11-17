package telemetry

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

// TEL07 #93: bounded structured Windows error evidence.
//
// The collector reads Critical and Error events (levels 1 and 2) from the
// System and Application logs. Each record keeps its source (log and record
// ID) and creation time. A per-log read position makes repeated polls continue
// after the last examined record, so an already collected event is not
// returned again. Records are local, off-chain evidence. Nothing here writes to
// a chain or copies the event's computer name, user SID or raw XML.

const (
	// ErrorEvidenceSchema identifies one error-evidence batch.
	ErrorEvidenceSchema = "device-audit.error-evidence.v1"
	// ProvenanceEndpointEventLog marks records read from this host's event log.
	ProvenanceEndpointEventLog = "endpoint_event_log"
	LogSystem                  = "System"
	LogApplication             = "Application"
	// MaxErrorRecordsPerLog matches the system_errors.v1 max_entries ceiling.
	MaxErrorRecordsPerLog = 256
	// MaxEventMessageBytes bounds one record's message after UTF-8 encoding.
	MaxEventMessageBytes = 2048
	// MaxEventProviderBytes bounds the provider name.
	MaxEventProviderBytes = 256
	// DefaultErrorLookback bounds the first read of a log without a position.
	DefaultErrorLookback = 24 * time.Hour
)

// Message statuses. Every record has exactly one.
const (
	MessageComplete    = "complete"
	MessageTruncated   = "truncated"   // cut at a rune boundary to MaxEventMessageBytes
	MessageMalformed   = "malformed"   // invalid UTF-16 or control characters were replaced
	MessageOversized   = "oversized"   // larger than the provider read buffer; not read
	MessageUnavailable = "unavailable" // no publisher metadata or message template
)

// Log outcomes.
const (
	LogRead             = "read"
	LogPermissionDenied = "permission_denied"
	LogUnavailable      = "log_unavailable"
	LogCollectionError  = "collection_error"
)

// Position continuity. It says how this read relates to the saved position.
const (
	PositionStarted   = "started"   // no saved position; DefaultErrorLookback applies
	PositionContinued = "continued" // the saved record still exists
	PositionRollover  = "rollover"  // the saved record was overwritten; unread older records may be lost
	PositionReset     = "reset"     // the log was cleared or replaced; it is read from its start
)

// EventPosition is the last examined record of one log. RecordID 0 means read
// from the start of the log without a lookback limit.
type EventPosition struct {
	RecordID    uint64    `json:"record_id"`
	TimeCreated time.Time `json:"time_created"`
}

// ErrorRecord is one bounded event. Level is 1 (critical) or 2 (error).
type ErrorRecord struct {
	Log           string    `json:"log"`
	RecordID      uint64    `json:"record_id"`
	Provider      string    `json:"provider"`
	EventID       uint16    `json:"event_id"`
	Level         uint8     `json:"level"`
	TimeCreated   time.Time `json:"time_created"`
	Message       string    `json:"message"`
	MessageStatus string    `json:"message_status"`
	MessageBytes  int       `json:"message_bytes"`
}

// LogResult is one log's read. Next is the position to save after the batch is
// stored; it is nil when the read failed and the saved position must stay.
type LogResult struct {
	Log        string         `json:"log"`
	Outcome    string         `json:"outcome"`
	Detail     string         `json:"detail,omitempty"`
	Continuity string         `json:"continuity,omitempty"`
	Records    []ErrorRecord  `json:"records"`
	Skipped    int            `json:"skipped"`
	More       bool           `json:"more"`
	Next       *EventPosition `json:"next_position,omitempty"`
}

// ErrorBatch is one poll over every configured log.
type ErrorBatch struct {
	Schema      string      `json:"schema"`
	Provenance  string      `json:"provenance"`
	CollectedAt time.Time   `json:"collected_at"`
	Logs        []LogResult `json:"logs"`
}

// Positions returns saved with every successful log's next position applied.
// A failed log keeps its saved position.
func (b ErrorBatch) Positions(saved map[string]EventPosition) map[string]EventPosition {
	out := make(map[string]EventPosition, len(saved)+len(b.Logs))
	for log, pos := range saved {
		out[log] = pos
	}
	for _, l := range b.Logs {
		if l.Next != nil {
			out[l.Log] = *l.Next
		}
	}
	return out
}

// LogBounds is the record ID range a log currently holds, read from its first
// and last records. NewestTime is the newest record's creation time, so the
// pair identifies that record even if the log is cleared later.
type LogBounds struct {
	Oldest, Newest uint64
	NewestTime     time.Time
	Empty          bool
}

// RawEvent is one event as the OS returned it. Malformed means its system
// fields could not be decoded; such an event is counted, not recorded.
// RecordID is 0 when even the record ID could not be read.
type RawEvent struct {
	RecordID      uint64
	Provider      string
	EventID       uint16
	Level         uint8
	TimeCreated   time.Time
	Message       string
	MessageStatus string
	Malformed     bool
}

// EventLogReader is the OS event-log boundary.
type EventLogReader interface {
	// Bounds returns the actual oldest and newest records of log. Record IDs
	// can have gaps, so a count-based range is not acceptable.
	Bounds(ctx context.Context, log string) (LogBounds, error)
	// RecordTime returns the creation time of record id in log, if it exists.
	RecordTime(ctx context.Context, log string, id uint64) (time.Time, bool, error)
	// ReadErrors returns up to limit level 1-2 events with a record ID above
	// after, oldest first. A non-zero since also requires creation at or
	// after since.
	ReadErrors(ctx context.Context, log string, after uint64, since time.Time, limit int) ([]RawEvent, error)
}

// ErrorCollector polls the selected logs through an EventLogReader.
type ErrorCollector struct {
	Reader   EventLogReader
	Logs     []string
	Limit    int
	Lookback time.Duration
	Now      func() time.Time
}

// NewErrorCollector returns the platform reader for the System and
// Application logs with the default bounds.
func NewErrorCollector() ErrorCollector {
	return ErrorCollector{
		Reader:   platformEventReader(),
		Logs:     []string{LogSystem, LogApplication},
		Limit:    MaxErrorRecordsPerLog,
		Lookback: DefaultErrorLookback,
	}
}

// Collect reads every log once from its saved position. A failed log is
// recorded with its outcome and does not stop later logs. Collect returns an
// error only for invalid configuration or a cancelled parent context.
func (c ErrorCollector) Collect(ctx context.Context, saved map[string]EventPosition) (ErrorBatch, error) {
	if c.Reader == nil || len(c.Logs) == 0 || c.Limit < 1 || c.Limit > MaxErrorRecordsPerLog || c.Lookback <= 0 {
		return ErrorBatch{}, errors.New("telemetry: error collector is not configured")
	}
	seen := map[string]bool{}
	for _, log := range c.Logs {
		if log != LogSystem && log != LogApplication || seen[log] {
			return ErrorBatch{}, fmt.Errorf("telemetry: error log %q is not selected or is duplicated", log)
		}
		seen[log] = true
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	batch := ErrorBatch{Schema: ErrorEvidenceSchema, Provenance: ProvenanceEndpointEventLog, CollectedAt: now().UTC()}
	for _, log := range c.Logs {
		if errors.Is(ctx.Err(), context.Canceled) {
			return ErrorBatch{}, ctx.Err()
		}
		pos, have := saved[log]
		result, err := c.readLog(ctx, log, pos, have, batch.CollectedAt)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				return ErrorBatch{}, ctx.Err()
			}
			reason, detail := ClassifySensorError(err)
			result = LogResult{Log: log, Outcome: logOutcome(reason), Detail: detail, Records: []ErrorRecord{}}
		}
		batch.Logs = append(batch.Logs, result)
	}
	return batch, nil
}

func (c ErrorCollector) readLog(ctx context.Context, log string, pos EventPosition, have bool, now time.Time) (LogResult, error) {
	bounds, err := c.Reader.Bounds(ctx, log)
	if err != nil {
		return LogResult{}, err
	}
	continuity, after, since, err := c.plan(ctx, log, pos, have, bounds, now)
	if err != nil {
		return LogResult{}, err
	}
	raws, err := c.Reader.ReadErrors(ctx, log, after, since, c.Limit+1)
	if err != nil {
		return LogResult{}, err
	}
	result := LogResult{Log: log, Outcome: LogRead, Continuity: continuity, Records: []ErrorRecord{}}
	if len(raws) > c.Limit {
		raws, result.More = raws[:c.Limit], true
	}
	next := EventPosition{RecordID: after}
	if continuity == PositionContinued || continuity == PositionRollover {
		next.TimeCreated = pos.TimeCreated
	}
	for _, raw := range raws {
		// An event whose system fields could not be rendered may have no
		// record ID. It is counted and cannot move the position; a later
		// record or the newest-record anchor below moves past it.
		if raw.Malformed && raw.RecordID == 0 {
			result.Skipped++
			continue
		}
		// The reader returns ascending IDs above after. Anything else would
		// move the position backwards and duplicate events on the next poll.
		if raw.RecordID <= next.RecordID {
			return LogResult{}, sensorErr(errors.New("telemetry: event log returned records out of order"), "record_order_invalid")
		}
		next = EventPosition{RecordID: raw.RecordID, TimeCreated: raw.TimeCreated.UTC()}
		record, ok := normalizeEvent(log, raw)
		if !ok {
			result.Skipped++
			continue
		}
		result.Records = append(result.Records, record)
	}
	// After a complete read every record up to the newest one at Bounds time
	// was examined, so the position can move there and stay a live anchor.
	// The anchor's time was captured before the read: if the log is cleared
	// during the read, the next poll sees a different record at that ID and
	// resets instead of skipping the new log's records.
	if !result.More && !bounds.Empty && bounds.Newest > next.RecordID {
		next = EventPosition{RecordID: bounds.Newest, TimeCreated: bounds.NewestTime.UTC()}
	}
	result.Next = &next
	return result, nil
}

// plan decides where this read starts. It never returns an after value that
// skips an existing unread record.
func (c ErrorCollector) plan(ctx context.Context, log string, pos EventPosition, have bool, bounds LogBounds, now time.Time) (continuity string, after uint64, since time.Time, err error) {
	switch {
	case !have:
		return PositionStarted, 0, now.Add(-c.Lookback), nil
	case pos.RecordID == 0:
		return PositionContinued, 0, time.Time{}, nil
	case bounds.Empty, pos.RecordID > bounds.Newest:
		return PositionReset, 0, time.Time{}, nil
	case pos.RecordID < bounds.Oldest:
		return PositionRollover, pos.RecordID, time.Time{}, nil
	}
	created, found, err := c.Reader.RecordTime(ctx, log, pos.RecordID)
	if err != nil {
		return "", 0, time.Time{}, err
	}
	if !found || !created.Equal(pos.TimeCreated) {
		return PositionReset, 0, time.Time{}, nil
	}
	return PositionContinued, pos.RecordID, time.Time{}, nil
}

func logOutcome(reason string) string {
	switch reason {
	case ReasonPermissionDenied:
		return LogPermissionDenied
	case ReasonSensorUnavailable, ReasonNotApplicable:
		return LogUnavailable
	default:
		return LogCollectionError
	}
}

// normalizeEvent bounds one event. An event without a record ID, time or an
// error level is not a record.
func normalizeEvent(log string, raw RawEvent) (ErrorRecord, bool) {
	if raw.Malformed || raw.RecordID == 0 || raw.TimeCreated.IsZero() || (raw.Level != 1 && raw.Level != 2) {
		return ErrorRecord{}, false
	}
	provider, _ := boundText(raw.Provider, MaxEventProviderBytes)
	record := ErrorRecord{
		Log: log, RecordID: raw.RecordID, Provider: provider, EventID: raw.EventID,
		Level: raw.Level, TimeCreated: raw.TimeCreated.UTC(),
	}
	switch raw.MessageStatus {
	case MessageOversized, MessageUnavailable:
		record.MessageStatus = raw.MessageStatus
		return record, true
	}
	text, status := boundText(raw.Message, MaxEventMessageBytes)
	record.Message, record.MessageBytes = text, len(raw.Message)
	if raw.MessageStatus == MessageMalformed {
		status = MessageMalformed
	}
	record.MessageStatus = status
	return record, true
}

// boundText replaces invalid UTF-8 and control characters other than newline
// and tab, normalizes CRLF, trims trailing space and cuts the result to limit
// bytes at a rune boundary. Replacement wins over truncation in the status.
func boundText(s string, limit int) (string, string) {
	status := MessageComplete
	if !utf8.ValidString(s) {
		s, status = strings.ToValidUTF8(s, "�"), MessageMalformed
	}
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	for _, r := range s {
		if r != '\n' && r != '\t' && (r < 0x20 || (r >= 0x7f && r < 0xa0)) {
			r, status = '�', MessageMalformed
		}
		b.WriteRune(r)
	}
	s = strings.TrimRight(b.String(), " \n\t")
	if len(s) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
		if status == MessageComplete {
			status = MessageTruncated
		}
	}
	return s, status
}

// DecodeUTF16 decodes u up to its first NUL. ok is false when it held an
// unpaired surrogate, which is replaced with U+FFFD.
func DecodeUTF16(u []uint16) (s string, ok bool) {
	for i, c := range u {
		if c == 0 {
			u = u[:i]
			break
		}
	}
	ok = true
	for i := 0; i < len(u); i++ {
		switch {
		case utf16.IsSurrogate(rune(u[i])) && u[i] < 0xdc00 && i+1 < len(u) && u[i+1] >= 0xdc00 && u[i+1] <= 0xdfff:
			i++
		case utf16.IsSurrogate(rune(u[i])):
			ok = false
		}
	}
	return string(utf16.Decode(u)), ok
}
