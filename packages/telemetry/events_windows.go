//go:build windows

package telemetry

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	wevtapi                      = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtOpenLog               = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo            = wevtapi.NewProc("EvtGetLogInfo")
	procEvtQuery                 = wevtapi.NewProc("EvtQuery")
	procEvtNext                  = wevtapi.NewProc("EvtNext")
	procEvtCreateRenderContext   = wevtapi.NewProc("EvtCreateRenderContext")
	procEvtRender                = wevtapi.NewProc("EvtRender")
	procEvtOpenPublisherMetadata = wevtapi.NewProc("EvtOpenPublisherMetadata")
	procEvtFormatMessage         = wevtapi.NewProc("EvtFormatMessage")
	procEvtClose                 = wevtapi.NewProc("EvtClose")
)

const (
	evtOpenChannelPath       = 0x1
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtLogNumberOfLogRecords = 5
	evtLogOldestRecordNumber = 6
	evtRenderContextSystem   = 1
	evtRenderEventValues     = 0
	evtFormatMessageEvent    = 1
	evtNextTimeoutMS         = 1000
	evtNextBatch             = 16

	// EVT_SYSTEM_PROPERTY_ID indexes in a system render context.
	evtSystemProviderName  = 0
	evtSystemEventID       = 2
	evtSystemLevel         = 4
	evtSystemTimeCreated   = 8
	evtSystemEventRecordID = 9
	evtSystemPropertyCount = 18

	// EVT_VARIANT_TYPE values.
	evtVarTypeString   = 1
	evtVarTypeByte     = 4
	evtVarTypeUInt16   = 6
	evtVarTypeUInt64   = 10
	evtVarTypeFileTime = 17
	evtVarTypeMask     = 0x7f

	// Read-buffer ceilings. A larger rendering is counted or marked oversized.
	maxEventRenderBytes  = 64 << 10
	maxEventMessageChars = 32 << 10
	maxEventStringChars  = 4096
)

// evtVariant mirrors EVT_VARIANT: an 8-byte union, a count and a type.
type evtVariant struct {
	Value uint64
	Count uint32
	Type  uint32
}

type windowsEventReader struct{}

func platformEventReader() EventLogReader { return windowsEventReader{} }

func evtClose(h windows.Handle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}

// eventLogError classifies a wevtapi failure. Provider error text is dropped.
func eventLogError(err error, detail string) error {
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return sensorErr(ErrPermissionDenied, "event_log_access_denied")
	case errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND):
		return sensorErr(ErrSensorUnavailable, "event_log_absent")
	default:
		return sensorErr(fmt.Errorf("telemetry: event log call failed: %w", err), detail)
	}
}

func (windowsEventReader) Bounds(ctx context.Context, log string) (LogBounds, error) {
	if err := wevtapi.Load(); err != nil {
		return LogBounds{}, sensorErr(ErrSensorUnavailable, "wevtapi_absent")
	}
	path, err := windows.UTF16PtrFromString(log)
	if err != nil {
		return LogBounds{}, sensorErr(err, "event_log_name_invalid")
	}
	h, _, callErr := procEvtOpenLog.Call(0, uintptr(unsafe.Pointer(path)), evtOpenChannelPath)
	if h == 0 {
		return LogBounds{}, eventLogError(callErr, "event_log_open_failed")
	}
	defer evtClose(windows.Handle(h))
	count, err := logInfo(windows.Handle(h), evtLogNumberOfLogRecords)
	if err != nil {
		return LogBounds{}, err
	}
	if count == 0 {
		return LogBounds{Empty: true}, nil
	}
	oldest, err := logInfo(windows.Handle(h), evtLogOldestRecordNumber)
	if err != nil {
		return LogBounds{}, err
	}
	return LogBounds{Oldest: oldest, Newest: oldest + count - 1}, ctx.Err()
}

func logInfo(h windows.Handle, property uint32) (uint64, error) {
	var v evtVariant
	var used uint32
	r, _, callErr := procEvtGetLogInfo.Call(uintptr(h), uintptr(property), unsafe.Sizeof(v), uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&used)))
	if r == 0 {
		return 0, eventLogError(callErr, "event_log_info_failed")
	}
	if v.Type&evtVarTypeMask != evtVarTypeUInt64 {
		return 0, sensorErr(errors.New("telemetry: unexpected log info type"), "event_log_info_failed")
	}
	return v.Value, nil
}

func (windowsEventReader) RecordTime(ctx context.Context, log string, id uint64) (time.Time, bool, error) {
	events, err := queryEvents(ctx, log, fmt.Sprintf("*[System[EventRecordID=%d]]", id), 1, false)
	if err != nil || len(events) == 0 {
		return time.Time{}, false, err
	}
	if events[0].Malformed || events[0].RecordID != id {
		return time.Time{}, false, nil
	}
	return events[0].TimeCreated, true, nil
}

func (windowsEventReader) ReadErrors(ctx context.Context, log string, after uint64, since time.Time, limit int) ([]RawEvent, error) {
	query := fmt.Sprintf("*[System[(Level=1 or Level=2) and EventRecordID>%d", after)
	if !since.IsZero() {
		query += fmt.Sprintf(" and TimeCreated[@SystemTime>='%s']", since.UTC().Format("2006-01-02T15:04:05.000Z"))
	}
	return queryEvents(ctx, log, query+"]]", limit, true)
}

// queryEvents runs a forward channel query and renders at most limit events.
func queryEvents(ctx context.Context, log, query string, limit int, messages bool) ([]RawEvent, error) {
	if err := wevtapi.Load(); err != nil {
		return nil, sensorErr(ErrSensorUnavailable, "wevtapi_absent")
	}
	path, err := windows.UTF16PtrFromString(log)
	if err != nil {
		return nil, sensorErr(err, "event_log_name_invalid")
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return nil, sensorErr(err, "event_query_invalid")
	}
	results, _, callErr := procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(q)), evtQueryChannelPath|evtQueryForwardDirection)
	if results == 0 {
		return nil, eventLogError(callErr, "event_query_failed")
	}
	defer evtClose(windows.Handle(results))
	render, _, callErr := procEvtCreateRenderContext.Call(0, 0, evtRenderContextSystem)
	if render == 0 {
		return nil, eventLogError(callErr, "event_render_context_failed")
	}
	defer evtClose(windows.Handle(render))
	publishers := map[string]windows.Handle{}
	defer func() {
		for _, h := range publishers {
			evtClose(h)
		}
	}()
	var out []RawEvent
	for len(out) < limit {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var handles [evtNextBatch]windows.Handle
		want := min(evtNextBatch, limit-len(out))
		var returned uint32
		r, _, callErr := procEvtNext.Call(results, uintptr(want), uintptr(unsafe.Pointer(&handles[0])), evtNextTimeoutMS, 0, uintptr(unsafe.Pointer(&returned)))
		if r == 0 {
			if errors.Is(callErr, windows.ERROR_NO_MORE_ITEMS) {
				break
			}
			return nil, eventLogError(callErr, "event_next_failed")
		}
		for _, h := range handles[:returned] {
			event := renderSystem(windows.Handle(render), h)
			if messages && !event.Malformed {
				event.Message, event.MessageStatus = formatMessage(publishers, event.Provider, h)
			}
			evtClose(h)
			out = append(out, event)
		}
	}
	return out, nil
}

// renderSystem decodes the system properties this collector keeps. Computer,
// user SID, process and thread IDs are rendered by the OS but not copied.
func renderSystem(render, handle windows.Handle) RawEvent {
	buf := make([]byte, 2048)
	var used, count uint32
	for {
		r, _, callErr := procEvtRender.Call(uintptr(render), uintptr(handle), evtRenderEventValues, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&count)))
		if r != 0 {
			break
		}
		if !errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) || used > maxEventRenderBytes || int(used) <= len(buf) {
			return RawEvent{Malformed: true}
		}
		buf = make([]byte, used)
	}
	if count < evtSystemPropertyCount || uintptr(count)*unsafe.Sizeof(evtVariant{}) > uintptr(used) {
		return RawEvent{Malformed: true}
	}
	values := unsafe.Slice((*evtVariant)(unsafe.Pointer(&buf[0])), count)
	var event RawEvent
	ok := true
	// String values point into buf. Decode them by offset so a pointer outside
	// the rendered bytes is malformed instead of an out-of-bounds read.
	base := uint64(uintptr(unsafe.Pointer(&buf[0])))
	if v := values[evtSystemProviderName]; v.Type&evtVarTypeMask == evtVarTypeString && v.Value >= base && v.Value < base+uint64(used) {
		event.Provider, ok = DecodeUTF16(utf16Units(buf[v.Value-base:used], maxEventStringChars))
	} else {
		ok = false
	}
	if v := values[evtSystemEventID]; v.Type&evtVarTypeMask == evtVarTypeUInt16 {
		event.EventID = uint16(v.Value)
	} else {
		ok = false
	}
	if v := values[evtSystemLevel]; v.Type&evtVarTypeMask == evtVarTypeByte {
		event.Level = uint8(v.Value)
	} else {
		ok = false
	}
	if v := values[evtSystemTimeCreated]; v.Type&evtVarTypeMask == evtVarTypeFileTime && v.Value != 0 {
		ft := windows.Filetime{LowDateTime: uint32(v.Value), HighDateTime: uint32(v.Value >> 32)}
		event.TimeCreated = time.Unix(0, ft.Nanoseconds()).UTC()
	} else {
		ok = false
	}
	if v := values[evtSystemEventRecordID]; v.Type&evtVarTypeMask == evtVarTypeUInt64 {
		event.RecordID = v.Value
	} else {
		ok = false
	}
	event.Malformed = !ok
	return event
}

// utf16Units reads little-endian UTF-16 units from b up to a NUL, at most max.
func utf16Units(b []byte, max int) []uint16 {
	var out []uint16
	for i := 0; i+1 < len(b) && len(out) < max; i += 2 {
		u := uint16(b[i]) | uint16(b[i+1])<<8
		if u == 0 {
			break
		}
		out = append(out, u)
	}
	return out
}

// formatMessage renders the event's message through its publisher metadata.
func formatMessage(publishers map[string]windows.Handle, provider string, event windows.Handle) (string, string) {
	pm, cached := publishers[provider]
	if !cached {
		if name, err := windows.UTF16PtrFromString(provider); err == nil {
			h, _, _ := procEvtOpenPublisherMetadata.Call(0, uintptr(unsafe.Pointer(name)), 0, 0, 0)
			pm = windows.Handle(h)
		}
		publishers[provider] = pm
	}
	if pm == 0 {
		return "", MessageUnavailable
	}
	buf := make([]uint16, 1024)
	var used uint32
	for {
		r, _, callErr := procEvtFormatMessage.Call(uintptr(pm), uintptr(event), 0, 0, 0, evtFormatMessageEvent, uintptr(len(buf)), uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&used)))
		// An unresolved insert still yields the formatted text.
		if r != 0 || errors.Is(callErr, windows.ERROR_EVT_UNRESOLVED_VALUE_INSERT) {
			break
		}
		if !errors.Is(callErr, windows.ERROR_INSUFFICIENT_BUFFER) || int(used) <= len(buf) {
			return "", MessageUnavailable
		}
		if used > maxEventMessageChars {
			return "", MessageOversized
		}
		buf = make([]uint16, used)
	}
	text, ok := DecodeUTF16(buf[:min(int(used), len(buf))])
	if !ok {
		return text, MessageMalformed
	}
	return text, MessageComplete
}
