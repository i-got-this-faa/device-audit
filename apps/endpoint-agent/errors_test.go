package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

var errorEpoch = time.Date(2026, 11, 17, 8, 0, 0, 0, time.UTC)

// stubEventLog is one in-memory log with consecutive record IDs from 1.
type stubEventLog struct {
	levels []uint8
	denied bool
}

func (l *stubEventLog) Bounds(context.Context, string) (telemetry.LogBounds, error) {
	if l.denied {
		return telemetry.LogBounds{}, telemetry.ErrPermissionDenied
	}
	if len(l.levels) == 0 {
		return telemetry.LogBounds{Empty: true}, nil
	}
	return telemetry.LogBounds{Oldest: 1, Newest: uint64(len(l.levels))}, nil
}

func (l *stubEventLog) RecordTime(_ context.Context, _ string, id uint64) (time.Time, bool, error) {
	if id == 0 || id > uint64(len(l.levels)) {
		return time.Time{}, false, nil
	}
	return errorEpoch.Add(time.Duration(id) * time.Second), true, nil
}

func (l *stubEventLog) ReadErrors(_ context.Context, _ string, after uint64, since time.Time, limit int) ([]telemetry.RawEvent, error) {
	var out []telemetry.RawEvent
	for i, level := range l.levels {
		id := uint64(i + 1)
		created := errorEpoch.Add(time.Duration(id) * time.Second)
		if len(out) == limit || id <= after || (level != 1 && level != 2) || (!since.IsZero() && created.Before(since)) {
			continue
		}
		out = append(out, telemetry.RawEvent{RecordID: id, Provider: "Stub", EventID: 7, Level: level, TimeCreated: created, Message: "disk error", MessageStatus: telemetry.MessageComplete})
	}
	return out, nil
}

func stubCollector(log *stubEventLog) telemetry.ErrorCollector {
	return telemetry.ErrorCollector{Reader: log, Logs: []string{telemetry.LogSystem}, Limit: telemetry.MaxErrorRecordsPerLog,
		Lookback: 24 * time.Hour, Now: func() time.Time { return errorEpoch.Add(time.Hour) }}
}

func pollIDs(t *testing.T, data []byte) []uint64 {
	t.Helper()
	var batch telemetry.ErrorBatch
	if err := json.Unmarshal(bytes.TrimSpace(data), &batch); err != nil {
		t.Fatalf("decode batch: %v", err)
	}
	if batch.Schema != telemetry.ErrorEvidenceSchema || batch.Provenance != telemetry.ProvenanceEndpointEventLog {
		t.Fatalf("batch header = %+v", batch)
	}
	var ids []uint64
	for _, l := range batch.Logs {
		for _, r := range l.Records {
			ids = append(ids, r.RecordID)
		}
	}
	return ids
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("pipe closed") }

// Positions survive a restart, so a later process does not return collected
// records. A failed output write commits nothing, so those records come back.
func TestErrorPositionsPersistAcrossRestart(t *testing.T) {
	s, path, _, _ := admittedStore(t)
	log := &stubEventLog{levels: []uint8{2, 4, 1}}
	var out bytes.Buffer
	if err := s.collectErrorEvidence(context.Background(), stubCollector(log), &out); err != nil {
		t.Fatal(err)
	}
	if ids := pollIDs(t, out.Bytes()); len(ids) != 2 || ids[0] != 1 || ids[1] != 3 {
		t.Fatalf("first poll = %v", ids)
	}
	s.close()

	s, err := openIdentityStore(path, false)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := s.collectErrorEvidence(context.Background(), stubCollector(log), &out); err != nil {
		t.Fatal(err)
	}
	if ids := pollIDs(t, out.Bytes()); len(ids) != 0 {
		t.Fatalf("restart duplicated %v", ids)
	}

	log.levels = append(log.levels, 4, 2)
	if err := s.collectErrorEvidence(context.Background(), stubCollector(log), failingWriter{}); err == nil {
		t.Fatal("failed write reported success")
	}
	out.Reset()
	if err := s.collectErrorEvidence(context.Background(), stubCollector(log), &out); err != nil {
		t.Fatal(err)
	}
	if ids := pollIDs(t, out.Bytes()); len(ids) != 1 || ids[0] != 5 {
		t.Fatalf("after failed write = %v", ids)
	}

	// A denied log keeps its saved position.
	log.denied = true
	out.Reset()
	if err := s.collectErrorEvidence(context.Background(), stubCollector(log), &out); err != nil {
		t.Fatal(err)
	}
	positions, err := s.loadErrorPositions()
	if err != nil || positions[telemetry.LogSystem].RecordID != 5 {
		t.Fatalf("positions after denial = %+v %v", positions, err)
	}
	s.close()
}

func TestErrorPositionsFailClosed(t *testing.T) {
	good := encodeErrorPositions(map[string]telemetry.EventPosition{telemetry.LogSystem: {RecordID: 3, TimeCreated: errorEpoch}})
	if got, err := decodeErrorPositions(good); err != nil || got[telemetry.LogSystem].RecordID != 3 {
		t.Fatalf("round trip = %+v %v", got, err)
	}
	flipped := bytes.Clone(good)
	flipped[len(flipped)-2] ^= 1
	for name, data := range map[string][]byte{
		"checksum":   flipped,
		"short":      good[:10],
		"unselected": encodeErrorPositions(map[string]telemetry.EventPosition{"Security": {RecordID: 1}}),
		"nil":        encodeErrorPositions(nil),
	} {
		if _, err := decodeErrorPositions(data); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	s, _, _, _ := admittedStore(t)
	defer s.close()
	if err := s.replace(errorPositionsFile, errorPositionsTempFile, flipped); err != nil {
		t.Fatal(err)
	}
	if err := s.collectErrorEvidence(context.Background(), stubCollector(&stubEventLog{levels: []uint8{2}}), &bytes.Buffer{}); err == nil {
		t.Fatal("damaged positions were reset")
	}
}

// On Windows the real System and Application logs and the real private store:
// a second process-equivalent poll returns no record already returned.
func TestErrorEvidenceRealLogsNoDuplicates(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("V1 selects only the Windows event log")
	}
	s, _, _, _ := admittedStore(t)
	defer s.close()
	var first, second bytes.Buffer
	if err := s.collectErrorEvidence(context.Background(), telemetry.NewErrorCollector(), &first); err != nil {
		t.Fatal(err)
	}
	if err := s.collectErrorEvidence(context.Background(), telemetry.NewErrorCollector(), &second); err != nil {
		t.Fatal(err)
	}
	type key struct {
		log string
		id  uint64
	}
	seen := map[key]bool{}
	var batch telemetry.ErrorBatch
	if err := json.Unmarshal(first.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	for _, l := range batch.Logs {
		for _, r := range l.Records {
			seen[key{l.Log, r.RecordID}] = true
		}
	}
	if err := json.Unmarshal(second.Bytes(), &batch); err != nil {
		t.Fatal(err)
	}
	for _, l := range batch.Logs {
		for _, r := range l.Records {
			if seen[key{l.Log, r.RecordID}] {
				t.Fatalf("%s record %d returned twice", l.Log, r.RecordID)
			}
		}
	}
}
