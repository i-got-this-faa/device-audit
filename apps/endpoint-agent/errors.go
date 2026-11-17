package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

const (
	errorPositionsFile     = "error-positions.state"
	errorPositionsTempFile = "error-positions.state.tmp"
	errorPositionsVersion  = "device-audit.endpoint-error-positions.v1"
)

// errorPositionsState holds the last examined event-log record per log. It is
// local read state, not a secret, receipt or evidence.
type errorPositionsState struct {
	SchemaVersion string                             `json:"schema_version"`
	Positions     map[string]telemetry.EventPosition `json:"positions"`
}

func encodeErrorPositions(positions map[string]telemetry.EventPosition) []byte {
	body, _ := json.Marshal(errorPositionsState{SchemaVersion: errorPositionsVersion, Positions: positions})
	return checksummed(body)
}

func decodeErrorPositions(data []byte) (map[string]telemetry.EventPosition, error) {
	body, ok := verifyChecksum(data)
	if !ok {
		return nil, errors.New("error position state checksum failed")
	}
	var state errorPositionsState
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || decoder.More() || state.SchemaVersion != errorPositionsVersion || state.Positions == nil {
		return nil, errors.New("invalid error position state")
	}
	for log := range state.Positions {
		if log != telemetry.LogSystem && log != telemetry.LogApplication {
			return nil, errors.New("error position state names an unselected log")
		}
	}
	return state.Positions, nil
}

// loadErrorPositions returns the saved positions. A missing file is the first
// poll. Damaged state fails closed so it is never silently reset.
func (s *identityStore) loadErrorPositions() (map[string]telemetry.EventPosition, error) {
	data, err := s.read(errorPositionsFile)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]telemetry.EventPosition{}, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeErrorPositions(data)
}

// collectErrorEvidence writes one error-evidence batch to out and only then
// commits the new positions. A failed write leaves the saved positions, so the
// next poll returns the same records. A crash after the write and before the
// commit can return them again. Consumers deduplicate on log, record_id and
// time_created, because a cleared or replaced log reuses record IDs.
func (s *identityStore) collectErrorEvidence(ctx context.Context, collector telemetry.ErrorCollector, out io.Writer) error {
	saved, err := s.loadErrorPositions()
	if err != nil {
		return err
	}
	batch, err := collector.Collect(ctx, saved)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(batch)
	if err != nil {
		return errors.New("encode error evidence")
	}
	if _, err := out.Write(append(encoded, '\n')); err != nil {
		return errors.New("write error evidence")
	}
	return s.replace(errorPositionsFile, errorPositionsTempFile, encodeErrorPositions(batch.Positions(saved)))
}
