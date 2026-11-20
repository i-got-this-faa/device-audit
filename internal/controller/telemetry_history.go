package controller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// historyCursor is the last row of the previous page. The sequence breaks ties
// between samples that share a collection time.
type historyCursor struct {
	collectedAt time.Time
	sequence    uint64
}

func (c historyCursor) String() string {
	return strconv.FormatInt(c.collectedAt.UnixMicro(), 10) + "." + strconv.FormatUint(c.sequence, 10)
}

func parseHistoryCursor(raw string) (historyCursor, error) {
	micros, seq, ok := strings.Cut(raw, ".")
	if !ok {
		return historyCursor{}, ErrDeviceStateInvalid
	}
	m, err1 := strconv.ParseInt(micros, 10, 64)
	s, err2 := strconv.ParseUint(seq, 10, 64)
	c := historyCursor{collectedAt: time.UnixMicro(m).UTC(), sequence: s}
	if err1 != nil || err2 != nil || c.String() != raw || s < 2 || s > 9007199254740991 {
		return historyCursor{}, ErrDeviceStateInvalid
	}
	return c, nil
}

// TelemetryHistory returns up to limit samples of one enrolled device with
// from <= collected_at < to, after the cursor. A zero cursor starts at the window start.
func (s *PostgresRepository) TelemetryHistory(ctx context.Context, deviceID string, from, to time.Time, after *historyCursor, limit int) (contracts.TelemetryHistoryV1, error) {
	from, to = from.UTC().Truncate(time.Microsecond), to.UTC().Truncate(time.Microsecond)
	if !repositoryIDPattern.MatchString(deviceID) || limit < 1 || limit > contracts.TelemetryHistoryPageMaxV1 ||
		!from.Before(to) || to.Sub(from) > contracts.TelemetryHistoryWindowMaxV1 {
		return contracts.TelemetryHistoryV1{}, ErrDeviceStateInvalid
	}
	// An unknown device is 404, not an empty page. Revoked devices stay readable.
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, deviceID).Scan(&exists); err != nil {
		return contracts.TelemetryHistoryV1{}, repositoryReadError(err)
	}
	cursor := historyCursor{collectedAt: from}
	if after != nil {
		cursor = *after
	}
	// Row-value comparison keeps equal timestamps stable. The cursor start uses
	// sequence 0 so the first sample at `from` is included.
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, payload_bytes, request_sha256, collected_at, received_at
		FROM device_evidence
		WHERE deployment_id=$1 AND device_id=$2 AND collected_at < $3 AND (collected_at, sequence) > ($4, $5)
		ORDER BY collected_at, sequence LIMIT $6`,
		s.deploymentID, deviceID, to, cursor.collectedAt, int64(cursor.sequence), limit+1)
	if err != nil {
		return contracts.TelemetryHistoryV1{}, repositoryUnavailable(err)
	}
	defer rows.Close()
	page := contracts.TelemetryHistoryV1{SchemaVersion: contracts.TelemetryHistoryV1Version, DeploymentID: s.deploymentID,
		DeviceID: deviceID, From: from, To: to, Samples: []contracts.HistorySampleV1{}}
	for rows.Next() {
		var sample contracts.HistorySampleV1
		var payload, digest []byte
		if err := rows.Scan(&sample.Sequence, &payload, &digest, &sample.CollectedAt, &sample.ReceivedAt); err != nil {
			return contracts.TelemetryHistoryV1{}, repositoryUnavailable(err)
		}
		var telemetry contracts.TelemetryV2
		if err := json.Unmarshal(payload, &telemetry); err != nil {
			return contracts.TelemetryHistoryV1{}, repositoryUnavailable(fmt.Errorf("stored sample %d: %w", sample.Sequence, err))
		}
		sample.Source, sample.Metrics, sample.LogReferences = telemetry.Source, telemetry.Metrics, telemetry.LogReferences
		sample.CollectedAt, sample.ReceivedAt = sample.CollectedAt.UTC(), sample.ReceivedAt.UTC()
		sample.RequestSHA256 = hex.EncodeToString(digest)
		page.Samples = append(page.Samples, sample)
	}
	if err := rows.Err(); err != nil {
		return contracts.TelemetryHistoryV1{}, repositoryUnavailable(err)
	}
	if len(page.Samples) > limit {
		page.Samples = page.Samples[:limit]
		last := page.Samples[limit-1]
		next := historyCursor{collectedAt: last.CollectedAt, sequence: last.Sequence}.String()
		page.NextAfter = &next
	}
	return page, nil
}

func (s *DeviceStateService) history(w http.ResponseWriter, r *http.Request) {
	query, err := s.parseQuery(r, "deployment_id", "from", "to", "limit", "after")
	if err != nil {
		deviceStateError(w, err)
		return
	}
	var window [2]time.Time
	for i, key := range []string{"from", "to"} {
		values, ok := query[key]
		if !ok {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
		if window[i], err = time.Parse(time.RFC3339Nano, values[0]); err != nil {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
	}
	limit := contracts.TelemetryHistoryPageDefaultV1
	if values, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > contracts.TelemetryHistoryPageMaxV1 || values[0] != strconv.Itoa(limit) {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
	}
	var after *historyCursor
	if values, ok := query["after"]; ok {
		cursor, err := parseHistoryCursor(values[0])
		if err != nil {
			deviceStateError(w, err)
			return
		}
		after = &cursor
	}
	page, err := s.repository.TelemetryHistory(r.Context(), r.PathValue("id"), window[0], window[1], after, limit)
	if err != nil {
		deviceStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}
