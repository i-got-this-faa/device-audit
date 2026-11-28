package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// FaultTypeUnclassified is the type of every persisted fault report today.
// A telemetry v2 log reference names error evidence by digest and window but
// carries no fault type, and no classifier exists yet.
const FaultTypeUnclassified = "unclassified"

// DeviceFaultHistory is one device's ML10 #106 comparison with what it read.
// It is an internal Go type, not a wire contract, and no route serves it.
type DeviceFaultHistory struct {
	DeploymentID string
	DeviceID     string
	// SamplesRead counts persisted samples in both windows.
	SamplesRead int
	// LastSequence is the highest evidence sequence read, or 0 for none.
	LastSequence uint64
	History      health.FaultHistory
}

// DeviceFaultHistory compares one device's fault reports in the seven UTC days
// ending at asOf with the 21 days before them. Each telemetry log reference is
// one report of FaultTypeUnclassified, keyed by its content digest, at the
// collected_at of the sample that carried it. A sample collected after asOf is
// never read. An unknown device is ErrRepositoryNotFound, not an empty history.
//
// An empty log_references list does not show that error collection ran, so a
// sampled day without a report is "no report", not "no fault". Health rules
// that read this result (#35) must keep that distinction.
func (s *PostgresRepository) DeviceFaultHistory(ctx context.Context, deviceID string, asOf time.Time) (DeviceFaultHistory, error) {
	return s.deviceFaultHistory(ctx, s.db, deviceID, asOf)
}

func (s *PostgresRepository) deviceFaultHistory(ctx context.Context, q dbQueryer, deviceID string, asOf time.Time) (DeviceFaultHistory, error) {
	current, baseline := health.FaultWindows(asOf)
	from, to := baseline.From, current.To
	if !repositoryIDPattern.MatchString(deviceID) || to.Sub(from) > contracts.TelemetryHistoryWindowMaxV1 {
		return DeviceFaultHistory{}, ErrDeviceStateInvalid
	}
	var exists bool
	if err := q.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, deviceID).Scan(&exists); err != nil {
		return DeviceFaultHistory{}, repositoryReadError(err)
	}
	result := DeviceFaultHistory{DeploymentID: s.deploymentID, DeviceID: deviceID}
	var evidence health.FaultEvidence

	// Coverage reads no payload: a sampled day is one row however many samples it holds.
	rows, err := q.QueryContext(ctx, `SELECT date_trunc('day', collected_at AT TIME ZONE 'UTC'), count(*), max(sequence)
		FROM device_evidence WHERE deployment_id=$1 AND device_id=$2 AND collected_at >= $3 AND collected_at < $4
		GROUP BY 1 ORDER BY 1`, s.deploymentID, deviceID, from, to)
	if err != nil {
		return DeviceFaultHistory{}, repositoryUnavailable(err)
	}
	defer rows.Close()
	for rows.Next() {
		var day time.Time
		var samples int
		var last uint64
		if err := rows.Scan(&day, &samples, &last); err != nil {
			return DeviceFaultHistory{}, repositoryUnavailable(err)
		}
		evidence.SampleDays = append(evidence.SampleDays, time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC))
		result.SamplesRead += samples
		result.LastSequence = max(result.LastSequence, last)
	}
	if err := rows.Err(); err != nil {
		return DeviceFaultHistory{}, repositoryUnavailable(err)
	}
	rows.Close()

	// Only samples that carried a log reference return their references.
	rows, err = q.QueryContext(ctx, `SELECT e.sequence, e.collected_at, r.refs
		FROM device_evidence e, LATERAL (SELECT convert_from(e.payload_bytes, 'UTF8')::jsonb -> 'log_references' AS refs) r
		WHERE e.deployment_id=$1 AND e.device_id=$2 AND e.collected_at >= $3 AND e.collected_at < $4
		AND jsonb_typeof(r.refs) = 'array' AND jsonb_array_length(r.refs) > 0
		ORDER BY e.collected_at, e.sequence`, s.deploymentID, deviceID, from, to)
	if err != nil {
		return DeviceFaultHistory{}, repositoryUnavailable(err)
	}
	defer rows.Close()
	for rows.Next() {
		var sequence uint64
		var collectedAt time.Time
		var raw []byte
		if err := rows.Scan(&sequence, &collectedAt, &raw); err != nil {
			return DeviceFaultHistory{}, repositoryUnavailable(err)
		}
		var refs []contracts.LogReferenceV2
		if err := json.Unmarshal(raw, &refs); err != nil {
			return DeviceFaultHistory{}, repositoryUnavailable(fmt.Errorf("stored sample %d log references: %w", sequence, err))
		}
		for _, ref := range refs {
			evidence.Reports = append(evidence.Reports, health.FaultReport{Type: FaultTypeUnclassified, ReportedAt: collectedAt.UTC(),
				EvidenceSHA256: strings.ToLower(ref.SHA256), Sequence: sequence})
		}
	}
	if err := rows.Err(); err != nil {
		return DeviceFaultHistory{}, repositoryUnavailable(err)
	}
	if result.History, err = health.CompareFaultHistory(asOf, evidence); err != nil {
		return DeviceFaultHistory{}, fmt.Errorf("compare fault history: %w", err)
	}
	return result, nil
}
