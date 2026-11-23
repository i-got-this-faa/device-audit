package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// evidenceRef is when one persisted sample was collected and its evidence
// sequence. A feature window needs nothing else while no telemetry payload holds
// a SMART counter; when one does, the reference gains that counter.
type evidenceRef struct {
	Sequence    uint64
	CollectedAt time.Time
}

// featureEvidence is the persisted-evidence read a feature window needs.
// PostgresRepository implements it.
type featureEvidence interface {
	// FeatureEvidence returns one device's sample references with from <= collected_at < to.
	FeatureEvidence(ctx context.Context, deviceID string, from, to time.Time) (deploymentID string, refs []evidenceRef, err error)
}

// DeviceFeatures is a controller-built CT03 vector with what it was built from.
// The vector names the feature version and its window dates. SamplesRead and
// LastSequence let a caller see which persisted evidence the window held; they
// are not a wire contract, and no endpoint serves this yet.
type DeviceFeatures struct {
	DeploymentID string
	DeviceID     string
	Vector       contracts.FeatureVectorV1
	// SamplesRead counts persisted samples with collected_at inside the window.
	SamplesRead int
	// LastSequence is the highest evidence sequence read, or 0 for none.
	LastSequence uint64
}

// BuildDeviceFeatures reads one device's persisted samples for the seven UTC
// days ending on the day of asOf and runs the same health.Preprocess the
// endpoint runs. A sample collected after asOf is never read, whatever order
// it arrived in. Missing counters stay missing: telemetry v2 holds no SMART
// counter, so every persisted window gives an incomplete vector today.
func BuildDeviceFeatures(ctx context.Context, evidence featureEvidence, deviceID string, asOf time.Time) (DeviceFeatures, error) {
	return buildDeviceFeatures(ctx, evidence, deviceID, asOf, func(r evidenceRef) health.SMARTReading {
		return health.SMARTReading{ObservedAt: r.CollectedAt}
	})
}

// buildDeviceFeatures takes the reference-to-reading step as a parameter so a
// test can supply known counters. Persisted telemetry v2 carries none, so
// production reads every counter as not observed.
func buildDeviceFeatures(ctx context.Context, evidence featureEvidence, deviceID string, asOf time.Time, read func(evidenceRef) health.SMARTReading) (DeviceFeatures, error) {
	asOf = asOf.UTC()
	end := time.Date(asOf.Year(), asOf.Month(), asOf.Day(), 0, 0, 0, 0, time.UTC)
	from := end.AddDate(0, 0, -(contracts.FeatureWindowDays - 1))
	// The window excludes its end, in microseconds. Add one to keep asOf.
	to := asOf.Truncate(time.Microsecond).Add(time.Microsecond)

	deploymentID, refs, err := evidence.FeatureEvidence(ctx, deviceID, from, to)
	if err != nil {
		return DeviceFeatures{}, fmt.Errorf("read feature window: %w", err)
	}
	result := DeviceFeatures{DeploymentID: deploymentID, DeviceID: deviceID, SamplesRead: len(refs)}
	readings := make([]health.SMARTReading, len(refs))
	for i, ref := range refs {
		readings[i] = read(ref)
		result.LastSequence = max(result.LastSequence, ref.Sequence)
	}
	if result.Vector, err = health.Preprocess(asOf, readings); err != nil {
		return DeviceFeatures{}, err
	}
	return result, nil
}

// FeatureEvidence reads only the collection time and sequence of one device's
// samples in one query. It does not decode payloads: none holds a SMART counter,
// and 37,000 decoded payloads cost seconds and 450 MB for a 15 s sampler's week.
// An unknown device is ErrRepositoryNotFound, not an empty window.
func (s *PostgresRepository) FeatureEvidence(ctx context.Context, deviceID string, from, to time.Time) (string, []evidenceRef, error) {
	from, to = from.UTC().Truncate(time.Microsecond), to.UTC().Truncate(time.Microsecond)
	if !repositoryIDPattern.MatchString(deviceID) || !from.Before(to) || to.Sub(from) > contracts.TelemetryHistoryWindowMaxV1 {
		return "", nil, ErrDeviceStateInvalid
	}
	var exists bool
	if err := s.db.QueryRowContext(ctx, `SELECT true FROM device_enrollments WHERE deployment_id=$1 AND device_id=$2`, s.deploymentID, deviceID).Scan(&exists); err != nil {
		return "", nil, repositoryReadError(err)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, collected_at FROM device_evidence
		WHERE deployment_id=$1 AND device_id=$2 AND collected_at >= $3 AND collected_at < $4
		ORDER BY collected_at, sequence`, s.deploymentID, deviceID, from, to)
	if err != nil {
		return "", nil, repositoryUnavailable(err)
	}
	defer rows.Close()
	var refs []evidenceRef
	for rows.Next() {
		var ref evidenceRef
		if err := rows.Scan(&ref.Sequence, &ref.CollectedAt); err != nil {
			return "", nil, repositoryUnavailable(err)
		}
		ref.CollectedAt = ref.CollectedAt.UTC()
		refs = append(refs, ref)
	}
	if err := rows.Err(); err != nil {
		return "", nil, repositoryUnavailable(err)
	}
	return s.deploymentID, refs, nil
}
