package controller

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"

	webconsole "github.com/i-got-this-faa/device-audit/apps/web-console"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

var (
	ErrDeviceStateInvalid = errors.New("invalid device state query")
	// ErrDeviceStateScope means the caller selected a deployment this controller does not serve.
	ErrDeviceStateScope = errors.New("selected deployment is not served by this controller")
)

const deviceStateSelect = `SELECT d.device_id, d.signing_key_id, d.enrolled_at, d.revoked_at, d.last_sequence,
	e.payload_bytes, e.request_sha256, e.collected_at, e.received_at
	FROM device_enrollments d
	LEFT JOIN device_evidence e ON e.deployment_id=d.deployment_id AND e.device_id=d.device_id AND e.sequence=d.last_sequence
	WHERE d.deployment_id=$1`

type deviceStateScanner interface{ Scan(...any) error }

func (s *PostgresRepository) scanDeviceState(row deviceStateScanner) (contracts.DeviceStateV1, error) {
	state := contracts.DeviceStateV1{SchemaVersion: contracts.DeviceStateV1Version, DeploymentID: s.deploymentID}
	var payload, digest []byte
	var collectedAt, receivedAt *time.Time
	if err := row.Scan(&state.DeviceID, &state.SigningKeyID, &state.EnrolledAt, &state.RevokedAt, &state.LastSequence,
		&payload, &digest, &collectedAt, &receivedAt); err != nil {
		return contracts.DeviceStateV1{}, repositoryReadError(err)
	}
	state.EnrolledAt = state.EnrolledAt.UTC()
	if state.RevokedAt != nil {
		revoked := state.RevokedAt.UTC()
		state.RevokedAt = &revoked
	}
	if payload == nil {
		return state, nil
	}
	var telemetry contracts.TelemetryV2
	if err := json.Unmarshal(payload, &telemetry); err != nil {
		return contracts.DeviceStateV1{}, repositoryUnavailable(err)
	}
	state.Latest = &contracts.LatestSampleV1{
		Sequence: state.LastSequence, Source: telemetry.Source, CollectedAt: collectedAt.UTC(), ReceivedAt: receivedAt.UTC(),
		RequestSHA256: hex.EncodeToString(digest), Metrics: telemetry.Metrics, Sensors: contracts.SensorStates(telemetry.Metrics),
	}
	return state, nil
}

// DeviceState returns one enrolled device and its latest durable sample.
func (s *PostgresRepository) DeviceState(ctx context.Context, deviceID string) (contracts.DeviceStateV1, error) {
	if !repositoryIDPattern.MatchString(deviceID) {
		return contracts.DeviceStateV1{}, ErrDeviceStateInvalid
	}
	return s.scanDeviceState(s.db.QueryRowContext(ctx, deviceStateSelect+` AND d.device_id=$2`, s.deploymentID, deviceID))
}

// DeviceStates returns up to limit devices after the cursor, ordered by device
// ID. An empty cursor starts at the beginning.
func (s *PostgresRepository) DeviceStates(ctx context.Context, after string, limit int) (contracts.DeviceStatePageV1, error) {
	if limit < 1 || limit > contracts.DeviceStatePageMaxV1 || (after != "" && !repositoryIDPattern.MatchString(after)) {
		return contracts.DeviceStatePageV1{}, ErrDeviceStateInvalid
	}
	// Fetch one extra row to learn whether another page exists.
	rows, err := s.db.QueryContext(ctx, deviceStateSelect+` AND d.device_id > $2 ORDER BY d.device_id LIMIT $3`, s.deploymentID, after, limit+1)
	if err != nil {
		return contracts.DeviceStatePageV1{}, repositoryUnavailable(err)
	}
	defer rows.Close()
	page := contracts.DeviceStatePageV1{SchemaVersion: contracts.DeviceStatePageV1Version, DeploymentID: s.deploymentID, Devices: []contracts.DeviceStateV1{}}
	for rows.Next() {
		state, err := s.scanDeviceState(rows)
		if err != nil {
			return contracts.DeviceStatePageV1{}, err
		}
		page.Devices = append(page.Devices, state)
	}
	if err := rows.Err(); err != nil {
		return contracts.DeviceStatePageV1{}, repositoryUnavailable(err)
	}
	if len(page.Devices) > limit {
		page.Devices = page.Devices[:limit]
		next := page.Devices[limit-1].DeviceID
		page.NextAfter = &next
	}
	return page, nil
}

// ConsoleDevices gives console pages the same durable reads as the device
// state API, with errors mapped to the console's not-found and invalid cases.
func (s *PostgresRepository) ConsoleDevices() webconsole.DeviceReader { return consoleDevices{s} }

type consoleDevices struct{ repository *PostgresRepository }

func (c consoleDevices) DeviceStates(ctx context.Context, after string, limit int) (contracts.DeviceStatePageV1, error) {
	page, err := c.repository.DeviceStates(ctx, after, limit)
	return page, consoleDeviceError(err)
}

func (c consoleDevices) DeviceState(ctx context.Context, deviceID string) (contracts.DeviceStateV1, error) {
	state, err := c.repository.DeviceState(ctx, deviceID)
	return state, consoleDeviceError(err)
}

func (c consoleDevices) TelemetryHistory(ctx context.Context, deviceID string, from, to time.Time, after string, limit int) (contracts.TelemetryHistoryV1, error) {
	var cursor *historyCursor
	if after != "" {
		parsed, err := parseHistoryCursor(after)
		if err != nil {
			return contracts.TelemetryHistoryV1{}, consoleDeviceError(err)
		}
		cursor = &parsed
	}
	page, err := c.repository.TelemetryHistory(ctx, deviceID, from, to, cursor, limit)
	return page, consoleDeviceError(err)
}

func consoleDeviceError(err error) error {
	switch {
	case errors.Is(err, ErrRepositoryNotFound):
		return fmt.Errorf("%w: %w", webconsole.ErrDeviceNotFound, err)
	case errors.Is(err, ErrDeviceStateInvalid):
		return fmt.Errorf("%w: %w", webconsole.ErrDeviceQueryInvalid, err)
	}
	return err
}

// DeviceStateService serves the viewer-scoped fleet inventory.
type DeviceStateService struct {
	repository *PostgresRepository
	auth       *auth.Service
}

func NewDeviceStateService(repository *PostgresRepository, consoleAuth *auth.Service) (*DeviceStateService, error) {
	if repository == nil || consoleAuth == nil {
		return nil, errors.New("device state requires a durable repository and console authentication")
	}
	return &DeviceStateService{repository: repository, auth: consoleAuth}, nil
}

func (s *DeviceStateService) Register(mux *http.ServeMux) {
	mux.Handle("GET /console/api/devices", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.list)))
	mux.Handle("GET /console/api/devices/{id}", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.detail)))
	mux.Handle("GET /console/api/devices/{id}/history", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.history)))
	mux.Handle("GET /console/api/devices/{id}/predictions", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.predictions)))
	mux.Handle("GET /console/api/devices/{id}/predictions/latest", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.latestPrediction)))
}

// parseDeviceStateQuery requires an explicit deployment_id so a client cannot
// read another deployment by accident; only the listed keys are accepted.
func (s *DeviceStateService) parseQuery(r *http.Request, allowed ...string) (url.Values, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, ErrDeviceStateInvalid
	}
	for key, values := range query {
		if len(values) != 1 {
			return nil, ErrDeviceStateInvalid
		}
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known {
			return nil, ErrDeviceStateInvalid
		}
	}
	deployment, ok := query["deployment_id"]
	if !ok || deployment[0] == "" {
		return nil, ErrDeviceStateInvalid
	}
	if deployment[0] != s.repository.deploymentID {
		return nil, ErrDeviceStateScope
	}
	return query, nil
}

func (s *DeviceStateService) list(w http.ResponseWriter, r *http.Request) {
	query, err := s.parseQuery(r, "deployment_id", "limit", "after")
	if err != nil {
		deviceStateError(w, err)
		return
	}
	limit := contracts.DeviceStatePageDefaultV1
	if values, ok := query["limit"]; ok {
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > contracts.DeviceStatePageMaxV1 || values[0] != strconv.Itoa(limit) {
			deviceStateError(w, ErrDeviceStateInvalid)
			return
		}
	}
	page, err := s.repository.DeviceStates(r.Context(), query.Get("after"), limit)
	if err != nil {
		deviceStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *DeviceStateService) detail(w http.ResponseWriter, r *http.Request) {
	if _, err := s.parseQuery(r, "deployment_id"); err != nil {
		deviceStateError(w, err)
		return
	}
	state, err := s.repository.DeviceState(r.Context(), r.PathValue("id"))
	if err != nil {
		deviceStateError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func deviceStateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrDeviceStateScope):
		http.Error(w, "selected deployment is not available", http.StatusForbidden)
	case errors.Is(err, ErrDeviceStateInvalid), errors.Is(err, ErrPredictionInvalid):
		http.Error(w, "invalid device query", http.StatusBadRequest)
	case errors.Is(err, ErrRepositoryNotFound):
		http.Error(w, "device not found", http.StatusNotFound)
	case errors.Is(err, ErrPredictionEvidenceBroken):
		http.Error(w, "prediction evidence reference failed integrity check", http.StatusInternalServerError)
	default:
		http.Error(w, "device inventory unavailable", http.StatusServiceUnavailable)
	}
}
