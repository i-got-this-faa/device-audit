// Package controller implements a bounded, ephemeral telemetry scaffold.
package controller

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type Device struct {
	Telemetry      contracts.Telemetry `json:"telemetry"`
	ReceivedAt     time.Time           `json:"received_at"`
	EvidenceDigest string              `json:"evidence_digest"`
	Health         string              `json:"health"`
}

// Config describes the bounded development API and its configured dependencies.
type Config struct {
	MaxDevices     int
	DatabaseStatus string
	SchemaVersion  int
	Auth           *auth.Service
	AuthStatus     string
	Enrollment     *EnrollmentService
}

type API struct {
	mu         sync.Mutex
	devices    map[string]Device
	maxDevices int
	database   string
	schema     int
	auth       *auth.Service
	authStatus string
	enrollment *EnrollmentService
}

func NewAPI(cfg Config) *API {
	if cfg.MaxDevices < 1 {
		panic("MaxDevices must be positive")
	}
	if cfg.DatabaseStatus == "" {
		cfg.DatabaseStatus = "not_configured"
	}
	if cfg.AuthStatus == "" {
		cfg.AuthStatus = "not_configured"
	}
	return &API{
		devices:    make(map[string]Device),
		maxDevices: cfg.MaxDevices,
		database:   cfg.DatabaseStatus,
		schema:     cfg.SchemaVersion,
		auth:       cfg.Auth,
		authStatus: cfg.AuthStatus,
		enrollment: cfg.Enrollment,
	}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		enrollment := "not_configured"
		if a.enrollment != nil {
			enrollment = "configured"
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "ok",
			"mode":           "development",
			"sample_storage": "memory",
			"database":       a.database,
			"schema_version": a.schema,
			"auth":           a.authStatus,
			"mesh":           "not_implemented",
			"enrollment":     enrollment,
		})
	})
	mux.HandleFunc("POST /v1/telemetry", a.ingest)
	mux.HandleFunc("GET /v1/devices/{id}", a.device)
	if a.auth != nil {
		a.auth.Register(mux)
	}
	if a.enrollment != nil {
		a.enrollment.Register(mux)
	}
	return mux
}

func (a *API) ingest(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var t contracts.Telemetry
	if err := decoder.Decode(&t); err != nil {
		http.Error(w, "invalid telemetry JSON", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return
	}
	if err := t.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// This digest binds our normalized Go representation, not source truth or cross-language canonical JSON.
	normalized, err := json.Marshal(t)
	if err != nil {
		http.Error(w, "cannot encode telemetry", http.StatusBadRequest)
		return
	}
	digest := sha256.Sum256(normalized)
	d := Device{Telemetry: t, ReceivedAt: time.Now().UTC(), EvidenceDigest: hex.EncodeToString(digest[:]), Health: "unknown"}
	a.mu.Lock()
	_, exists := a.devices[t.DeviceID]
	if !exists && len(a.devices) >= a.maxDevices {
		a.mu.Unlock()
		http.Error(w, "development device limit reached", http.StatusServiceUnavailable)
		return
	}
	a.devices[t.DeviceID] = d
	a.mu.Unlock()
	writeJSON(w, http.StatusAccepted, d)
}

func (a *API) device(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	d, ok := a.devices[r.PathValue("id")]
	a.mu.Unlock()
	if !ok {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
