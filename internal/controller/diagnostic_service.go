package controller

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

// DiagnosticService exposes authenticated console administration and viewer
// endpoints for signing, cancelling, and querying diagnostic assignments.
type DiagnosticService struct {
	repository workflows.AssignmentCoordinator
	deployment string
	auth       *auth.Service
	signer     ed25519.PrivateKey
	forecasts  *PostgresRepository
}

func NewDiagnosticService(repository *PostgresRepository, consoleAuth *auth.Service, signer ed25519.PrivateKey) (*DiagnosticService, error) {
	if repository == nil || consoleAuth == nil || len(signer) != ed25519.PrivateKeySize {
		return nil, errors.New("diagnostics service requires repository, console authentication and an Ed25519 signing key")
	}
	return &DiagnosticService{
		repository: repository,
		deployment: repository.deploymentID,
		auth:       consoleAuth,
		signer:     signer,
		forecasts:  repository,
	}, nil
}

func (s *DiagnosticService) Register(mux *http.ServeMux) {
	mux.Handle("POST /console/api/diagnostics/assignments", s.auth.RequireFreshAdmin(http.HandlerFunc(s.create)))
	mux.Handle("POST /console/api/diagnostics/assignments/{id}/cancel", s.auth.RequireFreshAdmin(http.HandlerFunc(s.cancel)))
	mux.Handle("GET /console/api/diagnostics/assignments/{id}", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.get)))
	mux.Handle("POST /console/api/devices/{id}/forecast-diagnostics", s.auth.RequireFreshAdmin(http.HandlerFunc(s.triggerForecast)))
	mux.Handle("GET /console/api/devices/{id}/forecast-diagnostics", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.forecastTrace)))
	mux.Handle("GET /console/api/devices/{id}/diagnostics/assignments", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.listForDevice)))
}

func (s *DiagnosticService) create(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "unexpected query parameters", http.StatusBadRequest)
		return
	}
	ct, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || ct != "application/json" {
		http.Error(w, "application/json content type required", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var req workflows.AssignmentRequest
	if err := dec.Decode(&req); err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid diagnostic assignment request", http.StatusBadRequest)
		return
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		http.Error(w, "trailing JSON content", http.StatusBadRequest)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	rec, created, err := s.repository.CreateDiagnosticAssignment(r.Context(), req, s.signer, workflows.Actor(actor))
	writeDiagnosticResult(w, rec, created, err)
}

func (s *DiagnosticService) cancel(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "unexpected query parameters", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	if body, err := io.ReadAll(r.Body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	} else if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 && string(trimmed) != "{}" {
		http.Error(w, "cancel accepts only empty body or {}", http.StatusBadRequest)
		return
	}
	actor, ok := sessionActor(w, r)
	if !ok {
		return
	}
	rec, err := s.repository.CancelDiagnosticAssignment(r.Context(), r.PathValue("id"), workflows.Actor(actor))
	writeDiagnosticResult(w, rec, false, err)
}

func (s *DiagnosticService) get(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, vals := range q {
		if k != "deployment_id" || len(vals) != 1 {
			http.Error(w, "invalid query parameters", http.StatusBadRequest)
			return
		}
	}
	dep := q.Get("deployment_id")
	if !repositoryIDPattern.MatchString(dep) {
		http.Error(w, "valid deployment_id is required", http.StatusBadRequest)
		return
	}
	if dep != s.deployment {
		http.Error(w, "forbidden deployment scope", http.StatusForbidden)
		return
	}
	rec, err := s.repository.DiagnosticAssignment(r.Context(), r.PathValue("id"))
	writeDiagnosticResult(w, rec, false, err)
}

func (s *DiagnosticService) listForDevice(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	for k, vals := range q {
		if (k != "deployment_id" && k != "limit" && k != "after") || len(vals) != 1 {
			http.Error(w, "invalid query parameters", http.StatusBadRequest)
			return
		}
	}
	dep := q.Get("deployment_id")
	if !repositoryIDPattern.MatchString(dep) {
		http.Error(w, "valid deployment_id is required", http.StatusBadRequest)
		return
	}
	if dep != s.deployment {
		http.Error(w, "forbidden deployment scope", http.StatusForbidden)
		return
	}
	limit := diagnosticPageDefault
	if raw := q.Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(parsed) != raw || parsed < 1 || parsed > diagnosticPageMax {
			http.Error(w, "invalid limit", http.StatusBadRequest)
			return
		}
		limit = parsed
	}
	page, err := s.repository.ListDeviceDiagnosticAssignments(r.Context(), r.PathValue("id"), limit, q.Get("after"))
	writeDiagnosticResult(w, page, false, err)
}

func writeDiagnosticResult(w http.ResponseWriter, value any, created bool, err error) {
	w.Header().Set("Cache-Control", "no-store")
	switch {
	case err == nil && created:
		writeJSON(w, http.StatusCreated, value)
	case err == nil:
		writeJSON(w, http.StatusOK, value)
	case errors.Is(err, ErrRepositoryNotFound), errors.Is(err, workflows.ErrAssignmentNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, workflows.ErrAssignmentInvalid), errors.Is(err, ErrDeviceStateInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, workflows.ErrAssignmentUnauthorized):
		http.Error(w, "unauthorized", http.StatusForbidden)
	case errors.Is(err, workflows.ErrAssignmentConflict), errors.Is(err, workflows.ErrAssignmentDeviceRevoked),
		errors.Is(err, workflows.ErrAssignmentExpired), errors.Is(err, workflows.ErrAssignmentReplay),
		errors.Is(err, workflows.ErrAssignmentTerminal):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, workflows.ErrAssignmentCorrupt):
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		http.Error(w, "diagnostic store unavailable", http.StatusServiceUnavailable)
	}
}
