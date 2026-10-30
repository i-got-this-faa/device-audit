package controller

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

type InventoryService struct {
	repository *PostgresRepository
	auth       *auth.Service
}

func NewInventoryService(repository *PostgresRepository, consoleAuth *auth.Service) (*InventoryService, error) {
	if repository == nil || consoleAuth == nil {
		return nil, errors.New("inventory requires a durable repository and console authentication")
	}
	return &InventoryService{repository: repository, auth: consoleAuth}, nil
}

func (s *InventoryService) Register(mux *http.ServeMux) {
	mux.Handle("GET /console/api/devices/{id}/inventory", s.auth.RequireRole(auth.RoleViewer, http.HandlerFunc(s.read)))
	mux.Handle("PUT /console/api/devices/{id}/inventory", s.auth.RequireFreshAdmin(http.HandlerFunc(s.update)))
}

func (s *InventoryService) read(w http.ResponseWriter, r *http.Request) {
	query, err := parseInventoryRevision(r)
	if err != nil {
		http.Error(w, "invalid revision query", http.StatusBadRequest)
		return
	}
	record, err := s.repository.Inventory(r.Context(), r.PathValue("id"), query)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func parseInventoryRevision(r *http.Request) (uint64, error) {
	// ParseQuery errors must not silently discard malformed query parameters.
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, err
	}
	if len(query) == 0 && !r.URL.ForceQuery {
		return 0, nil
	}
	values := query["revision"]
	if len(query) != 1 || len(values) != 1 || values[0] == "" {
		return 0, ErrInventoryInvalid
	}
	for _, c := range values[0] {
		if c < '0' || c > '9' {
			return 0, ErrInventoryInvalid
		}
	}
	revision, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || revision == 0 || revision > contracts.MaxInventoryRevisionV1 {
		return 0, ErrInventoryInvalid
	}
	return revision, nil
}

func (s *InventoryService) update(w http.ResponseWriter, r *http.Request) {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "expected inventory JSON without query parameters", http.StatusBadRequest)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	var update contracts.InventoryUpdateV1
	if err := decoder.Decode(&update); err != nil {
		inventoryError(w, ErrInventoryInvalid)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		inventoryError(w, ErrInventoryInvalid)
		return
	}
	if update.DeviceID != r.PathValue("id") {
		inventoryError(w, ErrInventoryInvalid)
		return
	}
	issuer, subject, ok := auth.SessionIdentity(r.Context())
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	record, err := s.repository.UpdateInventory(r.Context(), update, issuer, subject)
	if err != nil {
		inventoryError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func inventoryError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrRepositoryNotFound):
		http.Error(w, "inventory or enrolled device not found", http.StatusNotFound)
	case errors.Is(err, ErrInventoryConflict):
		http.Error(w, "inventory revision conflict; reload before updating", http.StatusConflict)
	case errors.Is(err, ErrInventoryRevoked):
		http.Error(w, "device is revoked", http.StatusConflict)
	case errors.Is(err, ErrInventoryInvalid):
		http.Error(w, "invalid inventory update", http.StatusBadRequest)
	default:
		http.Error(w, "inventory unavailable", http.StatusServiceUnavailable)
	}
}
