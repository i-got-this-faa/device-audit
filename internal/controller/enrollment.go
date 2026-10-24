package controller

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const maxEnrollmentBodyBytes = 16 << 10

type EnrollmentService struct {
	repository *PostgresRepository
	admin      *auth.Service
}

func NewEnrollmentService(repository *PostgresRepository, admin *auth.Service) (*EnrollmentService, error) {
	if repository == nil || admin == nil {
		return nil, errors.New("enrollment requires a durable repository and administrator authentication")
	}
	return &EnrollmentService{repository: repository, admin: admin}, nil
}

func (s *EnrollmentService) Register(mux *http.ServeMux) {
	mux.Handle("POST /admin/bootstrap-tokens", enrollmentTLS(s.admin.RequireFreshAdmin(http.HandlerFunc(s.issueToken))))
	mux.Handle("POST /v1/enrollment/challenges", enrollmentTLS(http.HandlerFunc(s.start)))
	mux.Handle("POST /v1/enrollment", enrollmentTLS(http.HandlerFunc(s.admit)))
}

func enrollmentTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.TLS == nil {
			enrollmentError(w, "tls_required", http.StatusForbidden)
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			enrollmentError(w, contracts.EnvelopeRejectionInvalidPayload, http.StatusBadRequest)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func decodeEnrollmentBody(w http.ResponseWriter, r *http.Request, value interface{ Validate() error }) bool {
	contentType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || contentType != "application/json" {
		enrollmentError(w, contracts.EnvelopeRejectionInvalidPayload, http.StatusBadRequest)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollmentBodyBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(value); err != nil {
		enrollmentError(w, contracts.EnvelopeRejectionInvalidPayload, http.StatusBadRequest)
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		enrollmentError(w, contracts.EnvelopeRejectionInvalidPayload, http.StatusBadRequest)
		return false
	}
	if err := value.Validate(); err != nil {
		enrollmentError(w, contracts.EnvelopeRejectionInvalidPayload, http.StatusBadRequest)
		return false
	}
	return true
}

func bootstrapBearer(r *http.Request) (string, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return "", false
	}
	value := strings.TrimPrefix(values[0], "Bearer ")
	return value, len(value) == contracts.BootstrapSecretBytes*2
}

func (s *EnrollmentService) issueToken(w http.ResponseWriter, r *http.Request) {
	var request contracts.BootstrapTokenRequestV1
	if !decodeEnrollmentBody(w, r, &request) {
		return
	}
	issuer, subject, ok := auth.SessionIdentity(r.Context())
	if !ok {
		enrollmentError(w, contracts.EnvelopeRejectionBootstrapInvalid, http.StatusForbidden)
		return
	}
	result, err := s.repository.IssueBootstrapToken(r.Context(), request, issuer, subject)
	if err != nil {
		enrollmentRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (s *EnrollmentService) start(w http.ResponseWriter, r *http.Request) {
	token, ok := bootstrapBearer(r)
	if !ok {
		enrollmentError(w, contracts.EnvelopeRejectionBootstrapInvalid, http.StatusForbidden)
		return
	}
	var request contracts.EnrollmentStartV1
	if !decodeEnrollmentBody(w, r, &request) {
		return
	}
	result, err := s.repository.StartEnrollment(r.Context(), token, request)
	if err != nil {
		enrollmentRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *EnrollmentService) admit(w http.ResponseWriter, r *http.Request) {
	token, ok := bootstrapBearer(r)
	if !ok {
		enrollmentError(w, contracts.EnvelopeRejectionBootstrapInvalid, http.StatusForbidden)
		return
	}
	var request contracts.EnrollmentAdmissionV1
	if !decodeEnrollmentBody(w, r, &request) {
		return
	}
	result, err := s.repository.AdmitEnrollment(r.Context(), token, request)
	if err != nil {
		enrollmentRepositoryError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func enrollmentError(w http.ResponseWriter, reason string, status int) {
	writeJSON(w, status, contracts.EnrollmentErrorV1{SchemaVersion: contracts.EnrollmentErrorV1Version, Reason: reason})
}

func enrollmentRepositoryError(w http.ResponseWriter, err error) {
	var rejection *RepositoryRejection
	if !errors.As(err, &rejection) {
		enrollmentError(w, contracts.EnvelopeRejectionStorageUnavailable, http.StatusServiceUnavailable)
		return
	}
	status := http.StatusForbidden
	switch rejection.Reason {
	case contracts.EnvelopeRejectionInvalidPayload:
		status = http.StatusBadRequest
	case contracts.EnvelopeRejectionChallengeReused, contracts.EnvelopeRejectionEnrollmentConflict:
		status = http.StatusConflict
	case contracts.EnvelopeRejectionStorageUnavailable:
		status = http.StatusServiceUnavailable
	}
	enrollmentError(w, rejection.Reason, status)
}
