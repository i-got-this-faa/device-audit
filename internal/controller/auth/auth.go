// Package auth implements the console's OIDC login, server-side sessions and
// role-based authorization. It does not create accounts or infer roles from
// identity-provider claims.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	webconsole "github.com/i-got-this-faa/device-audit/apps/web-console"
)

type Role string

const (
	RoleViewer Role = "viewer"
	RoleAdmin  Role = "admin"
)

func (r Role) Valid() bool {
	return r == RoleViewer || r == RoleAdmin
}

// Allows reports whether this role has the required role. Admin inherits viewer.
func (r Role) Allows(required Role) bool {
	return r == RoleAdmin || r == required
}

type LoginTransaction struct {
	StateDigest  []byte
	Nonce        string
	CodeVerifier string
	ReturnTo     string
	CreatedAt    time.Time
	ExpiresAt    time.Time
}

type Session struct {
	IDDigest          []byte
	CSRFToken         string
	Issuer            string
	Subject           string
	Role              Role
	CreatedAt         time.Time
	AuthenticatedAt   time.Time
	LastSeenAt        time.Time
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
	RevokedAt         *time.Time
}

type Binding struct {
	Issuer    string    `json:"issuer"`
	Subject   string    `json:"subject"`
	Role      Role      `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

var (
	ErrNotFound  = errors.New("console auth record not found")
	ErrLastAdmin = errors.New("console role change would remove the last admin")
)

// Store is the durable authorization and session boundary. An error other than
// ErrNotFound or ErrLastAdmin must be treated as an unavailable store and fail
// closed.
type Store interface {
	PutLogin(ctx context.Context, transaction LoginTransaction) error
	// ConsumeLogin atomically consumes an unexpired, unused transaction.
	ConsumeLogin(ctx context.Context, stateDigest []byte, now time.Time) (LoginTransaction, error)
	CreateSession(ctx context.Context, session Session) error
	Session(ctx context.Context, idDigest []byte) (Session, error)
	TouchSession(ctx context.Context, idDigest []byte, now, idleExpires time.Time) error
	RevokeSession(ctx context.Context, idDigest []byte, now time.Time) error
	Binding(ctx context.Context, issuer, subject string) (Binding, error)
	// CreateBinding inserts only when the issuer and subject are absent. It must
	// not change an existing role.
	CreateBinding(ctx context.Context, binding Binding) error
	// UpsertBinding atomically revokes subject sessions when the role changes.
	UpsertBinding(ctx context.Context, binding Binding) error
	Bindings(ctx context.Context, issuer string) ([]Binding, error)
	RevokeSubjectSessions(ctx context.Context, issuer, subject string, now time.Time) error
}

const (
	defaultSessionCookie = "__Host-device-audit-session"
	defaultLoginCookie   = "__Host-device-audit-login"
	defaultSessionIdle   = 15 * time.Minute
	defaultSessionMax    = 8 * time.Hour
	defaultLoginLifetime = 5 * time.Minute
)

// Config describes one configured OIDC deployment. Issuer and PublicOrigin are
// operator configuration, never values supplied by a request.
type Config struct {
	Issuer          string
	PublicOrigin    string
	Store           Store
	Provider        IdentityProvider
	Logger          *slog.Logger
	Now             func() time.Time
	SessionCookie   string
	LoginCookie     string
	SessionIdle     time.Duration
	SessionAbsolute time.Duration
	LoginLifetime   time.Duration
	RequiredAMR     string
}

type Service struct {
	issuer          string
	publicOrigin    string
	store           Store
	provider        IdentityProvider
	logger          *slog.Logger
	now             func() time.Time
	sessionCookie   string
	loginCookie     string
	sessionIdle     time.Duration
	sessionAbsolute time.Duration
	loginLifetime   time.Duration
	requiredAMR     string
}

func NewService(cfg Config) (*Service, error) {
	if cfg.Issuer == "" {
		return nil, errors.New("OIDC issuer is required")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" || issuer.User != nil || issuer.RawQuery != "" || issuer.Fragment != "" {
		return nil, errors.New("OIDC issuer must be an absolute URL without a query or fragment")
	}
	if issuer.Scheme != "https" && !(issuer.Scheme == "http" && isLoopbackHost(issuer.Hostname())) {
		return nil, errors.New("OIDC issuer must use https outside loopback development")
	}
	origin, err := url.Parse(cfg.PublicOrigin)
	if err != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || (origin.Path != "" && origin.Path != "/") || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("public origin must be an absolute scheme and host without a path")
	}
	if origin.Scheme != "https" && !(origin.Scheme == "http" && isLoopbackHost(origin.Hostname())) {
		return nil, errors.New("public origin must use https outside loopback development")
	}
	publicOrigin := origin.Scheme + "://" + origin.Host
	if cfg.Store == nil {
		return nil, errors.New("console auth store is required")
	}
	if cfg.Provider == nil {
		return nil, errors.New("OIDC provider is required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.SessionCookie == "" {
		cfg.SessionCookie = defaultSessionCookie
	}
	if cfg.LoginCookie == "" {
		cfg.LoginCookie = defaultLoginCookie
	}
	if cfg.SessionIdle <= 0 {
		cfg.SessionIdle = defaultSessionIdle
	}
	if cfg.SessionAbsolute <= 0 {
		cfg.SessionAbsolute = defaultSessionMax
	}
	if cfg.LoginLifetime <= 0 {
		cfg.LoginLifetime = defaultLoginLifetime
	}
	if cfg.SessionIdle > cfg.SessionAbsolute {
		return nil, errors.New("session idle lifetime cannot exceed absolute lifetime")
	}
	return &Service{
		issuer:          cfg.Issuer,
		publicOrigin:    publicOrigin,
		store:           cfg.Store,
		provider:        cfg.Provider,
		logger:          cfg.Logger,
		now:             cfg.Now,
		sessionCookie:   cfg.SessionCookie,
		loginCookie:     cfg.LoginCookie,
		sessionIdle:     cfg.SessionIdle,
		sessionAbsolute: cfg.SessionAbsolute,
		loginLifetime:   cfg.LoginLifetime,
		requiredAMR:     strings.TrimSpace(cfg.RequiredAMR),
	}, nil
}

func isLoopbackHost(host string) bool {
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

// EnsureBinding preprovisions an operator-managed local role when the subject
// has no binding. It never changes an existing role; use the admin API for that.
func (s *Service) EnsureBinding(ctx context.Context, subject string, role Role) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return errors.New("binding subject is required")
	}
	if !role.Valid() {
		return errors.New("binding role must be viewer or admin")
	}
	now := s.now().UTC()
	return s.store.CreateBinding(ctx, Binding{Issuer: s.issuer, Subject: subject, Role: role, CreatedAt: now, UpdatedAt: now})
}

func (s *Service) Register(mux *http.ServeMux) {
	webconsole.RegisterAssets(mux)
	mux.HandleFunc("GET /auth/login", s.login)
	mux.HandleFunc("GET /auth/callback", s.callback)
	mux.Handle("GET /auth/session", s.RequireSession(http.HandlerFunc(s.sessionInfo)))
	mux.Handle("POST /auth/logout", s.RequireSession(http.HandlerFunc(s.logout)))
	mux.HandleFunc("GET /signed-out", s.signedOut)
	mux.Handle("GET /console", s.RequireRole(RoleViewer, http.HandlerFunc(s.console)))
	mux.Handle("GET /console/devices", s.RequireRole(RoleViewer, http.HandlerFunc(s.console)))
	mux.Handle("GET /console/devices/{device}", s.RequireRole(RoleViewer, http.HandlerFunc(s.console)))
	mux.Handle("GET /console/workflows", s.RequireRole(RoleViewer, http.HandlerFunc(s.console)))
	mux.Handle("GET /console/access", s.RequireRole(RoleAdmin, http.HandlerFunc(s.console)))
	mux.Handle("GET /admin/role-bindings", s.RequireRole(RoleAdmin, http.HandlerFunc(s.listBindings)))
	mux.Handle("POST /admin/role-bindings", s.RequireFreshAdmin(http.HandlerFunc(s.upsertBinding)))
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/console"
	}
	if !allowedReturnTo(returnTo) {
		http.Error(w, "invalid login return path", http.StatusBadRequest)
		return
	}
	state, err := randomToken(32)
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	verifier, err := randomToken(32)
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		http.Error(w, "cannot start login", http.StatusInternalServerError)
		return
	}
	now := s.now().UTC()
	transaction := LoginTransaction{
		StateDigest:  digest(state),
		Nonce:        nonce,
		CodeVerifier: verifier,
		ReturnTo:     returnTo,
		CreatedAt:    now,
		ExpiresAt:    now.Add(s.loginLifetime),
	}
	if err := s.store.PutLogin(r.Context(), transaction); err != nil {
		s.logger.Error("console login transaction failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	authorizationURL, err := s.provider.AuthCodeURL(r.Context(), state, nonce, verifier)
	if err != nil {
		s.logger.Error("oidc discovery failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, s.cookie(s.loginCookie, base64.RawURLEncoding.EncodeToString(transaction.StateDigest), now.Add(s.loginLifetime)))
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	s.clearCookie(w, s.loginCookie)
	if errorCode := r.URL.Query().Get("error"); errorCode != "" {
		s.rejectLogin(w, "provider_error", http.StatusBadRequest, nil)
		return
	}
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" {
		s.rejectLogin(w, "missing_state_or_code", http.StatusBadRequest, nil)
		return
	}
	cookie, err := r.Cookie(s.loginCookie)
	if err != nil {
		s.rejectLogin(w, "missing_login_cookie", http.StatusBadRequest, nil)
		return
	}
	cookieDigest, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(cookieDigest) != sha256.Size {
		s.rejectLogin(w, "invalid_login_cookie", http.StatusBadRequest, nil)
		return
	}
	stateDigest := digest(state)
	if subtle.ConstantTimeCompare(cookieDigest, stateDigest) != 1 {
		s.rejectLogin(w, "state_mismatch", http.StatusBadRequest, nil)
		return
	}
	now := s.now().UTC()
	transaction, err := s.store.ConsumeLogin(r.Context(), stateDigest, now)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.rejectLogin(w, "transaction_invalid", http.StatusBadRequest, nil)
			return
		}
		s.logger.Error("console login transaction read failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	identity, err := s.provider.Exchange(r.Context(), code, transaction.CodeVerifier)
	if err != nil {
		s.rejectLogin(w, "identity_rejected", http.StatusBadRequest, err)
		return
	}
	if identity.Issuer != s.issuer || subtle.ConstantTimeCompare([]byte(identity.Nonce), []byte(transaction.Nonce)) != 1 {
		s.rejectLogin(w, "identity_mismatch", http.StatusForbidden, nil)
		return
	}
	if identity.AuthenticatedAt.IsZero() || identity.AuthenticatedAt.After(now) || now.Sub(identity.AuthenticatedAt) > 5*time.Minute || identity.AuthenticatedAt.Before(transaction.CreatedAt.Truncate(time.Second)) {
		s.rejectLogin(w, "fresh_authentication_required", http.StatusForbidden, nil)
		return
	}
	if s.requiredAMR != "" && !contains(identity.AMR, s.requiredAMR) {
		s.rejectLogin(w, "mfa_required", http.StatusForbidden, nil)
		return
	}
	binding, err := s.store.Binding(r.Context(), identity.Issuer, identity.Subject)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.rejectLogin(w, "no_local_binding", http.StatusForbidden, nil)
			return
		}
		s.logger.Error("console role lookup failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	if !binding.Role.Valid() {
		s.rejectLogin(w, "invalid_role", http.StatusForbidden, nil)
		return
	}
	sessionID, err := randomToken(32)
	if err != nil {
		http.Error(w, "cannot create session", http.StatusInternalServerError)
		return
	}
	csrfToken, err := randomToken(32)
	if err != nil {
		http.Error(w, "cannot create session", http.StatusInternalServerError)
		return
	}
	session := Session{
		IDDigest:          digest(sessionID),
		CSRFToken:         csrfToken,
		Issuer:            identity.Issuer,
		Subject:           identity.Subject,
		Role:              binding.Role,
		CreatedAt:         now,
		AuthenticatedAt:   identity.AuthenticatedAt,
		LastSeenAt:        now,
		IdleExpiresAt:     minTime(now.Add(s.sessionIdle), now.Add(s.sessionAbsolute)),
		AbsoluteExpiresAt: now.Add(s.sessionAbsolute),
	}
	if existingCookie, cookieErr := r.Cookie(s.sessionCookie); cookieErr == nil && existingCookie.Value != "" {
		if err := s.store.RevokeSession(r.Context(), digest(existingCookie.Value), now); err != nil {
			s.logger.Error("console session rotation failed", "error", err)
			http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if err := s.store.CreateSession(r.Context(), session); err != nil {
		s.logger.Error("console session creation failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, s.cookie(s.sessionCookie, sessionID, session.AbsoluteExpiresAt))
	s.logger.Info("console login", "issuer", identity.Issuer, "subject", identity.Subject, "role", binding.Role)
	http.Redirect(w, r, transaction.ReturnTo, http.StatusSeeOther)
}

func (s *Service) rejectLogin(w http.ResponseWriter, reason string, status int, err error) {
	if err != nil {
		// Provider errors can include unbounded response bodies. Log only the
		// error type so a code, token or provider payload cannot reach the log.
		s.logger.Warn("console login rejected", "reason", reason, "error_type", fmt.Sprintf("%T", err))
	} else {
		s.logger.Warn("console login rejected", "reason", reason)
	}
	s.renderPage(w, status, webconsole.Page{Title: "Sign-in denied", Message: "Your organization sign-in could not be completed. Try signing in again or contact your administrator."})
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	current, ok := sessionFrom(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if err := s.store.RevokeSession(r.Context(), current.Session.IDDigest, s.now().UTC()); err != nil {
		s.logger.Error("console logout failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	s.clearCookie(w, s.sessionCookie)
	s.clearCookie(w, s.loginCookie)
	s.logger.Info("console logout", "issuer", current.Session.Issuer, "subject", current.Session.Subject, "role", current.Role)
	http.Redirect(w, r, "/signed-out", http.StatusSeeOther)
}

func (s *Service) signedOut(w http.ResponseWriter, r *http.Request) {
	page := webconsole.Page{Title: "Signed out", Section: "signed-out", Message: "Your local session has ended. Sign in with your organization account to continue."}
	if r.URL.Query().Get("reason") == "expired" {
		page.Title = "Session expired"
		page.Message = "Sign in again to continue. Your session may have ended after inactivity or reached its time limit."
	}
	s.renderPage(w, http.StatusOK, page)
}

func (s *Service) sessionInfo(w http.ResponseWriter, r *http.Request) {
	current, ok := sessionFrom(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":     current.Session.Issuer,
		"subject":    current.Session.Subject,
		"role":       current.Role,
		"csrf_token": current.Session.CSRFToken,
	})
}

func (s *Service) console(w http.ResponseWriter, r *http.Request) {
	current, ok := sessionFrom(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	page := webconsole.Page{Title: "Workspace", Section: "overview", Subject: current.Session.Subject,
		Role: string(current.Role), CSRFToken: current.Session.CSRFToken,
		ExpiresAt: minTime(current.Session.IdleExpiresAt, current.Session.AbsoluteExpiresAt).Format(time.RFC3339Nano)}
	status := http.StatusOK
	switch r.URL.Path {
	case "/console/devices":
		page.Title, page.Section = "Devices", "devices"
		page.Devices, status = webconsole.FixtureDevices(r.URL.Query(), "")
	case "/console/workflows":
		page.Title, page.Section = "Workflows", "workflows"
	case "/console/access":
		page.Title, page.Section = "Console access", "access"
		bindings, err := s.store.Bindings(r.Context(), s.issuer)
		if err != nil {
			s.unavailable(w, r)
			return
		}
		for _, binding := range bindings {
			page.Bindings = append(page.Bindings, webconsole.Binding{Subject: binding.Subject, Role: string(binding.Role)})
		}
	default:
		if deviceID := r.PathValue("device"); deviceID != "" {
			page.Title, page.Section = "Device detail", "devices"
			page.Devices, status = webconsole.FixtureDevices(r.URL.Query(), deviceID)
		}
	}
	s.renderPage(w, status, page)
}

func (s *Service) renderPage(w http.ResponseWriter, status int, page webconsole.Page) {
	if err := webconsole.Render(w, status, page); err != nil {
		s.logger.Error("console render failed", "error", err)
	}
}

func (s *Service) listBindings(w http.ResponseWriter, r *http.Request) {
	bindings, err := s.store.Bindings(r.Context(), s.issuer)
	if err != nil {
		s.logger.Error("console role list failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"issuer": s.issuer, "bindings": bindings})
}

func (s *Service) upsertBinding(w http.ResponseWriter, r *http.Request) {
	current, _ := sessionFrom(r.Context())
	now := s.now().UTC()
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request struct {
		Subject string `json:"subject"`
		Role    Role   `json:"role"`
	}
	if err := decoder.Decode(&request); err != nil {
		http.Error(w, "invalid role binding JSON", http.StatusBadRequest)
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "expected one JSON object", http.StatusBadRequest)
		return
	}
	request.Subject = strings.TrimSpace(request.Subject)
	if request.Subject == "" || !request.Role.Valid() {
		http.Error(w, "subject and role are required", http.StatusBadRequest)
		return
	}
	existing, err := s.store.Binding(r.Context(), s.issuer, request.Subject)
	if err != nil && !errors.Is(err, ErrNotFound) {
		s.logger.Error("console role read failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	binding := Binding{Issuer: s.issuer, Subject: request.Subject, Role: request.Role, CreatedAt: now, UpdatedAt: now}
	if err == nil {
		binding.CreatedAt = existing.CreatedAt
	}
	if err := s.store.UpsertBinding(r.Context(), binding); err != nil {
		if errors.Is(err, ErrLastAdmin) {
			http.Error(w, "cannot remove the last admin", http.StatusConflict)
			return
		}
		s.logger.Error("console role update failed", "error", err)
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
		return
	}
	s.logger.Info("console role updated", "issuer", s.issuer, "actor_subject", current.Session.Subject, "subject", request.Subject, "role", request.Role)
	noStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(binding)
}

type sessionKey struct{}

type sessionContext struct {
	Session Session
	Role    Role
}

func sessionFrom(ctx context.Context) (sessionContext, bool) {
	current, ok := ctx.Value(sessionKey{}).(sessionContext)
	return current, ok
}

// RequireSession authenticates a session and permits any bound role.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.protect(w, r, "", next)
	})
}

// RequireRole authenticates a session and enforces the required role. It also
// validates CSRF and Origin for state-changing methods.
func (s *Service) RequireRole(required Role, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.protect(w, r, required, next)
	})
}

// RequireFreshAdmin protects sensitive administrator mutations with the same
// session, role, Origin and CSRF checks as other protected routes.
func (s *Service) RequireFreshAdmin(next http.Handler) http.Handler {
	return s.RequireRole(RoleAdmin, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		current, _ := sessionFrom(r.Context())
		now := s.now().UTC()
		if current.Session.AuthenticatedAt.IsZero() || current.Session.AuthenticatedAt.After(now) || now.Sub(current.Session.AuthenticatedAt) > 5*time.Minute {
			s.deny(w, r, RoleAdmin, "fresh_authentication_required", current.Session.Subject)
			return
		}
		next.ServeHTTP(w, r)
	}))
}

// SessionIdentity returns the authenticated issuer/subject for off-chain action
// provenance. It does not authorize an action; use the route middleware first.
func SessionIdentity(ctx context.Context) (issuer, subject string, ok bool) {
	current, ok := sessionFrom(ctx)
	if !ok {
		return "", "", false
	}
	return current.Session.Issuer, current.Session.Subject, true
}

func (s *Service) protect(w http.ResponseWriter, r *http.Request, required Role, next http.Handler) {
	noStore(w)
	cookie, err := r.Cookie(s.sessionCookie)
	if err != nil {
		s.deny(w, r, required, "no_session", "")
		return
	}
	if cookie.Value == "" {
		s.deny(w, r, required, "empty_session", "")
		return
	}
	session, err := s.store.Session(r.Context(), digest(cookie.Value))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.deny(w, r, required, "unknown_session", "")
			return
		}
		s.unavailable(w, r)
		return
	}
	now := s.now().UTC()
	if session.Issuer != s.issuer {
		if err := s.store.RevokeSession(r.Context(), session.IDDigest, now); err != nil {
			s.unavailable(w, r)
			return
		}
		s.deny(w, r, required, "issuer_changed", session.Subject)
		return
	}
	if !now.Before(session.IdleExpiresAt) || !now.Before(session.AbsoluteExpiresAt) || session.RevokedAt != nil {
		if err := s.store.RevokeSession(r.Context(), session.IDDigest, now); err != nil {
			s.unavailable(w, r)
			return
		}
		s.deny(w, r, required, "expired_session", session.Issuer)
		return
	}
	binding, err := s.store.Binding(r.Context(), session.Issuer, session.Subject)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			if err := s.store.RevokeSession(r.Context(), session.IDDigest, now); err != nil {
				s.unavailable(w, r)
				return
			}
			s.deny(w, r, required, "role_revoked", session.Subject)
			return
		}
		s.unavailable(w, r)
		return
	}
	if binding.Role != session.Role {
		if err := s.store.RevokeSession(r.Context(), session.IDDigest, now); err != nil {
			s.unavailable(w, r)
			return
		}
		s.deny(w, r, required, "role_changed", session.Subject)
		return
	}
	if required != "" && !binding.Role.Allows(required) {
		s.deny(w, r, required, "wrong_role", session.Subject)
		return
	}
	if isUnsafeMethod(r.Method) && !s.validCSRF(r, session.CSRFToken) {
		s.deny(w, r, required, "csrf_or_origin_rejected", session.Subject)
		return
	}
	idleExpires := minTime(now.Add(s.sessionIdle), session.AbsoluteExpiresAt)
	if err := s.store.TouchSession(r.Context(), session.IDDigest, now, idleExpires); err != nil {
		if errors.Is(err, ErrNotFound) {
			s.deny(w, r, required, "expired_session", session.Subject)
			return
		}
		s.unavailable(w, r)
		return
	}
	session.LastSeenAt, session.IdleExpiresAt = now, idleExpires
	current := sessionContext{Session: session, Role: binding.Role}
	s.logger.Info("console request", "method", r.Method, "resource", r.URL.Path, "outcome", "allowed", "issuer", session.Issuer, "subject", session.Subject, "role", binding.Role, "required_role", required)
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, current)))
}

func (s *Service) deny(w http.ResponseWriter, r *http.Request, required Role, reason, subject string) {
	s.logger.Info("console request denied", "method", r.Method, "resource", r.URL.Path, "reason", reason, "required_role", required, "subject", subject)
	switch reason {
	case "fresh_authentication_required", "wrong_role", "role_revoked", "role_changed", "csrf_or_origin_rejected":
		if wantsHTML(r) {
			s.renderPage(w, http.StatusForbidden, webconsole.Page{Title: "Access denied", Message: "Your account cannot open this page or perform this action. Contact your administrator if you need access."})
		} else {
			http.Error(w, "forbidden", http.StatusForbidden)
		}
		return
	}
	if wantsHTML(r) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		http.Redirect(w, r, "/auth/login?return_to="+url.QueryEscape(allowedReturnToRequest(r)), http.StatusFound)
		return
	}
	http.Error(w, "authentication required", http.StatusUnauthorized)
}

func (s *Service) unavailable(w http.ResponseWriter, r *http.Request) {
	s.logger.Error("console auth store unavailable", "method", r.Method, "resource", r.URL.Path)
	if wantsHTML(r) {
		s.renderPage(w, http.StatusServiceUnavailable, webconsole.Page{Title: "Sign-in service unavailable", Message: "Your access could not be checked. Try opening the workspace again in a moment."})
	} else {
		http.Error(w, "authentication unavailable", http.StatusServiceUnavailable)
	}
}

func (s *Service) validCSRF(r *http.Request, expected string) bool {
	if r.Header.Get("Origin") != s.publicOrigin {
		return false
	}
	token := r.Header.Get("X-CSRF-Token")
	if token == "" && strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err == nil {
			token = r.PostForm.Get("_csrf")
		}
	}
	if token == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
}

func (s *Service) cookie(name, value string, expires time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires.UTC(),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

func (s *Service) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(1, 0).UTC(),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func allowedReturnTo(target string) bool {
	return isConsolePage(target) || target == "/admin/role-bindings"
}

func isConsolePage(target string) bool {
	switch target {
	case "/console", "/console/devices", "/console/workflows", "/console/access":
		return true
	}
	return webconsole.IsDeviceDetailPath(target)
}

func allowedReturnToRequest(r *http.Request) string {
	if allowedReturnTo(r.URL.Path) {
		return r.URL.Path
	}
	return "/console"
}

func wantsHTML(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Accept"), "text/html") || isConsolePage(r.URL.Path)
}

func isUnsafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	default:
		return true
	}
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func randomToken(bytes int) (string, error) {
	buffer := make([]byte, bytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func digest(value string) []byte {
	sum := sha256.Sum256([]byte(value))
	return sum[:]
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Frame-Options", "DENY")
}

// PostgresStore stores opaque identifiers as digests and keeps authorization
// bindings outside the identity provider.
type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) PutLogin(ctx context.Context, transaction LoginTransaction) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO console_login_transactions
		(state_digest, nonce, code_verifier, return_to, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		transaction.StateDigest, transaction.Nonce, transaction.CodeVerifier, transaction.ReturnTo, transaction.CreatedAt, transaction.ExpiresAt)
	return err
}

func (s *PostgresStore) ConsumeLogin(ctx context.Context, stateDigest []byte, now time.Time) (LoginTransaction, error) {
	var transaction LoginTransaction
	transaction.StateDigest = stateDigest
	err := s.db.QueryRowContext(ctx, `UPDATE console_login_transactions
		SET consumed_at = $2
		WHERE state_digest = $1 AND consumed_at IS NULL AND expires_at > $2
		RETURNING nonce, code_verifier, return_to, created_at, expires_at`,
		stateDigest, now).Scan(&transaction.Nonce, &transaction.CodeVerifier, &transaction.ReturnTo, &transaction.CreatedAt, &transaction.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return LoginTransaction{}, ErrNotFound
	}
	return transaction, err
}

func (s *PostgresStore) CreateSession(ctx context.Context, session Session) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO console_sessions
		(id_digest, csrf_token, issuer, subject, role, created_at, authenticated_at, last_seen_at, idle_expires_at, absolute_expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		session.IDDigest, session.CSRFToken, session.Issuer, session.Subject, session.Role,
		session.CreatedAt, session.AuthenticatedAt, session.LastSeenAt, session.IdleExpiresAt, session.AbsoluteExpiresAt)
	return err
}

func (s *PostgresStore) Session(ctx context.Context, idDigest []byte) (Session, error) {
	var session Session
	session.IDDigest = idDigest
	err := s.db.QueryRowContext(ctx, `SELECT csrf_token, issuer, subject, role, created_at, authenticated_at, last_seen_at,
		idle_expires_at, absolute_expires_at, revoked_at
		FROM console_sessions WHERE id_digest = $1`, idDigest).Scan(
		&session.CSRFToken, &session.Issuer, &session.Subject, &session.Role, &session.CreatedAt, &session.AuthenticatedAt,
		&session.LastSeenAt, &session.IdleExpiresAt, &session.AbsoluteExpiresAt, &session.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return session, err
}

func (s *PostgresStore) TouchSession(ctx context.Context, idDigest []byte, now, idleExpires time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE console_sessions
		SET last_seen_at = $2, idle_expires_at = $3
		WHERE id_digest = $1 AND revoked_at IS NULL AND absolute_expires_at > $2 AND idle_expires_at > $2`,
		idDigest, now, idleExpires)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) RevokeSession(ctx context.Context, idDigest []byte, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE console_sessions SET revoked_at = $2 WHERE id_digest = $1 AND revoked_at IS NULL`, idDigest, now)
	return err
}

func (s *PostgresStore) Binding(ctx context.Context, issuer, subject string) (Binding, error) {
	var binding Binding
	err := s.db.QueryRowContext(ctx, `SELECT issuer, subject, role, created_at, updated_at
		FROM console_role_bindings WHERE issuer = $1 AND subject = $2`, issuer, subject).Scan(
		&binding.Issuer, &binding.Subject, &binding.Role, &binding.CreatedAt, &binding.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Binding{}, ErrNotFound
	}
	return binding, err
}

func (s *PostgresStore) CreateBinding(ctx context.Context, binding Binding) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO console_role_bindings
		(issuer, subject, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (issuer, subject) DO NOTHING`,
		binding.Issuer, binding.Subject, string(binding.Role), binding.CreatedAt, binding.UpdatedAt)
	return err
}

func (s *PostgresStore) UpsertBinding(ctx context.Context, binding Binding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Serialize role changes for one issuer so two concurrent demotions cannot
	// both observe the same remaining administrator.
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, binding.Issuer); err != nil {
		return err
	}
	var existing Role
	err = tx.QueryRowContext(ctx, `SELECT role FROM console_role_bindings
		WHERE issuer = $1 AND subject = $2 FOR UPDATE`, binding.Issuer, binding.Subject).Scan(&existing)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil && existing == RoleAdmin && binding.Role != RoleAdmin {
		var admins int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM console_role_bindings
			WHERE issuer = $1 AND role = 'admin'`, binding.Issuer).Scan(&admins); err != nil {
			return err
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO console_role_bindings
		(issuer, subject, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (issuer, subject) DO UPDATE SET role = EXCLUDED.role, updated_at = EXCLUDED.updated_at`,
		binding.Issuer, binding.Subject, binding.Role, binding.CreatedAt, binding.UpdatedAt); err != nil {
		return err
	}
	if existing != binding.Role {
		if _, err := tx.ExecContext(ctx, `UPDATE console_sessions SET revoked_at = $3
			WHERE issuer = $1 AND subject = $2 AND revoked_at IS NULL`, binding.Issuer, binding.Subject, binding.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) RevokeSubjectSessions(ctx context.Context, issuer, subject string, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE console_sessions SET revoked_at = $3
		WHERE issuer = $1 AND subject = $2 AND revoked_at IS NULL`, issuer, subject, now)
	return err
}

func (s *PostgresStore) Bindings(ctx context.Context, issuer string) ([]Binding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT issuer, subject, role, created_at, updated_at
		FROM console_role_bindings WHERE issuer = $1 ORDER BY subject`, issuer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	bindings := make([]Binding, 0)
	for rows.Next() {
		var binding Binding
		if err := rows.Scan(&binding.Issuer, &binding.Subject, &binding.Role, &binding.CreatedAt, &binding.UpdatedAt); err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}
