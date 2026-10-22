package auth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

type memoryStore struct {
	mu       sync.Mutex
	logins   map[string]LoginTransaction
	sessions map[string]Session
	bindings map[string]Binding
	fail     bool
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		logins:   make(map[string]LoginTransaction),
		sessions: make(map[string]Session),
		bindings: make(map[string]Binding),
	}
}

func (m *memoryStore) failIfSet() error {
	if m.fail {
		return errors.New("test store unavailable")
	}
	return nil
}

func key(issuer, subject string) string {
	return issuer + "\x00" + subject
}

func digestKey(digest []byte) string {
	return string(digest)
}

func (m *memoryStore) PutLogin(ctx context.Context, transaction LoginTransaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	m.logins[digestKey(transaction.StateDigest)] = transaction
	return nil
}

func (m *memoryStore) ConsumeLogin(ctx context.Context, stateDigest []byte, now time.Time) (LoginTransaction, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return LoginTransaction{}, err
	}
	transaction, ok := m.logins[digestKey(stateDigest)]
	if !ok || !now.Before(transaction.ExpiresAt) {
		return LoginTransaction{}, ErrNotFound
	}
	delete(m.logins, digestKey(stateDigest))
	return transaction, nil
}

func (m *memoryStore) CreateSession(ctx context.Context, session Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	m.sessions[digestKey(session.IDDigest)] = session
	return nil
}

func (m *memoryStore) Session(ctx context.Context, idDigest []byte) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return Session{}, err
	}
	session, ok := m.sessions[digestKey(idDigest)]
	if !ok {
		return Session{}, ErrNotFound
	}
	return session, nil
}

func (m *memoryStore) TouchSession(ctx context.Context, idDigest []byte, now, idleExpires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	session, ok := m.sessions[digestKey(idDigest)]
	if !ok || session.RevokedAt != nil || !now.Before(session.AbsoluteExpiresAt) || !now.Before(session.IdleExpiresAt) {
		return ErrNotFound
	}
	session.LastSeenAt = now
	session.IdleExpiresAt = idleExpires
	m.sessions[digestKey(idDigest)] = session
	return nil
}

func (m *memoryStore) RevokeSession(ctx context.Context, idDigest []byte, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	session, ok := m.sessions[digestKey(idDigest)]
	if !ok {
		return nil
	}
	if session.RevokedAt == nil {
		session.RevokedAt = &now
	}
	m.sessions[digestKey(idDigest)] = session
	return nil
}

func (m *memoryStore) Binding(ctx context.Context, issuer, subject string) (Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return Binding{}, err
	}
	binding, ok := m.bindings[key(issuer, subject)]
	if !ok {
		return Binding{}, ErrNotFound
	}
	return binding, nil
}

func (m *memoryStore) CreateBinding(ctx context.Context, binding Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	id := key(binding.Issuer, binding.Subject)
	if _, ok := m.bindings[id]; ok {
		return nil
	}
	m.bindings[id] = binding
	return nil
}

func (m *memoryStore) UpsertBinding(ctx context.Context, binding Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	existing, ok := m.bindings[key(binding.Issuer, binding.Subject)]
	if ok && existing.Role == RoleAdmin && binding.Role != RoleAdmin {
		admins := 0
		for _, candidate := range m.bindings {
			if candidate.Issuer == binding.Issuer && candidate.Role == RoleAdmin {
				admins++
			}
		}
		if admins <= 1 {
			return ErrLastAdmin
		}
	}
	if ok {
		binding.CreatedAt = existing.CreatedAt
	}
	if existing.Role != binding.Role {
		for id, session := range m.sessions {
			if session.Issuer == binding.Issuer && session.Subject == binding.Subject && session.RevokedAt == nil {
				now := binding.UpdatedAt
				session.RevokedAt = &now
				m.sessions[id] = session
			}
		}
	}
	m.bindings[key(binding.Issuer, binding.Subject)] = binding
	return nil
}

func (m *memoryStore) Bindings(ctx context.Context, issuer string) ([]Binding, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return nil, err
	}
	bindings := make([]Binding, 0)
	for _, binding := range m.bindings {
		if binding.Issuer == issuer {
			bindings = append(bindings, binding)
		}
	}
	return bindings, nil
}

func (m *memoryStore) RevokeSubjectSessions(ctx context.Context, issuer, subject string, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failIfSet(); err != nil {
		return err
	}
	for id, session := range m.sessions {
		if session.Issuer == issuer && session.Subject == subject && session.RevokedAt == nil {
			session.RevokedAt = &now
			m.sessions[id] = session
		}
	}
	return nil
}

func (m *memoryStore) removeBinding(issuer, subject string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bindings, key(issuer, subject))
}

func (m *memoryStore) setFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fail = fail
}

type stubProvider struct{}

func (stubProvider) AuthCodeURL(ctx context.Context, state, nonce, codeVerifier string) (string, error) {
	return "https://id.example.test/authorize", nil
}

func (stubProvider) Exchange(ctx context.Context, code, codeVerifier string) (Identity, error) {
	return Identity{}, errors.New("not used")
}

func newMiddlewareService(t *testing.T) (*Service, *memoryStore, *testClock, *bytes.Buffer) {
	t.Helper()
	store := newMemoryStore()
	clock := &testClock{now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}
	var logs bytes.Buffer
	service, err := NewService(Config{
		Issuer:       "https://id.example.test",
		PublicOrigin: "https://console.example.test",
		Store:        store,
		Provider:     stubProvider{},
		Now:          clock.Now,
		Logger:       slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return service, store, clock, &logs
}

func addSession(t *testing.T, store *memoryStore, clock *testClock, subject string, role Role) (string, string) {
	t.Helper()
	issuer := "https://id.example.test"
	now := clock.Now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: issuer, Subject: subject, Role: role, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(context.Background(), Session{
		IDDigest:          digest(sessionID),
		CSRFToken:         csrf,
		Issuer:            issuer,
		Subject:           subject,
		Role:              role,
		CreatedAt:         now,
		AuthenticatedAt:   now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return sessionID, csrf
}

func newTestServer(t *testing.T, service *Service) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	service.Register(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func request(t *testing.T, client *http.Client, target, method, body string, headers map[string]string, sessionID string) *http.Response {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	if sessionID != "" {
		req.AddCookie(&http.Cookie{Name: defaultSessionCookie, Value: sessionID})
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

func TestMiddlewareRejectsUnauthenticatedExpiredAndWrongScope(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, service)
	viewerID, viewerCSRF := addSession(t, store, clock, "viewer-1", RoleViewer)
	adminID, adminCSRF := addSession(t, store, clock, "admin-1", RoleAdmin)
	client := noRedirectClient()

	response := request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, "")
	if response.StatusCode != http.StatusFound {
		t.Fatalf("anonymous console status=%d", response.StatusCode)
	}
	if location := response.Header.Get("Location"); location != "/auth/login?return_to=%2Fconsole" {
		t.Fatalf("anonymous console location=%q", location)
	}
	response.Body.Close()

	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodGet, "", map[string]string{"Accept": "application/json"}, "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous admin status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, viewerID)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("viewer console status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "viewer-1") || !strings.Contains(string(body), "viewer") {
		t.Fatalf("viewer console body=%s", body)
	}

	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodGet, "", map[string]string{
		"Accept":           "application/json",
		"X-Forwarded-User": "admin-1",
		"X-Device-Id":      "device-admin",
		"Authorization":    "Bearer fake-token",
	}, viewerID)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("forged header admin status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodGet, "", map[string]string{"Accept": "application/json"}, adminID)
	if response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("admin list status=%d cache=%q", response.StatusCode, response.Header.Get("Cache-Control"))
	}
	adminBody, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(adminBody), `"issuer":"https://id.example.test"`) {
		t.Fatalf("admin list body=%s", adminBody)
	}

	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		fmt.Sprintf(`{"subject":"viewer-1","role":%q}`, RoleAdmin),
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": viewerCSRF}, viewerID)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer role mutation status=%d", response.StatusCode)
	}
	response.Body.Close()
	if binding, _ := store.Binding(context.Background(), "https://id.example.test", "viewer-1"); binding.Role != RoleViewer {
		t.Fatalf("viewer mutation changed role: %+v", binding)
	}

	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"new-admin","role":"admin"}`,
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://console.example.test"}, adminID)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("admin mutation without CSRF status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"new-admin","role":"admin"} trailing`,
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": adminCSRF}, adminID)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("trailing role JSON status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"new-admin","role":"admin"}`,
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://attacker.example", "X-CSRF-Token": adminCSRF}, adminID)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("admin mutation with foreign origin status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"new-admin","role":"admin"}`,
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": adminCSRF}, adminID)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("admin role mutation status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
	if binding, _ := store.Binding(context.Background(), "https://id.example.test", "new-admin"); binding.Role != RoleAdmin {
		t.Fatalf("admin mutation did not persist: %+v", binding)
	}
}

func readBody(response *http.Response) string {
	body, _ := io.ReadAll(response.Body)
	return string(body)
}

func TestSessionExpiryAndRoleRevocation(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, service)
	client := noRedirectClient()

	id, _ := addSession(t, store, clock, "idle-user", RoleViewer)
	clock.Advance(14*time.Minute + 59*time.Second)
	response := request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, id)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("session before idle expiry status=%d", response.StatusCode)
	}
	response.Body.Close()
	clock.Advance(15 * time.Minute)
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, id)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("session at idle expiry status=%d", response.StatusCode)
	}
	response.Body.Close()

	absoluteID, _ := addSession(t, store, clock, "absolute-user", RoleViewer)
	for elapsed := time.Duration(0); elapsed < 7*time.Hour+50*time.Minute; elapsed += 10 * time.Minute {
		clock.Advance(10 * time.Minute)
		response = request(t, client, server.URL+"/auth/session", http.MethodGet, "", map[string]string{"Accept": "application/json"}, absoluteID)
		if response.StatusCode != http.StatusOK {
			t.Fatalf("session at %s status=%d", elapsed+10*time.Minute, response.StatusCode)
		}
		response.Body.Close()
	}
	clock.Advance(10 * time.Minute)
	response = request(t, client, server.URL+"/auth/session", http.MethodGet, "", map[string]string{"Accept": "application/json"}, absoluteID)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session at absolute expiry status=%d", response.StatusCode)
	}
	response.Body.Close()

	revokedID, _ := addSession(t, store, clock, "removed-user", RoleViewer)
	store.removeBinding("https://id.example.test", "removed-user")
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, revokedID)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("removed role status=%d", response.StatusCode)
	}
	response.Body.Close()
	if err := store.CreateBinding(context.Background(), Binding{Issuer: "https://id.example.test", Subject: "removed-user", Role: RoleViewer}); err != nil {
		t.Fatal(err)
	}
	response = request(t, client, server.URL+"/auth/session", http.MethodGet, "", nil, revokedID)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("restored binding revived revoked session: status=%d", response.StatusCode)
	}
	response.Body.Close()

	changedID, _ := addSession(t, store, clock, "changed-user", RoleViewer)
	changed, _ := store.Binding(context.Background(), "https://id.example.test", "changed-user")
	changed.Role = RoleAdmin
	if err := store.UpsertBinding(context.Background(), changed); err != nil {
		t.Fatal(err)
	}
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, changedID)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("stale role session gained new authority: status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestRoleChangeRevokesExistingSessions(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, service)
	client := noRedirectClient()
	adminID, adminCSRF := addSession(t, store, clock, "admin-1", RoleAdmin)
	targetID, _ := addSession(t, store, clock, "target-1", RoleViewer)

	response := request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"target-1","role":"admin"}`,
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": adminCSRF}, adminID)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("role change status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, targetID)
	if response.StatusCode != http.StatusFound {
		t.Fatalf("session after role change status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestLastAdminCannotBeDemoted(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, service)
	client := noRedirectClient()
	adminID, adminCSRF := addSession(t, store, clock, "admin-1", RoleAdmin)

	response := request(t, client, server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"admin-1","role":"viewer"}`,
		map[string]string{"Accept": "application/json", "Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": adminCSRF}, adminID)
	if response.StatusCode != http.StatusConflict {
		t.Fatalf("last admin demotion status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
	if binding, _ := store.Binding(context.Background(), "https://id.example.test", "admin-1"); binding.Role != RoleAdmin {
		t.Fatalf("last admin binding changed: %+v", binding)
	}
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, adminID)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("last admin session status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestEnsureBindingDoesNotOverwriteExistingRole(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	now := clock.Now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: "https://id.example.test", Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := service.EnsureBinding(context.Background(), "viewer-1", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	binding, err := store.Binding(context.Background(), "https://id.example.test", "viewer-1")
	if err != nil || binding.Role != RoleViewer {
		t.Fatalf("existing role overwritten: %+v err=%v", binding, err)
	}
}

func TestFailedTokenExchangeDoesNotLogCode(t *testing.T) {
	service, fake, app, logs, clock, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	fake.SetSubject("viewer-1")
	now := clock.Now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: mustJar(t), Transport: base, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response := request(t, client, app.URL+"/auth/login?return_to=/console", http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusFound {
		t.Fatalf("login start status=%d", response.StatusCode)
	}
	authorizeURL := response.Header.Get("Location")
	response.Body.Close()
	response = request(t, client, authorizeURL, http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d", response.StatusCode)
	}
	callbackURL := response.Header.Get("Location")
	response.Body.Close()
	tampered := strings.Replace(callbackURL, "code=", "code=invalid-code", 1)
	response = request(t, client, tampered, http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid code status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
	if strings.Contains(logs.String(), "invalid-code") {
		t.Fatalf("logs contain authorization code: %s", logs.String())
	}
}

func TestCSRFOriginAndLogoutRevocation(t *testing.T) {
	service, store, clock, logs := newMiddlewareService(t)
	server := newTestServer(t, service)
	client := noRedirectClient()
	id, csrf := addSession(t, store, clock, "viewer-1", RoleViewer)

	response := request(t, client, server.URL+"/auth/logout", http.MethodPost, "", map[string]string{"Accept": "text/html"}, "")
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous HTML mutation status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/auth/logout", http.MethodPost, "_csrf="+csrf, map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, id)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without origin status=%d logs=%s", response.StatusCode, logs.String())
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/auth/logout", http.MethodPost, "_csrf="+csrf, map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://attacker.example"}, id)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with foreign origin status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/auth/logout", http.MethodPost, "_csrf=wrong", map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://console.example.test"}, id)
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("logout with wrong csrf status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = request(t, client, server.URL+"/auth/logout", http.MethodGet, "", map[string]string{"Accept": "text/html"}, id)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET logout status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, id)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET logout invalidated session: status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = request(t, client, server.URL+"/auth/logout", http.MethodPost, "_csrf="+csrf, map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://console.example.test"}, id)
	if response.StatusCode != http.StatusSeeOther || response.Header.Get("Location") != "/signed-out" {
		t.Fatalf("logout status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	if !strings.Contains(strings.Join(response.Header.Values("Set-Cookie"), "\n"), defaultSessionCookie+"=;") {
		t.Fatalf("logout did not clear cookie: %v", response.Header.Values("Set-Cookie"))
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/auth/session", http.MethodGet, "", map[string]string{"Accept": "application/json"}, id)
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed session status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestStoreOutageFailsClosed(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, service)
	client := noRedirectClient()
	id, _ := addSession(t, store, clock, "viewer-1", RoleViewer)
	store.setFail(true)
	response := request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, id)
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("store outage status=%d", response.StatusCode)
	}
	response.Body.Close()
	response = request(t, client, server.URL+"/auth/login", http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("login store outage status=%d", response.StatusCode)
	}
	response.Body.Close()
	store.setFail(false)
	response = request(t, client, server.URL+"/console", http.MethodGet, "", map[string]string{"Accept": "text/html"}, id)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("session after store recovery status=%d", response.StatusCode)
	}
	response.Body.Close()
}

type recordingTransport struct {
	base      http.RoundTripper
	mu        sync.Mutex
	responses []http.Header
}

func (r *recordingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if response != nil {
		r.mu.Lock()
		r.responses = append(r.responses, response.Header.Clone())
		r.mu.Unlock()
	}
	return response, err
}

func (r *recordingTransport) setCookies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var cookies []string
	for _, header := range r.responses {
		cookies = append(cookies, header.Values("Set-Cookie")...)
	}
	return cookies
}

func testTLSClient(base http.RoundTripper) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar:       jar,
		Transport: base,
		Timeout:   10 * time.Second,
	}
}

func testTLSRoots(app, issuer *httptest.Server) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(app.Certificate())
	pool.AddCert(issuer.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func newOIDCTestBed(t *testing.T) (*Service, *fakeIssuer, *httptest.Server, *bytes.Buffer, *testClock, *http.Transport) {
	t.Helper()
	fake := newFakeIssuer(t, "console-client", "client-secret")
	store := newMemoryStore()
	clock := &testClock{now: time.Now().UTC()}
	var logs bytes.Buffer
	mux := http.NewServeMux()
	app := httptest.NewTLSServer(mux)
	t.Cleanup(app.Close)
	base := &http.Transport{TLSClientConfig: testTLSRoots(app, fake.server)}
	providerHTTP := &http.Client{Transport: base, Timeout: 10 * time.Second}
	provider := NewOIDCProvider(fake.URL(), "console-client", "client-secret", app.URL+"/auth/callback", providerHTTP)
	service, err := NewService(Config{
		Issuer:       fake.URL(),
		PublicOrigin: app.URL,
		Store:        store,
		Provider:     provider,
		RequiredAMR:  "mfa",
		Now:          clock.Now,
		Logger:       slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	service.Register(mux)
	return service, fake, app, &logs, clock, base
}

func TestOIDCLoginFlowProtectsRoutesAndLogout(t *testing.T) {
	service, fake, app, logs, clock, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	fake.SetSubject("viewer-1")
	now := clock.Now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	recorder := &recordingTransport{base: base}
	client := testTLSClient(recorder)

	response, err := client.Get(app.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(response)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("login flow status=%d body=%s logs=%s", response.StatusCode, body, logs.String())
	}
	if !strings.Contains(body, "viewer-1") || !strings.Contains(body, "viewer") {
		t.Fatalf("console body=%s", body)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("console cache=%q", response.Header.Get("Cache-Control"))
	}
	cookies := recorder.setCookies()
	joinedCookies := strings.Join(cookies, "\n")
	if !strings.Contains(joinedCookies, defaultSessionCookie+"=") ||
		!strings.Contains(joinedCookies, "Path=/") ||
		!strings.Contains(joinedCookies, "Secure") ||
		!strings.Contains(joinedCookies, "HttpOnly") ||
		!strings.Contains(joinedCookies, "SameSite=Lax") ||
		strings.Contains(joinedCookies, "Domain=") {
		t.Fatalf("session cookie attributes: %s", joinedCookies)
	}

	response = request(t, client, app.URL+"/admin/role-bindings", http.MethodGet, "", map[string]string{"Accept": "application/json"}, "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer admin status=%d", response.StatusCode)
	}
	response.Body.Close()

	response, err = client.Get(app.URL + "/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	var sessionBody struct {
		Subject   string `json:"subject"`
		Role      string `json:"role"`
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&sessionBody); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if sessionBody.Subject != "viewer-1" || sessionBody.Role != "viewer" || sessionBody.CSRFToken == "" {
		t.Fatalf("session body=%+v", sessionBody)
	}
	sessionCookie := findCookie(client.Jar.Cookies(mustParse(t, app.URL)), defaultSessionCookie)
	if sessionCookie == nil {
		t.Fatal("session cookie missing")
	}

	logoutClient := &http.Client{Jar: client.Jar, Transport: client.Transport, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response = request(t, logoutClient, app.URL+"/auth/logout", http.MethodPost, "_csrf="+sessionBody.CSRFToken,
		map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": app.URL}, "")
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status=%d", response.StatusCode)
	}
	response.Body.Close()
	response, err = client.Get(app.URL + "/auth/session")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("session after logout status=%d", response.StatusCode)
	}
	response.Body.Close()

	joined := logs.String()
	for _, secret := range []string{fake.LastCode(), fake.LastIDToken(), sessionBody.CSRFToken, sessionCookie.Value} {
		if secret != "" && strings.Contains(joined, secret) {
			t.Fatalf("logs contain a reusable secret")
		}
	}
	if strings.Contains(joined, "client-secret") || strings.Contains(joined, "code_verifier") {
		t.Fatalf("logs contain OIDC credentials: %s", joined)
	}
}

func TestOIDCLoginRejectsNonceMismatch(t *testing.T) {
	service, fake, app, _, clock, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	fake.SetSubject("viewer-1")
	fake.SetNonceOverride("wrong-nonce")
	now := clock.Now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	client := testTLSClient(base)
	response, err := client.Get(app.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("nonce mismatch status=%d body=%s", response.StatusCode, body)
	}
	if cookie := findCookie(client.Jar.Cookies(mustParse(t, app.URL)), defaultSessionCookie); cookie != nil {
		t.Fatalf("nonce mismatch received session cookie: %v", cookie)
	}
}

func TestOIDCLoginRejectsMissingMFA(t *testing.T) {
	service, fake, app, _, _, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	fake.SetSubject("viewer-1")
	fake.SetAMR("pwd")
	now := service.now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	client := testTLSClient(base)
	response, err := client.Get(app.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("missing MFA status=%d body=%s", response.StatusCode, body)
	}
	if cookie := findCookie(client.Jar.Cookies(mustParse(t, app.URL)), defaultSessionCookie); cookie != nil {
		t.Fatalf("missing MFA received session cookie: %v", cookie)
	}
}

func TestIdPOutageFailsNewLoginButKeepsExistingSession(t *testing.T) {
	service, fake, app, logs, _, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	now := service.now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	sessionID, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	csrf, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateSession(context.Background(), Session{
		IDDigest:          digest(sessionID),
		CSRFToken:         csrf,
		Issuer:            fake.URL(),
		Subject:           "viewer-1",
		Role:              RoleViewer,
		CreatedAt:         now,
		AuthenticatedAt:   now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	client := testTLSClient(base)
	client.Jar.SetCookies(mustParse(t, app.URL), []*http.Cookie{{Name: defaultSessionCookie, Value: sessionID, Path: "/", Secure: true}})
	fake.server.Close()
	response, err := client.Get(app.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("existing session during IdP outage status=%d logs=%s", response.StatusCode, logs.String())
	}
	response.Body.Close()
	response, err = client.Get(app.URL + "/auth/login?return_to=/console")
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("new login during IdP outage status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func TestOIDCLoginRejectsUnknownIdentityAndReplay(t *testing.T) {
	service, fake, app, _, _, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	fake.SetSubject("unknown-user")
	client := testTLSClient(base)
	response, err := client.Get(app.URL + "/console")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(response)
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("unknown identity status=%d body=%s", response.StatusCode, body)
	}
	if cookie := findCookie(client.Jar.Cookies(mustParse(t, app.URL)), defaultSessionCookie); cookie != nil {
		t.Fatalf("unknown identity received session cookie: %v", cookie)
	}

	fake.SetSubject("replay-user")
	now := service.now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "replay-user", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	noFollow := &http.Client{Jar: mustJar(t), Transport: base, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response = request(t, noFollow, app.URL+"/auth/login?return_to=/console", http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusFound {
		t.Fatalf("login start status=%d", response.StatusCode)
	}
	authorizeURL := response.Header.Get("Location")
	response.Body.Close()
	loginCookie := findCookie(noFollow.Jar.Cookies(mustParse(t, app.URL)), defaultLoginCookie)
	if loginCookie == nil {
		t.Fatal("login cookie missing before callback")
	}
	response = request(t, noFollow, authorizeURL, http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d", response.StatusCode)
	}
	callbackURL := response.Header.Get("Location")
	response.Body.Close()
	response = request(t, noFollow, callbackURL, http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback status=%d body=%s", response.StatusCode, readBody(response))
	}
	response.Body.Close()
	noFollow.Jar.SetCookies(mustParse(t, app.URL), []*http.Cookie{loginCookie})
	replay := request(t, noFollow, callbackURL, http.MethodGet, "", map[string]string{}, "")
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback status=%d", replay.StatusCode)
	}
	replay.Body.Close()
}

func TestLoginTransactionExpiryAndStateMismatch(t *testing.T) {
	service, fake, app, _, clock, base := newOIDCTestBed(t)
	store := service.store.(*memoryStore)
	fake.SetSubject("expired-user")
	now := clock.Now()
	if err := store.UpsertBinding(context.Background(), Binding{Issuer: fake.URL(), Subject: "expired-user", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: mustJar(t), Transport: base, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	response := request(t, client, app.URL+"/auth/login?return_to=/console", http.MethodGet, "", map[string]string{}, "")
	authorizeURL := response.Header.Get("Location")
	response.Body.Close()
	response = request(t, client, authorizeURL, http.MethodGet, "", map[string]string{}, "")
	callbackURL := response.Header.Get("Location")
	response.Body.Close()
	clock.Advance(5 * time.Minute)
	response = request(t, client, callbackURL, http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired login status=%d", response.StatusCode)
	}
	response.Body.Close()

	response = request(t, client, app.URL+"/auth/login?return_to=/console", http.MethodGet, "", map[string]string{}, "")
	authorizeURL = response.Header.Get("Location")
	response.Body.Close()
	response = request(t, client, authorizeURL, http.MethodGet, "", map[string]string{}, "")
	callbackURL = response.Header.Get("Location")
	response.Body.Close()
	tampered := strings.Replace(callbackURL, "state=", "state=wrong", 1)
	response = request(t, client, tampered, http.MethodGet, "", map[string]string{}, "")
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("tampered state status=%d", response.StatusCode)
	}
	response.Body.Close()
}

func mustParse(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func mustJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return jar
}

func TestRoleChangeRequiresFreshAuthentication(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, service)
	id, csrf := addSession(t, store, clock, "admin", RoleAdmin)
	clock.Advance(5*time.Minute + time.Second)
	response := request(t, noRedirectClient(), server.URL+"/admin/role-bindings", http.MethodPost,
		`{"subject":"new-admin","role":"admin"}`,
		map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": csrf}, id)
	defer response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("stale authentication status=%d", response.StatusCode)
	}
	if _, err := store.Binding(context.Background(), "https://id.example.test", "new-admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale authentication changed binding: %v", err)
	}
}

func TestOIDCLoginRejectsUnfreshAuthentication(t *testing.T) {
	for _, offset := range []time.Duration{-10 * time.Minute, time.Minute} {
		t.Run(offset.String(), func(t *testing.T) {
			service, fake, app, _, clock, base := newOIDCTestBed(t)
			if err := service.EnsureBinding(context.Background(), "subject-viewer", RoleViewer); err != nil {
				t.Fatal(err)
			}
			value := clock.Now().Add(offset).Unix()
			fake.mu.Lock()
			fake.authTimeOverride = &value
			fake.mu.Unlock()
			client := testTLSClient(base)
			response, err := client.Get(app.URL + "/auth/login")
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("unfresh auth_time status=%d", response.StatusCode)
			}
		})
	}
}

func TestIssuerChangeRejectsPersistedSessions(t *testing.T) {
	service, store, clock, _ := newMiddlewareService(t)
	id, csrf := addSession(t, store, clock, "old-admin", RoleAdmin)
	oldIssuer := service.issuer
	service.issuer = "https://replacement-id.example.test"
	server := newTestServer(t, service)
	for _, path := range []string{"/auth/session", "/console", "/admin/role-bindings"} {
		response := request(t, noRedirectClient(), server.URL+path, http.MethodGet, "", map[string]string{"Accept": "application/json"}, id)
		response.Body.Close()
		want := http.StatusUnauthorized
		if path == "/console" {
			want = http.StatusFound
			if !strings.HasPrefix(response.Header.Get("Location"), "/auth/login?") {
				t.Errorf("old issuer console did not redirect to login")
			}
		}
		if response.StatusCode != want {
			t.Errorf("old issuer session at %s: status=%d want=%d", path, response.StatusCode, want)
		}
	}
	response := request(t, noRedirectClient(), server.URL+"/admin/role-bindings", http.MethodPost, `{"subject":"injected-admin","role":"admin"}`, map[string]string{"Content-Type": "application/json", "Origin": "https://console.example.test", "X-CSRF-Token": csrf}, id)
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("old issuer session mutation status=%d", response.StatusCode)
	}
	if _, err := store.Binding(context.Background(), service.issuer, "injected-admin"); !errors.Is(err, ErrNotFound) {
		t.Errorf("old issuer session changed new issuer bindings: %v", err)
	}
	// A denied session must stay revoked if the operator later restores the issuer.
	service.issuer = oldIssuer
	response = request(t, noRedirectClient(), server.URL+"/auth/session", http.MethodGet, "", nil, id)
	defer response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Errorf("issuer rollback revived session: status=%d", response.StatusCode)
	}
}
