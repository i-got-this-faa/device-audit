package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestConsoleNavigationAuthorization(t *testing.T) {
	s, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, s)
	viewer, _ := addSession(t, store, clock, "viewer:private", RoleViewer)
	admin, _ := addSession(t, store, clock, "admin:private", RoleAdmin)
	client := noRedirectClient()
	for _, path := range []string{"/console", "/console/devices", "/console/devices/fixture-laptop", "/console/workflows", "/console/access"} {
		r := request(t, client, server.URL+path, "GET", "", map[string]string{"Accept": "text/html"}, "")
		if r.StatusCode != 302 || !strings.Contains(r.Header.Get("Location"), "return_to=") {
			t.Fatalf("anonymous %s: %d", path, r.StatusCode)
		}
		if strings.Contains(readBody(r), "private") {
			t.Fatal("anonymous navigation leaked subject")
		}
		r.Body.Close()
		r = request(t, client, server.URL+path, "GET", "", map[string]string{}, viewer)
		want := 200
		if path == "/console/access" {
			want = 403
		}
		body := readBody(r)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("viewer %s: %d", path, r.StatusCode)
		}
		if path == "/console/access" && strings.Contains(body, "admin:private") {
			t.Fatal("denied page leaked bindings")
		}
		if r.Header.Get("Cache-Control") != "no-store" || !strings.Contains(r.Header.Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatal("unprotected response policy")
		}
		r = request(t, client, server.URL+path, "GET", "", map[string]string{}, admin)
		if r.StatusCode != 200 {
			t.Fatalf("admin %s: %d", path, r.StatusCode)
		}
		r.Body.Close()
	}
	clock.Advance(15 * time.Minute)
	for _, path := range []string{"/console/devices", "/console/devices/fixture-laptop", "/console/workflows", "/console/access"} {
		r := request(t, client, server.URL+path, "GET", "", map[string]string{}, admin)
		body := readBody(r)
		r.Body.Close()
		if r.StatusCode != 302 || strings.Contains(body, "private") {
			t.Fatalf("expired %s: %d", path, r.StatusCode)
		}
	}
	for _, target := range []string{"//attacker.example", "/console/devices?next=https://attacker.example", "/console/devices/../access", "/console/api/devices/x/inventory", "/console/workflows/evil", "/console/devices/unregistered", "/console/devices/fixture-laptop?fixture=live", "/console/devices/fixture-laptop/extra"} {
		if allowedReturnTo(target) {
			t.Fatalf("unsafe return path %q", target)
		}
	}
}

func TestConsoleEscapesSubjectsAndFailsClosed(t *testing.T) {
	s, store, clock, _ := newMiddlewareService(t)
	server := newTestServer(t, s)
	id, _ := addSession(t, store, clock, `<script>alert("subject")</script>`, RoleViewer)
	r := request(t, noRedirectClient(), server.URL+"/console", "GET", "", nil, id)
	body := readBody(r)
	r.Body.Close()
	if strings.Contains(body, `<script>alert`) || !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("unescaped subject")
	}
	store.setFail(true)
	r = request(t, noRedirectClient(), server.URL+"/console/devices/fixture-laptop", "GET", "", nil, id)
	body = readBody(r)
	r.Body.Close()
	if r.StatusCode != 503 || strings.Contains(body, "subject") || strings.Contains(body, "data-protected") {
		t.Fatal("unavailable store leaked protected shell")
	}
}

// This fixture is compiled only by go test. It provides real OIDC/TLS routes
// with synthetic accounts and an in-memory auth store, never a login bypass in
// the controller binary.
func consoleBrowserFixture(t *testing.T) *httptest.Server {
	t.Helper()
	s, issuer, app, _, clock, _ := newOIDCTestBed(t)
	s.now = time.Now
	issuer.SetSubject("viewer:browser")
	if err := s.EnsureBinding(context.Background(), "viewer:browser", RoleViewer); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureBinding(context.Background(), "admin:browser", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	store := s.store.(*memoryStore)
	mux := app.Config.Handler.(*http.ServeMux)
	mux.HandleFunc("POST /__test/{action}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("action") {
		case "expire":
			store.mu.Lock()
			for key, session := range store.sessions {
				session.IdleExpiresAt = clock.Now()
				store.sessions[key] = session
			}
			store.mu.Unlock()
		case "viewer":
			issuer.SetSubject("viewer:browser")
		case "admin":
			issuer.SetSubject("admin:browser")
		case "unknown":
			issuer.SetSubject("unknown:private")
		case "outage":
			store.setFail(true)
		case "restore":
			store.setFail(false)
		default:
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return app
}

func TestConsoleBrowser(t *testing.T) {
	if os.Getenv("CONSOLE_BROWSER_TEST") != "1" {
		t.Skip("run make browser-check with Node and a Chromium executable")
	}
	app := consoleBrowserFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "../../../apps/web-console/tests/browser.mjs", app.URL)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("browser acceptance: %v\n%s", err, output)
	}
	t.Log(string(output))
}

func TestConsolePreview(t *testing.T) {
	path := os.Getenv("CONSOLE_PREVIEW_FILE")
	if path == "" {
		t.Skip("set CONSOLE_PREVIEW_FILE for a ten-minute synthetic preview")
	}
	app := consoleBrowserFixture(t)
	if err := os.WriteFile(path, []byte(app.URL), 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("Synthetic console preview: %s", app.URL)
	timer := time.NewTimer(10 * time.Minute)
	defer timer.Stop()
	select {
	case <-t.Context().Done():
	case <-timer.C:
	}
}
