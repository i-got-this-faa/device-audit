package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
)

func TestRunRejectsUnavailableDatabaseBeforeListening(t *testing.T) {
	address := freeAddress(t)
	err := run(context.Background(), []string{"--listen", address, "--database-url", "postgres://deviceaudit@127.0.0.1:1/device_audit?sslmode=disable&connect_timeout=1"}, environment{})
	if err == nil || !strings.Contains(err.Error(), "database startup failed") {
		t.Fatalf("database startup error: %v", err)
	}
	if connection, dialErr := net.DialTimeout("tcp", address, 200*time.Millisecond); dialErr == nil {
		connection.Close()
		t.Fatal("controller listened after database startup failed")
	}
}

func TestRunRejectsMeshTransport(t *testing.T) {
	err := run(context.Background(), []string{"--transport", "mesh", "--listen", freeAddress(t)}, environment{})
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Fatalf("mesh transport error: %v", err)
	}
}

func TestRunAbortsOnMigrationFailure(t *testing.T) {
	databaseURL := testDatabase(t)
	ctx := context.Background()
	db, err := database.Open(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE schema_migrations SET name = '001_changed' WHERE version = 1`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	address := freeAddress(t)
	err = run(ctx, []string{"--listen", address, "--database-url", databaseURL}, environment{})
	if err == nil || !strings.Contains(err.Error(), "schema migration failed") {
		t.Fatalf("migration startup error: %v", err)
	}
	if connection, dialErr := net.DialTimeout("tcp", address, 200*time.Millisecond); dialErr == nil {
		connection.Close()
		t.Fatal("controller listened after migration failure")
	}
}

func TestRunReportsConfiguredSchema(t *testing.T) {
	databaseURL := testDatabase(t)
	address := freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, []string{"--listen", address, "--database-url", databaseURL}, environment{})
	}()

	client := &http.Client{Timeout: time.Second}
	base := "http://" + address
	var health map[string]any
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(base + "/healthz")
		if err == nil {
			var candidate map[string]any
			decodeErr := json.NewDecoder(response.Body).Decode(&candidate)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil {
				health = candidate
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if health == nil {
		t.Fatal("controller did not become healthy")
	}
	if health["database"] != "connected" || health["schema_version"] != float64(3) || health["auth"] != "not_configured" || health["sample_storage"] != "memory" {
		t.Fatalf("health=%v", health)
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("controller shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
}

func TestRunReportsConfiguredAuth(t *testing.T) {
	databaseURL := testDatabase(t)
	address := freeAddress(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	args := []string{
		"--listen", address,
		"--database-url", databaseURL,
		"--oidc-issuer", "https://id.example.test",
		"--oidc-client-id", "console",
		"--oidc-client-secret", "secret",
		"--oidc-redirect-url", "https://console.example.test/auth/callback",
		"--public-origin", "https://console.example.test",
		"--bootstrap-admin", "admin-subject",
	}
	finished := make(chan error, 1)
	go func() { finished <- run(ctx, args, environment{}) }()

	base := "http://" + address
	client := &http.Client{Timeout: time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var health map[string]any
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(base + "/healthz")
		if err == nil {
			var candidate map[string]any
			decodeErr := json.NewDecoder(response.Body).Decode(&candidate)
			response.Body.Close()
			if response.StatusCode == http.StatusOK && decodeErr == nil {
				health = candidate
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if health == nil {
		t.Fatal("controller did not become healthy")
	}
	if health["auth"] != "oidc" || health["schema_version"] != float64(3) {
		t.Fatalf("health=%v", health)
	}
	response, err := client.Get(base + "/console")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusFound || response.Header.Get("Location") != "/auth/login?return_to=%2Fconsole" {
		t.Fatalf("anonymous console status=%d location=%q", response.StatusCode, response.Header.Get("Location"))
	}
	response, err = client.Get(base + "/admin/role-bindings")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous admin status=%d", response.StatusCode)
	}

	if err := databaseURLIsBound(databaseURL, "admin-subject"); err != nil {
		t.Fatalf("bootstrap binding: %v", err)
	}

	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatalf("controller shutdown: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not stop")
	}
}

func databaseURLIsBound(databaseURL, subject string) error {
	ctx := context.Background()
	db, err := database.Open(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	var role string
	if err := db.QueryRowContext(ctx, `SELECT role FROM console_role_bindings WHERE issuer = $1 AND subject = $2`, "https://id.example.test", subject).Scan(&role); err != nil {
		return err
	}
	if role != "admin" {
		return fmt.Errorf("bootstrap role=%q", role)
	}
	return nil
}

func TestRunRejectsAuthWithoutDatabase(t *testing.T) {
	err := run(context.Background(), []string{
		"--oidc-issuer", "https://id.example.test",
		"--oidc-client-id", "console",
		"--oidc-client-secret", "secret",
		"--oidc-redirect-url", "https://console.example.test/auth/callback",
		"--public-origin", "https://console.example.test",
	}, environment{})
	if err == nil || !strings.Contains(err.Error(), "requires --database-url") {
		t.Fatalf("auth without database error: %v", err)
	}
}

func TestRunRejectsIncompleteOrUnboundAuth(t *testing.T) {
	databaseURL := testDatabase(t)
	base := []string{"--listen", freeAddress(t), "--database-url", databaseURL}
	partial := append(append([]string{}, base...), "--oidc-issuer", "https://id.example.test")
	err := run(context.Background(), partial, environment{})
	if err == nil || !strings.Contains(err.Error(), "--oidc-client-id is required") {
		t.Fatalf("incomplete auth error: %v", err)
	}
	full := append(append([]string{}, base...),
		"--oidc-issuer", "https://id.example.test",
		"--oidc-client-id", "console",
		"--oidc-client-secret", "secret",
		"--oidc-redirect-url", "https://console.example.test/auth/callback",
		"--public-origin", "https://console.example.test",
	)
	err = run(context.Background(), full, environment{})
	if err == nil || !strings.Contains(err.Error(), "no admin role binding") {
		t.Fatalf("auth without admin binding error: %v", err)
	}
}

func TestEnvironmentFromOSRequiredAMR(t *testing.T) {
	t.Setenv("DEVICE_AUDIT_OIDC_REQUIRED_AMR", "")
	if got := environmentFromOS().OIDCRequiredAMR; got != "" {
		t.Fatalf("empty AMR override=%q", got)
	}
	t.Setenv("DEVICE_AUDIT_OIDC_REQUIRED_AMR", "pwd")
	if got := environmentFromOS().OIDCRequiredAMR; got != "pwd" {
		t.Fatalf("AMR override=%q", got)
	}
}

func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	return address
}

func testDatabase(t *testing.T) string {
	t.Helper()
	databaseURL := os.Getenv("TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	admin := *parsed
	admin.Path = "/postgres"
	adminDB, err := sql.Open("pgx", admin.String())
	if err != nil {
		t.Fatal(err)
	}
	name := fmt.Sprintf("device_audit_app_test_%d", time.Now().UnixNano())
	quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
	if _, err := adminDB.Exec(`CREATE DATABASE ` + quoted); err != nil {
		adminDB.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.Exec(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, name)
		if _, err := adminDB.Exec(`DROP DATABASE IF EXISTS ` + quoted); err != nil {
			t.Logf("drop test database: %v", err)
		}
		adminDB.Close()
	})
	testURL := *parsed
	testURL.Path = "/" + name
	return testURL.String()
}

func TestCLIUsageDoesNotExposeCredentials(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "controller.exe")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, argument := range []string{"--help", "--invalid-argument"} {
		command := exec.Command(binary, argument)
		command.Env = append(os.Environ(), "DEVICE_AUDIT_DATABASE_URL=postgres://user:synthetic-database-password@127.0.0.1/db", "DEVICE_AUDIT_OIDC_CLIENT_SECRET=synthetic-oidc-secret")
		output, err := command.CombinedOutput()
		if err == nil {
			t.Fatalf("%s should exit with help/parse status", argument)
		}
		for _, secret := range []string{"synthetic-database-password", "synthetic-oidc-secret"} {
			if strings.Contains(string(output), secret) {
				t.Errorf("%s exposed %s", argument, secret)
			}
		}
		if !strings.Contains(string(output), "database-url") {
			t.Fatalf("%s did not print usage", argument)
		}
	}
}

func TestDatabaseEnvironmentFallbackAndExplicitEmpty(t *testing.T) {
	databaseURL := "postgres://deviceaudit@127.0.0.1:1/device_audit?sslmode=disable&connect_timeout=1"
	for _, explicitEmpty := range []bool{false, true} {
		args := []string{"--listen", "invalid-address"}
		want := "database startup failed"
		if explicitEmpty {
			args = append(args, "--database-url=")
			want = "listen failed"
		}
		err := run(context.Background(), args, environment{DatabaseURL: databaseURL})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("explicit empty=%v: got %v want %s", explicitEmpty, err, want)
		}
	}
}

func TestOIDCSecretEnvironmentFallbackAndExplicitEmpty(t *testing.T) {
	for _, explicitEmpty := range []bool{false, true} {
		args := []string{"--listen", "invalid-address"}
		want := "console auth requires --database-url"
		if explicitEmpty {
			args = append(args, "--oidc-client-secret=")
			want = "listen failed"
		}
		err := run(context.Background(), args, environment{OIDCClientSecret: "synthetic-oidc-secret"})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("explicit empty=%v: got %v want %s", explicitEmpty, err, want)
		}
	}
}
