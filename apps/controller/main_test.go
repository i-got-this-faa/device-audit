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
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
)

func TestRunRejectsUnavailableDatabaseBeforeListening(t *testing.T) {
	address := freeAddress(t)
	err := run(context.Background(), []string{"--listen", address, "--database-url", "postgres://deviceaudit@127.0.0.1:1/device_audit?sslmode=disable&connect_timeout=1"}, "")
	if err == nil || !strings.Contains(err.Error(), "database startup failed") {
		t.Fatalf("database startup error: %v", err)
	}
	if connection, dialErr := net.DialTimeout("tcp", address, 200*time.Millisecond); dialErr == nil {
		connection.Close()
		t.Fatal("controller listened after database startup failed")
	}
}

func TestRunRejectsMeshTransport(t *testing.T) {
	err := run(context.Background(), []string{"--transport", "mesh", "--listen", freeAddress(t)}, "")
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
	err = run(ctx, []string{"--listen", address, "--database-url", databaseURL}, "")
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
	go func() { finished <- run(ctx, []string{"--listen", address, "--database-url", databaseURL}, "") }()

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
	if health["database"] != "connected" || health["schema_version"] != float64(1) || health["sample_storage"] != "memory" {
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
