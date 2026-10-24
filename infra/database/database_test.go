package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

func TestMigrateEmbeddedSchemaAndRestart(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	version, err := Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("schema version=%d want 4", version)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO devices (id, enrolled_at, identity_public_key, mesh_public_key) VALUES ('device:one', now(), '\x01', 'mesh-key')`); err != nil {
		t.Fatal(err)
	}
	version, err = Migrate(ctx, db)
	if err != nil {
		t.Fatalf("restart migration: %v", err)
	}
	if version != 4 {
		t.Fatalf("restart version=%d want 4", version)
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM devices`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("migration recreated data: count=%d", count)
	}
	status, err := CurrentStatus(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if status.Version != 4 || len(status.Pending) != 0 {
		t.Fatalf("status=%+v", status)
	}
}

func TestMigrateFromPriorSchemaPreservesData(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	prior := fstest.MapFS{
		"migrations/001_prior.sql": {Data: []byte(`CREATE TABLE prior_marker (id integer PRIMARY KEY, label text NOT NULL)`)},
	}
	if version, err := MigrateFS(ctx, db, prior); err != nil || version != 1 {
		t.Fatalf("prior schema version=%d err=%v", version, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO prior_marker (id, label) VALUES (1, 'kept')`); err != nil {
		t.Fatal(err)
	}
	upgrade := fstest.MapFS{
		"migrations/001_prior.sql":   {Data: []byte(`CREATE TABLE prior_marker (id integer PRIMARY KEY, label text NOT NULL)`)},
		"migrations/002_upgrade.sql": {Data: []byte(`ALTER TABLE prior_marker ADD COLUMN observed_at timestamptz`)},
	}
	version, err := MigrateFS(ctx, db, upgrade)
	if err != nil {
		t.Fatal(err)
	}
	if version != 2 {
		t.Fatalf("upgrade version=%d want 2", version)
	}
	var label string
	if err := db.QueryRowContext(ctx, `SELECT label FROM prior_marker WHERE id = 1`).Scan(&label); err != nil {
		t.Fatal(err)
	}
	if label != "kept" {
		t.Fatalf("prior row changed: %q", label)
	}
}

func TestDeviceRepositoryUpgradePreservesUntrustedCandidatesAndConsoleData(t *testing.T) {
	db := openTestDatabase(t)
	prior := fstest.MapFS{}
	for _, name := range []string{"migrations/001_initial.sql", "migrations/002_console_auth.sql"} {
		body, err := embeddedMigrations.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		prior[name] = &fstest.MapFile{Data: body}
	}
	if version, err := MigrateFS(context.Background(), db, prior); err != nil || version != 2 {
		t.Fatalf("install prior schema: version=%d err=%v", version, err)
	}
	if _, err := db.Exec(`INSERT INTO devices (id, enrolled_at, identity_public_key, mesh_public_key)
		VALUES ('candidate:old', now(), '\x01', 'mesh:old');
		INSERT INTO telemetry_samples (device_id, sequence, collected_at, schema_version, payload, evidence_digest, signature)
		VALUES ('candidate:old', 0, now(), 'legacy', '{"legacy":true}', decode(repeat('00',32),'hex'), '\x01');
		INSERT INTO console_role_bindings (issuer, subject, role) VALUES ('https://id.example.test', 'admin:old', 'admin')`); err != nil {
		t.Fatal(err)
	}
	if version, err := Migrate(context.Background(), db); err != nil || version != 4 {
		t.Fatalf("upgrade: version=%d err=%v", version, err)
	}
	var meshKey, role string
	var legacyPayload bool
	if err := db.QueryRow(`SELECT mesh_public_key FROM devices WHERE id='candidate:old'`).Scan(&meshKey); err != nil || meshKey != "mesh:old" {
		t.Fatalf("candidate identity changed: %q %v", meshKey, err)
	}
	if err := db.QueryRow(`SELECT (payload->>'legacy')::boolean FROM telemetry_samples WHERE device_id='candidate:old' AND sequence=0`).Scan(&legacyPayload); err != nil || !legacyPayload {
		t.Fatalf("candidate sample lost: %v %v", legacyPayload, err)
	}
	if err := db.QueryRow(`SELECT role FROM console_role_bindings WHERE subject='admin:old'`).Scan(&role); err != nil || role != "admin" {
		t.Fatalf("console binding changed: %q %v", role, err)
	}
	var enrolled int
	if err := db.QueryRow(`SELECT count(*) FROM device_enrollments`).Scan(&enrolled); err != nil || enrolled != 0 {
		t.Fatalf("untrusted rows acquired enrollment trust: count=%d err=%v", enrolled, err)
	}
}

func TestMigrationFailureAbortsWithoutAdvancing(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	working := fstest.MapFS{
		"migrations/001_base.sql": {Data: []byte(`CREATE TABLE failed_marker (id integer PRIMARY KEY)`)},
	}
	if _, err := MigrateFS(ctx, db, working); err != nil {
		t.Fatal(err)
	}
	broken := fstest.MapFS{
		"migrations/001_base.sql":   {Data: []byte(`CREATE TABLE failed_marker (id integer PRIMARY KEY)`)},
		"migrations/002_broken.sql": {Data: []byte(`CREATE TABLE half_written (`)},
	}
	if _, err := MigrateFS(ctx, db, broken); err == nil || !strings.Contains(err.Error(), "apply migration 002_broken") {
		t.Fatalf("injected failure: %v", err)
	}
	version, err := CurrentStatus(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version.Version != 1 {
		t.Fatalf("failed migration advanced the schema: %+v", version)
	}
	var halfWritten sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT to_regclass('half_written')::text`).Scan(&halfWritten); err != nil {
		t.Fatal(err)
	}
	if halfWritten.Valid {
		t.Fatalf("failed migration left a table behind: %q", halfWritten.String)
	}
	var marker int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM failed_marker`).Scan(&marker); err != nil {
		t.Fatal(err)
	}
	if marker != 0 {
		t.Fatalf("unexpected marker rows: %d", marker)
	}
}

func TestConcurrentMigrationRunsOnce(t *testing.T) {
	db := openTestDatabase(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Migrate(ctx, db)
			errors <- err
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 4 {
		t.Fatalf("migration ledger rows=%d want 4", count)
	}
}

func TestMigrationNaming(t *testing.T) {
	for name, files := range map[string]fstest.MapFS{
		"empty":               {},
		"bad name":            {"migrations/one.sql": {Data: []byte("SELECT 1")}},
		"duplicate":           {"migrations/001_a.sql": {Data: []byte("SELECT 1")}, "migrations/001_b.sql": {Data: []byte("SELECT 2")}},
		"managed transaction": {"migrations/001_a.sql": {Data: []byte("BEGIN;\nSELECT 1;\nCOMMIT;")}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadMigrations(files); err == nil {
				t.Fatal("invalid migration set accepted")
			}
		})
	}
}

func openTestDatabase(t *testing.T) *sql.DB {
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
	name := fmt.Sprintf("device_audit_test_%d", time.Now().UnixNano())
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
	db, err := Open(context.Background(), testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}
