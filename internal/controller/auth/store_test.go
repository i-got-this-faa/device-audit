package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
)

func TestPostgresStoreLifecycle(t *testing.T) {
	db := openAuthTestDatabase(t)
	ctx := context.Background()
	version, err := database.Migrate(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if version != 3 {
		t.Fatalf("schema version=%d want 3", version)
	}
	store := NewPostgresStore(db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	issuer := "https://id.example.test"

	if err := store.UpsertBinding(ctx, Binding{Issuer: issuer, Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	binding, err := store.Binding(ctx, issuer, "viewer-1")
	if err != nil || binding.Role != RoleViewer {
		t.Fatalf("binding=%+v err=%v", binding, err)
	}
	if err := store.CreateBinding(ctx, Binding{Issuer: issuer, Subject: "viewer-1", Role: RoleAdmin, CreatedAt: now.Add(time.Hour), UpdatedAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	binding, err = store.Binding(ctx, issuer, "viewer-1")
	if err != nil || binding.Role != RoleViewer {
		t.Fatalf("create-only binding=%+v err=%v", binding, err)
	}
	if err := store.UpsertBinding(ctx, Binding{Issuer: issuer, Subject: "viewer-1", Role: RoleAdmin, CreatedAt: now.Add(time.Hour), UpdatedAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	binding, err = store.Binding(ctx, issuer, "viewer-1")
	if err != nil || binding.Role != RoleAdmin || !binding.CreatedAt.Equal(now) {
		t.Fatalf("updated binding=%+v err=%v", binding, err)
	}
	bindings, err := store.Bindings(ctx, issuer)
	if err != nil || len(bindings) != 1 || bindings[0].Subject != "viewer-1" {
		t.Fatalf("bindings=%+v err=%v", bindings, err)
	}
	if _, err := store.Binding(ctx, issuer, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing binding error=%v", err)
	}
	if err := store.UpsertBinding(ctx, Binding{Issuer: issuer, Subject: "admin-2", Role: RoleAdmin, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertBinding(ctx, Binding{Issuer: issuer, Subject: "viewer-1", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("demote with another admin: %v", err)
	}
	if err := store.UpsertBinding(ctx, Binding{Issuer: issuer, Subject: "admin-2", Role: RoleViewer, CreatedAt: now, UpdatedAt: now}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("last admin demotion error=%v", err)
	}
	if binding, err := store.Binding(ctx, issuer, "admin-2"); err != nil || binding.Role != RoleAdmin {
		t.Fatalf("last admin binding changed: %+v err=%v", binding, err)
	}

	login := LoginTransaction{
		StateDigest:  digest("state-value"),
		Nonce:        "nonce-value",
		CodeVerifier: "verifier-value",
		ReturnTo:     "/console",
		CreatedAt:    now,
		ExpiresAt:    now.Add(5 * time.Minute),
	}
	if err := store.PutLogin(ctx, login); err != nil {
		t.Fatal(err)
	}
	consumed, err := store.ConsumeLogin(ctx, login.StateDigest, now.Add(time.Minute))
	if err != nil || consumed.Nonce != login.Nonce || consumed.ReturnTo != login.ReturnTo {
		t.Fatalf("consumed=%+v err=%v", consumed, err)
	}
	if _, err := store.ConsumeLogin(ctx, login.StateDigest, now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("reused login error=%v", err)
	}
	expired := LoginTransaction{
		StateDigest:  digest("expired-state"),
		Nonce:        "expired-nonce",
		CodeVerifier: "expired-verifier",
		ReturnTo:     "/console",
		CreatedAt:    now,
		ExpiresAt:    now.Add(time.Minute),
	}
	if err := store.PutLogin(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeLogin(ctx, expired.StateDigest, expired.ExpiresAt); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired login error=%v", err)
	}

	sessionID := digest("session-id")
	session := Session{
		IDDigest:          sessionID,
		CSRFToken:         "csrf-value",
		Issuer:            issuer,
		Subject:           "viewer-1",
		Role:              RoleAdmin,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}
	if err := store.CreateSession(ctx, session); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Session(ctx, sessionID)
	if err != nil || loaded.CSRFToken != "csrf-value" || loaded.Role != RoleAdmin {
		t.Fatalf("session=%+v err=%v", loaded, err)
	}
	touched := now.Add(5 * time.Minute)
	if err := store.TouchSession(ctx, sessionID, touched, touched.Add(15*time.Minute)); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Session(ctx, sessionID)
	if err != nil || !loaded.LastSeenAt.Equal(touched) {
		t.Fatalf("touched session=%+v err=%v", loaded, err)
	}
	if err := store.TouchSession(ctx, sessionID, touched.Add(15*time.Minute), touched.Add(30*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch revived idle-expired session: %v", err)
	}
	if err := store.RevokeSession(ctx, sessionID, touched); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Session(ctx, sessionID)
	if err != nil || loaded.RevokedAt == nil {
		t.Fatalf("revoked session=%+v err=%v", loaded, err)
	}
	if err := store.TouchSession(ctx, sessionID, touched, touched.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("touch revoked session error=%v", err)
	}

	secondSessionID := digest("second-session")
	if err := store.CreateSession(ctx, Session{
		IDDigest:          secondSessionID,
		CSRFToken:         "second-csrf",
		Issuer:            issuer,
		Subject:           "viewer-1",
		Role:              RoleAdmin,
		CreatedAt:         now,
		LastSeenAt:        now,
		IdleExpiresAt:     now.Add(15 * time.Minute),
		AbsoluteExpiresAt: now.Add(8 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.RevokeSubjectSessions(ctx, issuer, "viewer-1", touched); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Session(ctx, secondSessionID)
	if err != nil || loaded.RevokedAt == nil {
		t.Fatalf("subject sessions not revoked: %+v err=%v", loaded, err)
	}

	thirdSession := session
	thirdSession.IDDigest = digest("role-cycle-session")
	thirdSession.Role = RoleViewer
	if err := store.CreateSession(ctx, thirdSession); err != nil {
		t.Fatal(err)
	}
	for _, role := range []Role{RoleAdmin, RoleViewer} {
		if err := store.UpsertBinding(ctx, Binding{Issuer: issuer, Subject: "viewer-1", Role: role, CreatedAt: now, UpdatedAt: touched}); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err = store.Session(ctx, thirdSession.IDDigest)
	if err != nil || loaded.RevokedAt == nil {
		t.Fatalf("role cycle revived session: %+v err=%v", loaded, err)
	}

	db.Close()
	if _, err := store.Binding(ctx, issuer, "viewer-1"); err == nil {
		t.Fatal("closed database did not fail the store")
	}
}

func openAuthTestDatabase(t *testing.T) *sql.DB {
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
	name := "device_audit_auth_test_" + strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "_")
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
	db, err := database.Open(context.Background(), testURL.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
