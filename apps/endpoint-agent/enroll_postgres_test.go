package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/infra/database"
	"github.com/i-got-this-faa/device-audit/internal/controller"
	"github.com/i-got-this-faa/device-audit/internal/controller/auth"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// Uses the actual TLS handlers and a disposable PostgreSQL database. Issuance
// calls the authorized repository boundary; no external OIDC login is claimed.
func TestEndpointEnrollmentPostgres(t *testing.T) {
	configured := os.Getenv("TEST_DATABASE_URL")
	if configured == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	parsed, err := url.Parse(configured)
	if err != nil {
		t.Fatal("invalid test database URL")
	}
	ctx := context.Background()
	adminURL := *parsed
	adminURL.Path = "/postgres"
	admin, err := database.Open(ctx, adminURL.String())
	if err != nil {
		t.Fatal("connect test database admin")
	}
	defer admin.Close()
	name := fmt.Sprintf("endpoint_keys_test_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE DATABASE "` + name + `"`); err != nil {
		t.Fatal("create isolated database")
	}
	defer func() {
		if _, err := admin.Exec(`DROP DATABASE "` + name + `" WITH (FORCE)`); err != nil {
			t.Error("drop isolated database")
		}
	}()
	parsed.Path = "/" + name
	db, err := database.Open(ctx, parsed.String())
	if err != nil {
		t.Fatal("connect isolated database")
	}
	defer db.Close()
	if _, err := database.Migrate(ctx, db); err != nil {
		t.Fatal("migrate isolated database")
	}
	repo, err := controller.NewPostgresRepository(ctx, db, controller.RepositoryConfig{DeploymentID: "deployment:endpoint-test"})
	if err != nil {
		t.Fatal(err)
	}
	store := auth.NewPostgresStore(db)
	adminService, err := auth.NewService(auth.Config{Issuer: "https://id.example.test", PublicOrigin: "https://console.example.test", Store: store, Provider: auth.NewOIDCProvider("https://id.example.test", "test-client", "test-only", "https://console.example.test/auth/callback", nil)})
	if err != nil {
		t.Fatal(err)
	}
	service, err := controller.NewEnrollmentService(repo, adminService)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	service.Register(mux)
	server := httptest.NewTLSServer(mux)
	defer server.Close()
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600) != nil {
		t.Fatal("write test CA")
	}
	client, origin, err := enrollmentClient(server.URL, ca)
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	token, err := repo.IssueBootstrapToken(ctx, contracts.BootstrapTokenRequestV1{SchemaVersion: contracts.BootstrapTokenRequestV1Version, DeviceID: "device:endpoint-test"}, "https://id.example.test", "admin:test")
	if err != nil {
		t.Fatal(err)
	}
	s, path := testStore(t)
	accepted, err := enroll(ctx, s, client, origin, token)
	if err != nil {
		t.Fatal(err)
	}
	var signingKey, networkKey string
	if err := db.QueryRow(`SELECT e.signing_key_id, encode(n.network_public_key,'hex') FROM device_enrollments e JOIN device_network_bindings n USING (deployment_id,device_id) WHERE e.deployment_id=$1 AND e.device_id=$2`, token.DeploymentID, token.DeviceID).Scan(&signingKey, &networkKey); err != nil {
		t.Fatal("read committed binding")
	}
	if signingKey != accepted.SigningKeyID || networkKey != accepted.NetworkPublicKey {
		t.Fatal("remote binding differs from local receipt")
	}
	i, err := s.load(false)
	if err != nil {
		t.Fatal(err)
	}
	s.close()
	// A new process reads disk state while the committed token remains consumed.
	command := identityStatusProcess(path)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("restart failed against admitted disk state")
	}
	var restarted contracts.EnrollmentAcceptedV1
	if json.Unmarshal(out, &restarted) != nil || restarted != accepted {
		t.Fatal("restart did not retain committed admission")
	}
	public, _ := hex.DecodeString(i.start(token.DeploymentID, token.DeviceID).PublicKey)
	id, _ := contracts.SigningKeyIDV1(ed25519.PublicKey(public))
	if id != signingKey {
		t.Fatal("restart key mismatch")
	}
}
