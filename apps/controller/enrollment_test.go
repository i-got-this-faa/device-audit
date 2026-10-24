package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEnrollmentConfigurationFailsBeforeListening(t *testing.T) {
	for _, args := range [][]string{
		{"--deployment-id", "deployment:test"},
		{"--tls-cert-file", "missing-certificate", "--tls-key-file", "missing-key"},
	} {
		t.Run(args[0], func(t *testing.T) {
			address := freeAddress(t)
			args = append(args, "--listen", address)
			if err := run(context.Background(), args, environment{}); err == nil {
				t.Fatal("incomplete enrollment/TLS configuration started")
			}
			if connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
				connection.Close()
				t.Fatal("invalid enrollment configuration opened listener")
			}
		})
	}
}

func TestRunServesEnrollmentThroughConfiguredTLS(t *testing.T) {
	databaseURL := testDatabase(t)
	certificateServer := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificate := certificateServer.TLS.Certificates[0]
	client := certificateServer.Client()
	certificateServer.Close()
	private, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile, keyFile := filepath.Join(directory, "certificate.pem"), filepath.Join(directory, "private.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	address := freeAddress(t)
	origin := "https://" + address
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		finished <- run(ctx, []string{"--listen", address}, environment{DatabaseURL: databaseURL, OIDCIssuer: "https://id.example.test", OIDCClientID: "test-client", OIDCClientSecret: "test-only", OIDCRedirectURL: origin + "/auth/callback", PublicOrigin: origin, BootstrapAdmin: "admin:test", DeploymentID: "deployment:startup", TLSCertFile: certFile, TLSKeyFile: keyFile})
	}()
	client.Timeout = time.Second
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get(origin + "/healthz")
		if err == nil {
			var health map[string]any
			decodeErr := json.NewDecoder(response.Body).Decode(&health)
			response.Body.Close()
			if decodeErr == nil && health["schema_version"] == float64(4) && health["enrollment"] == "configured" {
				ready = true
				break
			}
		}
		select {
		case err := <-finished:
			t.Fatalf("TLS enrollment startup failed: %v", err)
		default:
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("TLS controller did not become healthy")
	}
	for _, test := range []struct {
		path string
		want int
	}{
		{"/admin/bootstrap-tokens", http.StatusUnauthorized},
		{"/v1/enrollment/challenges", http.StatusForbidden},
		{"/v1/enrollment", http.StatusForbidden},
	} {
		response, err := client.Post(origin+test.path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != test.want {
			t.Fatalf("TLS route %s status=%d want=%d", test.path, response.StatusCode, test.want)
		}
	}
	cancel()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TLS controller did not stop")
	}
}
