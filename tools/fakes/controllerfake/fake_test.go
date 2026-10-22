package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

const vectorsPath = "../../../packages/contracts/fixtures/envelopes/v1-vectors.json"

func TestScenarios(t *testing.T) {
	report, err := RunScenarios(context.Background(), vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("scenario suite failed: %+v", report)
	}
	if len(report.Scenarios) != 4 {
		t.Fatalf("scenarios=%d want 4", len(report.Scenarios))
	}
	for _, result := range report.Scenarios {
		if result.Result != "pass" {
			t.Fatalf("%s: %+v", result.Name, result)
		}
	}
}

func TestHealthMarksFixtureMode(t *testing.T) {
	server, err := New(Config{Now: func() time.Time { return mustParseTime("2026-10-15T12:00:00Z") }})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health: %d", recorder.Code)
	}
	if recorder.Header().Get("X-Device-Audit-Fixture") != "true" {
		t.Fatal("health response is not marked as a fixture")
	}
	var body map[string]string
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["mode"] != "fixture" || body["storage"] != "memory" {
		t.Fatalf("health body: %+v", body)
	}
}

func TestUnknownDeviceAndWrongDeployment(t *testing.T) {
	vectors, err := loadVectorFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Now: func() time.Time { return mustParseTime("2026-10-15T12:00:00Z") }})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()

	acknowledgement, err := postEnvelope(context.Background(), httpServer.Client(), httpServer.URL+"/v1/envelopes", vectors["valid offline evidence with nullable metric"])
	if err != nil {
		t.Fatal(err)
	}
	if acknowledgement.Status != "rejected" || acknowledgement.RejectionReason == nil || *acknowledgement.RejectionReason != "unknown_device" {
		t.Fatalf("unexpected unknown-device acknowledgement: %+v", acknowledgement)
	}

	other, err := New(Config{DeploymentID: "deployment:other", Now: func() time.Time { return mustParseTime("2026-10-15T12:00:00Z") }})
	if err != nil {
		t.Fatal(err)
	}
	otherServer := httptest.NewServer(other.Handler())
	defer otherServer.Close()
	acknowledgement, err = postEnvelope(context.Background(), otherServer.Client(), otherServer.URL+"/v1/envelopes", vectors["valid enrollment"])
	if err != nil {
		t.Fatal(err)
	}
	if acknowledgement.Status != "rejected" || acknowledgement.RejectionReason == nil || *acknowledgement.RejectionReason != "deployment_mismatch" {
		t.Fatalf("unexpected deployment acknowledgement: %+v", acknowledgement)
	}
}

func TestMalformedAndOversizedEnvelopesHaveNoAcknowledgement(t *testing.T) {
	server, err := New(Config{MaxBodyBytes: 32})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	for name, body := range map[string]string{
		"malformed":       `{`,
		"unknown version": `{"schema_version":"device-audit.unknown.v1"}`,
		"oversized":       strings.Repeat("x", 64),
	} {
		t.Run(name, func(t *testing.T) {
			response, err := httpServer.Client().Post(httpServer.URL+"/v1/envelopes", "application/json", strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusBadRequest && response.StatusCode != http.StatusRequestEntityTooLarge {
				t.Fatalf("status=%d want 400 or 413", response.StatusCode)
			}
			if response.Header.Get("X-Device-Audit-Fixture") != "true" {
				t.Fatal("error response is not marked as a fixture")
			}
		})
	}
}

func TestReplayDoesNotAdvanceMark(t *testing.T) {
	vectors, err := loadVectorFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Now: func() time.Time { return mustParseTime("2026-10-15T12:00:00Z") }})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	if _, err := postEnvelope(context.Background(), httpServer.Client(), httpServer.URL+"/v1/envelopes", vectors["valid enrollment"]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		acknowledgement, err := postEnvelope(context.Background(), httpServer.Client(), httpServer.URL+"/v1/envelopes", vectors["valid offline evidence with nullable metric"])
		if err != nil {
			t.Fatal(err)
		}
		want := "accepted"
		if i == 1 {
			want = "rejected"
			if acknowledgement.RejectionReason == nil || *acknowledgement.RejectionReason != "replay" {
				t.Fatalf("second delivery: %+v", acknowledgement)
			}
		}
		if acknowledgement.Status != want {
			t.Fatalf("delivery %d status=%s want %s", i, acknowledgement.Status, want)
		}
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.highWater["asset:fixture-01"] != 2 {
		t.Fatalf("mark advanced to %d", server.highWater["asset:fixture-01"])
	}
}

func TestAcknowledgementContract(t *testing.T) {
	vectors, err := loadVectorFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Now: func() time.Time { return mustParseTime("2026-10-15T12:00:00Z") }})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	if _, err := postEnvelope(context.Background(), httpServer.Client(), httpServer.URL+"/v1/envelopes", vectors["valid enrollment"]); err != nil {
		t.Fatal(err)
	}
	response, err := httpServer.Client().Post(httpServer.URL+"/v1/envelopes", "application/json", strings.NewReader(string(vectors["valid offline evidence with nullable metric"])))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var acknowledgement contracts.AcknowledgementV1
	if err := json.NewDecoder(response.Body).Decode(&acknowledgement); err != nil {
		t.Fatal(err)
	}
	if acknowledgement.RequestSchemaVersion != contracts.EvidenceEnvelopeV1Version || acknowledgement.RequestSequence != 2 || acknowledgement.DeploymentID != FixtureDeploymentID {
		t.Fatalf("correlation fields: %+v", acknowledgement)
	}
	if acknowledgement.Status != "accepted" || acknowledgement.RejectionReason != nil {
		t.Fatalf("accepted acknowledgement: %+v", acknowledgement)
	}
}

func TestEnrollmentRejectsNonFixtureKey(t *testing.T) {
	vectors, err := loadVectorFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{Now: func() time.Time { return mustParseTime("2026-10-15T12:00:00Z") }})
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	var enrollment contracts.EnrollmentEnvelopeV1
	if err := json.Unmarshal(vectors["valid enrollment"], &enrollment); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	publicKey := key.Public().(ed25519.PublicKey)
	enrollment.PublicKey = hex.EncodeToString(publicKey)
	enrollment.SigningKeyID, err = contracts.SigningKeyIDV1(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	message, err := enrollment.SigningBytes()
	if err != nil {
		t.Fatal(err)
	}
	enrollment.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	if err := enrollment.Validate(); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatal(err)
	}
	ack, err := postEnvelope(context.Background(), httpServer.Client(), httpServer.URL+"/v1/envelopes", body)
	if err != nil {
		t.Fatal(err)
	}
	if ack.Status != "rejected" || ack.RejectionReason == nil || *ack.RejectionReason != "key_mismatch" {
		t.Fatalf("non-fixture enrollment: %+v", ack)
	}
	server.mu.Lock()
	if len(server.devices) != 0 || len(server.highWater) != 0 || len(server.challenges) != 0 {
		t.Error("rejected key changed fixture state")
	}
	server.mu.Unlock()
	// The rejected request must not consume the fixture's challenge or device ID.
	ack, err = postEnvelope(context.Background(), httpServer.Client(), httpServer.URL+"/v1/envelopes", vectors["valid enrollment"])
	if err != nil || ack.Status != "accepted" {
		t.Fatalf("fixture enrollment: %+v err=%v", ack, err)
	}
}

func TestServeCLI(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "controllerfake.exe")
	if output, err := exec.Command("go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, output)
	}
	for _, address := range []string{"0.0.0.0:0", "[::]:0", "localhost:0", "127.0.0.1"} {
		if output, err := exec.Command(binary, "--listen", address).CombinedOutput(); err == nil || !strings.Contains(string(output), "literal loopback") {
			t.Fatalf("unsafe listener %q: err=%v output=%s", address, err, output)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	listener.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--listen", address)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = command.Wait() }()
	client := &http.Client{Timeout: 200 * time.Millisecond}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response, err := client.Get("http://" + address + "/healthz")
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			response.Body.Close()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if response.StatusCode != http.StatusOK || response.Header.Get("X-Device-Audit-Fixture") != "true" || !strings.Contains(string(body), `"admission":"fixture_keys_only"`) {
				t.Fatalf("health response=%s", body)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("fixture CLI did not serve health on a literal loopback host:port")
}
