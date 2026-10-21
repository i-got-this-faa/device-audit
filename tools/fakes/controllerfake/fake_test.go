package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
