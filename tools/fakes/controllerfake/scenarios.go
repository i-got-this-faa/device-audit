package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

// Scenario names are stable so CI output and endpoint test harnesses can select one.
const (
	ScenarioAssignment = "assignment"
	ScenarioExpiry     = "expiry"
	ScenarioOffline    = "offline"
	ScenarioDuplicate  = "duplicate"
)

// ScenarioReport is the machine-readable fixture evidence written by `make fake-check`.
type ScenarioReport struct {
	Fixture   bool             `json:"fixture"`
	Scenarios []ScenarioResult `json:"scenarios"`
	Passed    bool             `json:"passed"`
}

type ScenarioResult struct {
	Name            string  `json:"name"`
	Result          string  `json:"result"`
	Status          string  `json:"status,omitempty"`
	RejectionReason string  `json:"rejection_reason,omitempty"`
	LastSequence    *uint64 `json:"last_sequence,omitempty"`
	Detail          string  `json:"detail,omitempty"`
}

type fixtureClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fixtureClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fixtureClock) Set(now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = now
}

type vectorFile struct {
	Vectors []struct {
		Name     string          `json:"name"`
		Envelope json.RawMessage `json:"envelope"`
	} `json:"vectors"`
}

// RunScenarios starts the fixture in-process and runs the four deterministic
// development scenarios. It is the command behind `make fake-check`.
func RunScenarios(ctx context.Context, fixturePath string) (ScenarioReport, error) {
	vectors, err := loadVectorFile(fixturePath)
	if err != nil {
		return ScenarioReport{}, err
	}
	report := ScenarioReport{Fixture: true, Passed: true}
	for _, run := range []struct {
		name string
		fn   func(context.Context, map[string]json.RawMessage) ScenarioResult
	}{
		{ScenarioAssignment, scenarioAssignment},
		{ScenarioExpiry, scenarioExpiry},
		{ScenarioOffline, scenarioOffline},
		{ScenarioDuplicate, scenarioDuplicate},
	} {
		result := run.fn(ctx, vectors)
		result.Name = run.name
		if result.Result != "pass" {
			report.Passed = false
		}
		report.Scenarios = append(report.Scenarios, result)
	}
	return report, nil
}

func scenarioAssignment(ctx context.Context, vectors map[string]json.RawMessage) ScenarioResult {
	clock, baseURL, stop, err := startFixture("2026-10-15T12:00:00Z")
	if err != nil {
		return failed(err.Error())
	}
	defer stop()
	enrollment, result := postVector(ctx, baseURL, vectors, "valid enrollment")
	if result != "" {
		return failed(result)
	}
	if enrollment.Status != "accepted" || enrollment.LastSequence == nil || *enrollment.LastSequence != 1 {
		return failed("enrollment was not accepted with sequence 1")
	}
	evidence, result := postVector(ctx, baseURL, vectors, "valid offline evidence with nullable metric")
	if result != "" {
		return failed(result)
	}
	if evidence.Status != "accepted" || evidence.LastSequence == nil || *evidence.LastSequence != 2 {
		return failed("evidence was not accepted with sequence 2")
	}
	return ScenarioResult{
		Result:       "pass",
		Status:       evidence.Status,
		LastSequence: evidence.LastSequence,
		Detail:       fmt.Sprintf("enrollment and evidence accepted at fixture clock %s", clock.Now().UTC().Format(time.RFC3339)),
	}
}

func scenarioExpiry(ctx context.Context, vectors map[string]json.RawMessage) ScenarioResult {
	clock, baseURL, stop, err := startFixture("2026-10-15T12:00:00Z")
	if err != nil {
		return failed(err.Error())
	}
	defer stop()
	if _, result := postVector(ctx, baseURL, vectors, "valid enrollment"); result != "" {
		return failed(result)
	}
	clock.Set(mustParseTime("2026-10-16T12:00:00Z"))
	acknowledgement, result := postVector(ctx, baseURL, vectors, "expired at exact boundary")
	if result != "" {
		return failed(result)
	}
	if acknowledgement.Status != "rejected" || acknowledgement.RejectionReason == nil || *acknowledgement.RejectionReason != "expired" {
		return failed("expiry did not produce a rejected acknowledgement")
	}
	return ScenarioResult{
		Result:          "pass",
		Status:          acknowledgement.Status,
		RejectionReason: *acknowledgement.RejectionReason,
		LastSequence:    acknowledgement.LastSequence,
		Detail:          "evidence at the inclusive expiry boundary was rejected as expired",
	}
}

func scenarioOffline(ctx context.Context, _ map[string]json.RawMessage) ScenarioResult {
	server := httptest.NewServer(http.NotFoundHandler())
	baseURL := server.URL + "/v1/envelopes"
	server.Close()
	client := &http.Client{Timeout: 2 * time.Second}
	_, err := postEnvelope(ctx, client, baseURL, []byte(`{}`))
	if err == nil {
		return failed("offline controller unexpectedly answered")
	}
	return ScenarioResult{Result: "pass", Detail: "an unreachable controller failed closed with no acknowledgement"}
}

func scenarioDuplicate(ctx context.Context, vectors map[string]json.RawMessage) ScenarioResult {
	_, baseURL, stop, err := startFixture("2026-10-15T12:00:00Z")
	if err != nil {
		return failed(err.Error())
	}
	defer stop()
	if _, result := postVector(ctx, baseURL, vectors, "valid enrollment"); result != "" {
		return failed(result)
	}
	first, result := postVector(ctx, baseURL, vectors, "valid offline evidence with nullable metric")
	if result != "" {
		return failed(result)
	}
	if first.Status != "accepted" {
		return failed("first evidence delivery was not accepted")
	}
	second, result := postVector(ctx, baseURL, vectors, "valid offline evidence with nullable metric")
	if result != "" {
		return failed(result)
	}
	if second.Status != "rejected" || second.RejectionReason == nil || *second.RejectionReason != "replay" {
		return failed("duplicate evidence was not rejected as replay")
	}
	if second.LastSequence == nil || *second.LastSequence != 2 {
		return failed("replay acknowledgement did not report the durable mark")
	}
	return ScenarioResult{
		Result:          "pass",
		Status:          second.Status,
		RejectionReason: *second.RejectionReason,
		LastSequence:    second.LastSequence,
		Detail:          "second delivery of sequence 2 was rejected without advancing the mark",
	}
}

func startFixture(now string) (*fixtureClock, string, func(), error) {
	clock := &fixtureClock{now: mustParseTime(now)}
	server, err := New(Config{Now: clock.Now})
	if err != nil {
		return nil, "", func() {}, err
	}
	httpServer := httptest.NewServer(server.Handler())
	return clock, httpServer.URL + "/v1/envelopes", httpServer.Close, nil
}

func postVector(ctx context.Context, baseURL string, vectors map[string]json.RawMessage, name string) (contracts.AcknowledgementV1, string) {
	envelope, ok := vectors[name]
	if !ok {
		return contracts.AcknowledgementV1{}, fmt.Sprintf("fixture vector %q is missing", name)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	acknowledgement, err := postEnvelope(ctx, client, baseURL, envelope)
	if err != nil {
		return contracts.AcknowledgementV1{}, err.Error()
	}
	return acknowledgement, ""
}

// postEnvelope validates and cryptographically verifies the controller-signed
// acknowledgement before returning it.
func postEnvelope(ctx context.Context, client *http.Client, url string, envelope []byte) (contracts.AcknowledgementV1, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(envelope))
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if err != nil {
		return contracts.AcknowledgementV1{}, err
	}
	if response.StatusCode != http.StatusOK {
		return contracts.AcknowledgementV1{}, fmt.Errorf("fixture returned %s: %s", response.Status, body)
	}
	var acknowledgement contracts.AcknowledgementV1
	if err := json.Unmarshal(body, &acknowledgement); err != nil {
		return contracts.AcknowledgementV1{}, fmt.Errorf("invalid fixture acknowledgement: %w", err)
	}
	controllerKey := ed25519.NewKeyFromSeed(mustHex(controllerSeed))
	if err := acknowledgement.VerifySignature(controllerKey.Public().(ed25519.PublicKey)); err != nil {
		return contracts.AcknowledgementV1{}, fmt.Errorf("fixture acknowledgement signature: %w", err)
	}
	return acknowledgement, nil
}

func loadVectorFile(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fixture vectors: %w", err)
	}
	var file vectorFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("decode fixture vectors: %w", err)
	}
	vectors := make(map[string]json.RawMessage, len(file.Vectors))
	for _, vector := range file.Vectors {
		vectors[vector.Name] = vector.Envelope
	}
	return vectors, nil
}

func mustParseTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return parsed
}

func failed(detail string) ScenarioResult {
	return ScenarioResult{Result: "fail", Detail: detail}
}
