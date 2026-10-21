package fakes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	replayfixtures "github.com/i-got-this-faa/device-audit/packages/contracts/fixtures/replay"
)

const (
	fakeTelemetryRoute     = "/contract-fake/telemetry"
	fakeDiagnosticsRoute   = "/contract-fake/diagnostics/results"
	fakeFederatedRoute     = "/contract-fake/federated/updates"
	contractFakeTestHeader = "X-Contract-Fake-Server"
	contractFakeTestLabel  = "contract-aware-test-fake"
)

type contractAwareFake struct {
	bundle        replayfixtures.Bundle
	deviceKey     []byte
	controllerKey []byte
	assignment    contracts.DiagnosticAssignmentV1
	round         contracts.FederatedRoundV1
	fixedTime     time.Time
	mu            sync.Mutex
	highWater     uint64
	seen          map[string]bool
	dropResponses map[string]bool
	accepted      int
	duplicates    int
	malformed     int
	requests      int
	sequences     []uint64
}

func newContractAwareFake(t *testing.T) *contractAwareFake {
	t.Helper()
	bundle, err := replayfixtures.Load()
	if err != nil {
		t.Fatal(err)
	}
	deviceKey, err := hex.DecodeString(bundle.DevicePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, err := hex.DecodeString(bundle.Diagnostics.ControllerPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var assignment contracts.DiagnosticAssignmentV1
	if err := json.Unmarshal(bundle.Diagnostics.Assignment.Body, &assignment); err != nil {
		t.Fatal(err)
	}
	var round contracts.FederatedRoundV1
	if err := json.Unmarshal(bundle.Federated.Round, &round); err != nil {
		t.Fatal(err)
	}
	fixedTime, err := time.Parse(time.RFC3339, bundle.FixedTime)
	if err != nil {
		t.Fatal(err)
	}
	return &contractAwareFake{
		bundle: bundle, deviceKey: deviceKey, controllerKey: controllerKey,
		assignment: assignment, round: round, fixedTime: fixedTime,
		seen: make(map[string]bool),
	}
}

func (fake *contractAwareFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(contractFakeTestHeader, contractFakeTestLabel)
	if r.Method != http.MethodPost || r.Header.Get(fixtureHeader) != "true" {
		http.Error(w, "fixture-only request required", http.StatusBadRequest)
		return
	}
	family, fixtureID, ok := fake.familyForRoute(r.URL.Path)
	if !ok || fixtureID != r.Header.Get(fixtureIDHeader) {
		http.Error(w, "unknown fixture route or ID", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBytes+1))
	if err != nil || len(body) > maxRequestBytes {
		http.Error(w, "request bound exceeded", http.StatusRequestEntityTooLarge)
		return
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	fake.requests++
	if r.Header.Get(fixtureScenarioHeader) == string(MalformedScenario) {
		if _, err := fake.verify(family, body); err == nil {
			http.Error(w, "malformed fixture unexpectedly verified", http.StatusUnprocessableEntity)
			return
		}
		fake.malformed++
		http.Error(w, "fixture signature rejected", http.StatusBadRequest)
		return
	}
	request, err := fake.verify(family, body)
	if err != nil {
		http.Error(w, "fixture contract check failed", http.StatusBadRequest)
		return
	}
	fingerprint := request.Fingerprint
	if fake.seen[fingerprint] {
		fake.duplicates++
		w.Header().Set("X-Contract-Fake-Result", "duplicate-same-envelope")
		if family == TelemetryFamily {
			http.Error(w, "fixture sequence already consumed", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if request.DeviceID != fake.bundle.DeviceID || request.Sequence <= fake.highWater {
		http.Error(w, "fixture sequence rejected", http.StatusConflict)
		return
	}
	fake.seen[fingerprint] = true
	fake.highWater = request.Sequence
	fake.accepted++
	fake.sequences = append(fake.sequences, request.Sequence)
	if fake.dropResponses[fixtureID] {
		delete(fake.dropResponses, fixtureID)
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "fake server cannot drop response", http.StatusInternalServerError)
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			http.Error(w, "fake server cannot drop response", http.StatusInternalServerError)
			return
		}
		_ = connection.Close()
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

type verifiedRequest struct {
	DeviceID    string
	Sequence    uint64
	Fingerprint string
}

func (fake *contractAwareFake) familyForRoute(route string) (Family, string, bool) {
	switch route {
	case fakeTelemetryRoute:
		return TelemetryFamily, fake.bundle.Telemetry.FixtureID, true
	case fakeDiagnosticsRoute:
		return DiagnosticsFamily, fake.bundle.Diagnostics.Result.FixtureID, true
	case fakeFederatedRoute:
		return FederatedFamily, fake.bundle.Federated.Update.FixtureID, true
	default:
		return "", "", false
	}
}

func (fake *contractAwareFake) verify(family Family, body []byte) (verifiedRequest, error) {
	switch family {
	case TelemetryFamily:
		var evidence contracts.EvidenceEnvelopeV1
		if err := json.Unmarshal(body, &evidence); err != nil {
			return verifiedRequest{}, err
		}
		if err := evidence.VerifySignature(fake.deviceKey); err != nil {
			return verifiedRequest{}, err
		}
		signingBytes, err := evidence.SigningBytes()
		if err != nil {
			return verifiedRequest{}, err
		}
		fingerprint, err := contracts.EnvelopeRequestSHA256V1(signingBytes, evidence.Signature)
		if err != nil {
			return verifiedRequest{}, err
		}
		return verifiedRequest{DeviceID: evidence.DeviceID, Sequence: evidence.Sequence, Fingerprint: fingerprint}, nil
	case DiagnosticsFamily:
		var result contracts.DiagnosticResultV1
		if err := json.Unmarshal(body, &result); err != nil {
			return verifiedRequest{}, err
		}
		if err := result.VerifySignature(fake.deviceKey); err != nil {
			return verifiedRequest{}, err
		}
		if err := fake.assignment.VerifySignature(fake.controllerKey); err != nil {
			return verifiedRequest{}, err
		}
		if err := result.CheckAssignment(fake.assignment); err != nil {
			return verifiedRequest{}, err
		}
		signingBytes, err := result.SigningBytes()
		if err != nil {
			return verifiedRequest{}, err
		}
		fingerprint, err := contracts.EnvelopeRequestSHA256V1(signingBytes, result.Signature)
		if err != nil {
			return verifiedRequest{}, err
		}
		return verifiedRequest{DeviceID: result.DeviceID, Sequence: result.Sequence, Fingerprint: fingerprint}, nil
	case FederatedFamily:
		var update contracts.FederatedUpdateV1
		if err := json.Unmarshal(body, &update); err != nil {
			return verifiedRequest{}, err
		}
		if err := update.VerifySignature(fake.deviceKey); err != nil {
			return verifiedRequest{}, err
		}
		if err := update.CheckRound(fake.round, fake.fixedTime); err != nil {
			return verifiedRequest{}, err
		}
		signingBytes, err := update.SigningBytes()
		if err != nil {
			return verifiedRequest{}, err
		}
		fingerprint, err := contracts.EnvelopeRequestSHA256V1(signingBytes, update.Signature)
		if err != nil {
			return verifiedRequest{}, err
		}
		return verifiedRequest{DeviceID: update.DeviceID, Sequence: update.Sequence, Fingerprint: fingerprint}, nil
	default:
		return verifiedRequest{}, fmt.Errorf("unknown family %q", family)
	}
}

func TestRunAllScenariosAgainstContractAwareFake(t *testing.T) {
	fake := newContractAwareFake(t)
	server := httptest.NewServer(fake)
	defer server.Close()

	report, err := Run(context.Background(), Options{
		Controller: server.URL, Profile: ContractFakeProfile, Scenario: AllScenarios,
		Routes: map[Family]string{
			TelemetryFamily: fakeTelemetryRoute, DiagnosticsFamily: fakeDiagnosticsRoute, FederatedFamily: fakeFederatedRoute,
		},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !report.Fixture || report.DeviceID != "fixture-replay-device" || len(report.Results) != 12 {
		t.Fatalf("unexpected replay report: fixture=%t device=%q results=%d", report.Fixture, report.DeviceID, len(report.Results))
	}
	outcomes := map[string]int{}
	for _, result := range report.Results {
		outcomes[result.Outcome]++
		if result.Outcome == "cancelled_before_submission" {
			want := http.StatusAccepted
			if result.Family == TelemetryFamily {
				want = http.StatusConflict
			}
			if result.Sent || result.Status != nil || result.ExpectedStatus != want {
				t.Errorf("invalid cancellation report row: %+v", result)
			}
			continue
		}
		if !result.Sent || result.Status == nil || *result.Status != result.ExpectedStatus {
			t.Errorf("unexpected response report row: %+v", result)
		}
	}
	if outcomes["cancelled_before_submission"] != 3 || outcomes["expected_response"] != 9 {
		t.Fatalf("unexpected report outcomes: %v", outcomes)
	}
	if fake.accepted != 3 || fake.duplicates != 3 || fake.malformed != 3 || fake.requests != 9 {
		t.Fatalf("fake state accepted=%d duplicates=%d malformed=%d requests=%d", fake.accepted, fake.duplicates, fake.malformed, fake.requests)
	}
	if fmt.Sprint(fake.sequences) != "[2 3 4]" || fake.highWater != 4 {
		t.Fatalf("unexpected sequence order/state: %v high-water=%d", fake.sequences, fake.highWater)
	}
}

func TestContractAwareFakeRejectsMalformedJSONForEveryFamily(t *testing.T) {
	fake := newContractAwareFake(t)
	server := httptest.NewServer(fake)
	defer server.Close()
	bundle, err := replayfixtures.Load()
	if err != nil {
		t.Fatal(err)
	}
	requests, err := validateFixtures(bundle)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := parseOrigin(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	routes := map[Family]string{
		TelemetryFamily: fakeTelemetryRoute, DiagnosticsFamily: fakeDiagnosticsRoute, FederatedFamily: fakeFederatedRoute,
	}
	for _, request := range requests {
		status, err := post(context.Background(), client, origin, routes[request.family], request.fixture, MalformedScenario, []byte("{"))
		if err != nil || status != http.StatusBadRequest {
			t.Fatalf("%s malformed JSON: status=%d err=%v", request.family, status, err)
		}
	}
	if fake.malformed != 3 || fake.accepted != 0 || fake.highWater != 0 {
		t.Fatalf("malformed JSON changed fake state: malformed=%d accepted=%d high-water=%d", fake.malformed, fake.accepted, fake.highWater)
	}
}

func TestLostResponsesResumeAsSameEnvelopeWithoutSecondCommit(t *testing.T) {
	fake := newContractAwareFake(t)
	server := httptest.NewServer(fake)
	defer server.Close()
	bundle, err := replayfixtures.Load()
	if err != nil {
		t.Fatal(err)
	}
	requests, err := validateFixtures(bundle)
	if err != nil {
		t.Fatal(err)
	}
	origin, err := parseOrigin(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	routes := map[Family]string{
		TelemetryFamily: fakeTelemetryRoute, DiagnosticsFamily: fakeDiagnosticsRoute, FederatedFamily: fakeFederatedRoute,
	}
	fake.dropResponses = make(map[string]bool, len(requests))
	for _, request := range requests {
		fake.dropResponses[request.fixture.FixtureID] = true
	}
	for _, request := range requests {
		for attempt := 0; attempt < 2; attempt++ {
			status, postErr := post(context.Background(), client, origin, routes[request.family], request.fixture, InterruptedScenario, request.fixture.Body)
			if attempt == 0 {
				if status != 0 || postErr == nil {
					t.Fatalf("first response for %s was not lost after commit: status=%d err=%v", request.family, status, postErr)
				}
				continue
			}
			want := http.StatusAccepted
			if request.family == TelemetryFamily {
				want = http.StatusConflict
			}
			if postErr != nil || status != want {
				t.Fatalf("resume for %s: status=%d want=%d err=%v", request.family, status, want, postErr)
			}
		}
	}
	if fake.accepted != 3 || fake.duplicates != 3 || fake.requests != 6 || fake.highWater != 4 || fmt.Sprint(fake.sequences) != "[2 3 4]" {
		t.Fatalf("lost response caused duplicate state: requests=%d accepted=%d duplicates=%d high-water=%d sequences=%v", fake.requests, fake.accepted, fake.duplicates, fake.highWater, fake.sequences)
	}
}

func TestScaffoldStatusOverrideDoesNotLabelAcceptedResponseUnsupported(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/telemetry" {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	report, err := Run(context.Background(), Options{
		Controller: server.URL, Profile: ScaffoldProfile, Scenario: ValidScenario,
		Routes: map[Family]string{
			TelemetryFamily: "/telemetry", DiagnosticsFamily: "/fixture/diagnostics", FederatedFamily: "/fixture/federated",
		},
		Expectations: map[Expectation]int{
			{Family: TelemetryFamily, Scenario: ValidScenario}: http.StatusAccepted,
		},
	})
	if err != nil {
		t.Fatalf("Run() with expected-status override: %v", err)
	}
	if len(report.Results) != 3 {
		t.Fatalf("results=%d, want 3", len(report.Results))
	}
	if report.Results[0].Outcome != "expected_response" || report.Results[0].Status == nil || *report.Results[0].Status != http.StatusAccepted {
		t.Fatalf("accepted response was mislabeled: %+v", report.Results[0])
	}
	for _, result := range report.Results[1:] {
		if result.Outcome != "expected_unsupported" || result.Status == nil || *result.Status != http.StatusNotFound {
			t.Errorf("missing-route response was mislabeled: %+v", result)
		}
	}
}

func TestClientBoundsResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(maxResponseBytes+1))
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, strings.Repeat("x", maxResponseBytes+1))
	}))
	defer server.Close()
	bundle, err := replayfixtures.Load()
	if err != nil {
		t.Fatal(err)
	}
	origin, err := parseOrigin(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	_, err = post(context.Background(), client, origin, fakeTelemetryRoute, bundle.Telemetry, ValidScenario, bundle.Telemetry.Body)
	if err == nil {
		t.Fatal("post() accepted an oversized response")
	}
}

func TestRunUsesBoundedHTTPTimeout(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)

	report, err := Run(context.Background(), Options{
		Controller: server.URL, Profile: ContractFakeProfile, Scenario: ValidScenario,
		Timeout: 20 * time.Millisecond,
		Routes: map[Family]string{
			TelemetryFamily: "/timeout", DiagnosticsFamily: "/timeout", FederatedFamily: "/timeout",
		},
	})
	if err == nil || len(report.Results) != 3 {
		t.Fatalf("Run() report=%+v error=%v; expected bounded request failures", report, err)
	}
	for _, result := range report.Results {
		if result.Outcome != "transport_error" || result.Status != nil {
			t.Errorf("unexpected timeout result: %+v", result)
		}
	}
}
