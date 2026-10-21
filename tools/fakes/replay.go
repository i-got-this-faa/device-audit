// Package fakes implements fixture-only endpoint replay and response checking.
package fakes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	replayfixtures "github.com/i-got-this-faa/device-audit/packages/contracts/fixtures/replay"
)

const (
	defaultTimeout        = 5 * time.Second
	maxTimeout            = time.Minute
	maxRequestBytes       = 256 << 10
	maxResponseBytes      = 64 << 10
	fixtureHeader         = "X-Device-Audit-Fixture"
	fixtureIDHeader       = "X-Device-Audit-Fixture-ID"
	fixtureScenarioHeader = "X-Device-Audit-Replay-Scenario"
)

// Family identifies one supported replay contract.
type Family string

// Profile selects expected HTTP responses without asserting admission semantics.
type Profile string

// Scenario selects the request variant to replay.
type Scenario string

const (
	// TelemetryFamily sends signed evidence envelopes.
	TelemetryFamily Family = "telemetry"
	// DiagnosticsFamily sends signed terminal diagnostic results.
	DiagnosticsFamily Family = "diagnostics"
	// FederatedFamily sends signed federated updates.
	FederatedFamily Family = "federated"

	// ScaffoldProfile asserts only the observed legacy/unsupported route boundary.
	ScaffoldProfile Profile = "scaffold"
	// ContractFakeProfile expects the response mapping used by contract-aware fakes.
	ContractFakeProfile Profile = "contract-fake"

	// ValidScenario sends each canonical signed fixture unchanged.
	ValidScenario Scenario = "valid"
	// MalformedScenario replaces each fixture signature with a deterministic invalid signature.
	MalformedScenario Scenario = "malformed"
	// InterruptedScenario cancels before sending, then resubmits the same bytes.
	InterruptedScenario Scenario = "interrupted"
	// AllScenarios runs valid, malformed, then interrupted.
	AllScenarios Scenario = "all"
)

// Expectation overrides the expected status for one family and scenario.
type Expectation struct {
	Family   Family
	Scenario Scenario
}

// Options configures the replay origin, routes, timeout, profile, and status expectations.
type Options struct {
	Controller   string
	Profile      Profile
	Scenario     Scenario
	Routes       map[Family]string
	Timeout      time.Duration
	Expectations map[Expectation]int
}

// Report contains fixture-only replay rows and never claims controller admission.
type Report struct {
	Fixture  bool     `json:"fixture"`
	Profile  Profile  `json:"profile"`
	DeviceID string   `json:"device_id"`
	Results  []Result `json:"results"`
}

// Result is one attempted or deliberately cancelled fixture transmission.
type Result struct {
	FixtureID      string   `json:"fixture_id"`
	Family         Family   `json:"family"`
	Scenario       Scenario `json:"scenario"`
	Route          string   `json:"route"`
	Attempt        int      `json:"attempt"`
	Sequence       uint64   `json:"sequence"`
	Sent           bool     `json:"sent"`
	Outcome        string   `json:"outcome"`
	Status         *int     `json:"status"`
	ExpectedStatus int      `json:"expected_status"`
}

type familyRequest struct {
	family  Family
	fixture replayfixtures.Request
}

type replayFailure struct{}

func (replayFailure) Error() string { return "one or more replay attempts failed" }

// DefaultRoutes keeps the known telemetry route separate from probe-only paths.
func DefaultRoutes() map[Family]string {
	return map[Family]string{
		TelemetryFamily:   "/v1/telemetry",
		DiagnosticsFamily: "/fixture/diagnostics/results",
		FederatedFamily:   "/fixture/federated/updates",
	}
}

// Run sends fixture-tagged requests and asserts the configured HTTP status codes.
func Run(ctx context.Context, options Options) (Report, error) {
	if ctx == nil {
		return Report{}, errors.New("context is required")
	}
	if options.Profile != ScaffoldProfile && options.Profile != ContractFakeProfile {
		return Report{}, errors.New("profile must be scaffold or contract-fake")
	}
	if options.Timeout == 0 {
		options.Timeout = defaultTimeout
	}
	if options.Timeout < time.Millisecond || options.Timeout > maxTimeout {
		return Report{}, errors.New("timeout must be between 1ms and 1m")
	}
	scenarios, err := selectedScenarios(options.Scenario)
	if err != nil {
		return Report{}, err
	}
	origin, err := parseOrigin(options.Controller)
	if err != nil {
		return Report{}, err
	}
	routes := DefaultRoutes()
	for family, route := range options.Routes {
		if _, ok := routes[family]; !ok {
			return Report{}, fmt.Errorf("unknown family route %q", family)
		}
		if err := validateRoute(route); err != nil {
			return Report{}, fmt.Errorf("invalid %s route", family)
		}
		routes[family] = route
	}
	for family, route := range routes {
		if err := validateRoute(route); err != nil {
			return Report{}, fmt.Errorf("invalid %s route", family)
		}
	}
	for key, status := range options.Expectations {
		if !knownFamily(key.Family) || !knownScenario(key.Scenario) || status < 100 || status > 599 {
			return Report{}, errors.New("invalid expected-status override")
		}
	}
	bundle, err := replayfixtures.Load()
	if err != nil {
		return Report{}, errors.New("could not load replay fixtures")
	}
	requests, err := validateFixtures(bundle)
	if err != nil {
		return Report{}, errors.New("replay fixture validation failed")
	}
	report := Report{Fixture: true, Profile: options.Profile, DeviceID: bundle.DeviceID, Results: make([]Result, 0, 12)}
	client := &http.Client{
		Timeout: options.Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	failures := 0
	validAlreadySent := false
	for _, scenario := range scenarios {
		for _, request := range requests {
			route := routes[request.family]
			expected := expectedStatus(options, request.family, scenario, validAlreadySent)
			body := request.fixture.Body
			if scenario == MalformedScenario {
				body, err = invalidSignature(body)
				if err != nil {
					return report, errors.New("could not construct malformed fixture request")
				}
			}
			if len(body) == 0 || len(body) > maxRequestBytes {
				return report, errors.New("fixture request exceeds its bound")
			}
			if scenario == InterruptedScenario {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				cancelStatus, cancelErr := post(cancelledCtx, client, origin, route, request.fixture, scenario, body)
				cancelResult := Result{
					FixtureID: request.fixture.FixtureID, Family: request.family, Scenario: scenario,
					Route: route, Attempt: 1, Sequence: request.fixture.Sequence,
					Sent: false, ExpectedStatus: expected,
				}
				if cancelStatus == 0 && errors.Is(cancelErr, context.Canceled) {
					cancelResult.Outcome = "cancelled_before_submission"
				} else {
					cancelResult.Outcome = "interruption_not_cancelled"
					if cancelStatus != 0 {
						cancelResult.Status = new(cancelStatus)
					}
					failures++
				}
				report.Results = append(report.Results, cancelResult)
			}
			status, postErr := post(ctx, client, origin, route, request.fixture, scenario, body)
			result := Result{
				FixtureID: request.fixture.FixtureID, Family: request.family, Scenario: scenario,
				Route: route, Attempt: 1, Sequence: request.fixture.Sequence,
				Sent: true, ExpectedStatus: expected,
			}
			if scenario == InterruptedScenario {
				result.Attempt = 2
			}
			if postErr != nil {
				result.Outcome = "transport_error"
				if status != 0 {
					result.Status = new(status)
				}
				failures++
			} else {
				result.Status = new(status)
				if status != expected {
					result.Outcome = "status_mismatch"
					failures++
				} else if isScaffoldUnsupported(options.Profile, request.family, status) {
					result.Outcome = "expected_unsupported"
				} else {
					result.Outcome = "expected_response"
				}
			}
			report.Results = append(report.Results, result)
		}
		if scenario == ValidScenario {
			validAlreadySent = true
		}
	}
	if failures != 0 {
		return report, replayFailure{}
	}
	return report, nil
}

func selectedScenarios(scenario Scenario) ([]Scenario, error) {
	if scenario == AllScenarios {
		return []Scenario{ValidScenario, MalformedScenario, InterruptedScenario}, nil
	}
	if knownScenario(scenario) {
		return []Scenario{scenario}, nil
	}
	return nil, errors.New("scenario must be all, valid, malformed, or interrupted")
}

func knownScenario(scenario Scenario) bool {
	return scenario == ValidScenario || scenario == MalformedScenario || scenario == InterruptedScenario
}

func knownFamily(family Family) bool {
	return family == TelemetryFamily || family == DiagnosticsFamily || family == FederatedFamily
}

func expectedStatus(options Options, family Family, scenario Scenario, priorValid bool) int {
	if status, ok := options.Expectations[Expectation{Family: family, Scenario: scenario}]; ok {
		return status
	}
	if options.Profile == ScaffoldProfile {
		if family == TelemetryFamily {
			return http.StatusBadRequest
		}
		return http.StatusNotFound
	}
	if scenario == MalformedScenario {
		return http.StatusBadRequest
	}
	if scenario == InterruptedScenario && priorValid && family == TelemetryFamily {
		return http.StatusConflict
	}
	return http.StatusAccepted
}

func isScaffoldUnsupported(profile Profile, family Family, status int) bool {
	if profile != ScaffoldProfile {
		return false
	}
	return family == TelemetryFamily && status == http.StatusBadRequest ||
		(family == DiagnosticsFamily || family == FederatedFamily) && status == http.StatusNotFound
}

func parseOrigin(value string) (*url.URL, error) {
	origin, err := url.Parse(value)
	if err != nil || (origin.Scheme != "http" && origin.Scheme != "https") || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" {
		return nil, errors.New("controller must be an HTTP(S) origin without credentials, query, or fragment")
	}
	if origin.Path != "" && origin.Path != "/" && path.Clean(origin.Path) != origin.Path {
		return nil, errors.New("controller path prefix must be clean")
	}
	return origin, nil
}

func validateRoute(route string) error {
	if !strings.HasPrefix(route, "/") || route == "" {
		return errors.New("route must be an absolute path")
	}
	parsed, err := url.Parse(route)
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" || path.Clean(parsed.Path) != parsed.Path {
		return errors.New("route must be a clean path without query or fragment")
	}
	return nil
}

func requestURL(origin *url.URL, route string) string {
	target := *origin
	prefix := strings.TrimRight(target.Path, "/")
	target.Path = prefix + "/" + strings.TrimLeft(route, "/")
	target.RawPath = ""
	return target.String()
}

func post(ctx context.Context, client *http.Client, origin *url.URL, route string, fixture replayfixtures.Request, scenario Scenario, body []byte) (int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL(origin, route), bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(fixtureHeader, "true")
	request.Header.Set(fixtureIDHeader, fixture.FixtureID)
	request.Header.Set(fixtureScenarioHeader, string(scenario))
	request.Header.Set("User-Agent", "device-audit-fixture-replay/1")
	response, err := client.Do(request)
	if err != nil {
		return 0, err
	}
	defer response.Body.Close()
	if response.ContentLength > maxResponseBytes {
		return response.StatusCode, errors.New("response exceeds size bound")
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return response.StatusCode, err
	}
	if len(responseBody) > maxResponseBytes {
		return response.StatusCode, errors.New("response exceeds size bound")
	}
	return response.StatusCode, nil
}

func invalidSignature(body []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	if _, ok := fields["signature"]; !ok {
		return nil, errors.New("signed fixture has no signature field")
	}
	badSignature, err := json.Marshal(strings.Repeat("0", ed25519.SignatureSize*2))
	if err != nil {
		return nil, err
	}
	fields["signature"] = badSignature
	return json.Marshal(fields)
}

func validateFixtures(bundle replayfixtures.Bundle) ([]familyRequest, error) {
	if !bundle.Fixture || bundle.DeviceID != "fixture-replay-device" || bundle.Telemetry.Sequence != 2 || bundle.Diagnostics.Result.Sequence != 3 || bundle.Federated.Update.Sequence != 4 {
		return nil, errors.New("fixture marker, ID, or sequence mismatch")
	}
	devicePublic, err := decodePublicKey(bundle.DevicePublicKey)
	if err != nil {
		return nil, err
	}
	var evidence contracts.EvidenceEnvelopeV1
	if err := json.Unmarshal(bundle.Telemetry.Body, &evidence); err != nil {
		return nil, err
	}
	if err := evidence.VerifySignature(devicePublic); err != nil {
		return nil, err
	}
	if evidence.DeviceID != bundle.DeviceID || evidence.Sequence != bundle.Telemetry.Sequence {
		return nil, errors.New("telemetry fixture identity mismatch")
	}
	controllerPublic, err := decodePublicKey(bundle.Diagnostics.ControllerPublicKey)
	if err != nil {
		return nil, err
	}
	var assignment contracts.DiagnosticAssignmentV1
	if err := json.Unmarshal(bundle.Diagnostics.Assignment.Body, &assignment); err != nil {
		return nil, err
	}
	if err := assignment.VerifySignature(controllerPublic); err != nil {
		return nil, err
	}
	var result contracts.DiagnosticResultV1
	if err := json.Unmarshal(bundle.Diagnostics.Result.Body, &result); err != nil {
		return nil, err
	}
	if err := result.VerifySignature(devicePublic); err != nil {
		return nil, err
	}
	if err := result.CheckAssignment(assignment); err != nil {
		return nil, err
	}
	if result.DeviceID != bundle.DeviceID || result.Sequence != bundle.Diagnostics.Result.Sequence {
		return nil, errors.New("diagnostic fixture identity mismatch")
	}
	var round contracts.FederatedRoundV1
	if err := json.Unmarshal(bundle.Federated.Round, &round); err != nil {
		return nil, err
	}
	if err := round.Validate(); err != nil {
		return nil, err
	}
	var update contracts.FederatedUpdateV1
	if err := json.Unmarshal(bundle.Federated.Update.Body, &update); err != nil {
		return nil, err
	}
	if err := update.VerifySignature(devicePublic); err != nil {
		return nil, err
	}
	fixedTime, err := time.Parse(time.RFC3339, bundle.FixedTime)
	if err != nil {
		return nil, err
	}
	if err := update.CheckRound(round, fixedTime); err != nil {
		return nil, err
	}
	if update.DeviceID != bundle.DeviceID || update.Sequence != bundle.Federated.Update.Sequence {
		return nil, errors.New("federated fixture identity mismatch")
	}
	return []familyRequest{
		{family: TelemetryFamily, fixture: bundle.Telemetry},
		{family: DiagnosticsFamily, fixture: bundle.Diagnostics.Result},
		{family: FederatedFamily, fixture: bundle.Federated.Update},
	}, nil
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	encoded, err := hex.DecodeString(value)
	if err != nil || len(encoded) != ed25519.PublicKeySize {
		return nil, errors.New("invalid fixture public key")
	}
	return ed25519.PublicKey(encoded), nil
}
