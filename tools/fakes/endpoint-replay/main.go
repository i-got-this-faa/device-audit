package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/tools/fakes"
)

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

func main() {
	var (
		controller       = flag.String("controller", "http://127.0.0.1:8080", "HTTP(S) controller origin")
		profile          = flag.String("profile", "scaffold", "expected response profile: scaffold or contract-fake")
		scenario         = flag.String("scenario", "all", "scenario: all, valid, malformed, or interrupted")
		telemetryRoute   = flag.String("telemetry-route", "/v1/telemetry", "telemetry evidence POST path")
		diagnosticsRoute = flag.String("diagnostics-route", "/fixture/diagnostics/results", "diagnostic result POST path (probe-only by default)")
		federatedRoute   = flag.String("federated-route", "/fixture/federated/updates", "federated update POST path (probe-only by default)")
		timeout          = flag.Duration("timeout", 5*time.Second, "maximum HTTP request/response duration (1ms..1m)")
	)
	var overrides stringList
	flag.Var(&overrides, "expect", "expected status override: family.scenario=status (repeatable)")
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(errors.New("unexpected positional arguments"))
	}

	expectations, err := parseExpectations(overrides)
	if err != nil {
		fatal(err)
	}
	routes := map[fakes.Family]string{
		fakes.TelemetryFamily:   *telemetryRoute,
		fakes.DiagnosticsFamily: *diagnosticsRoute,
		fakes.FederatedFamily:   *federatedRoute,
	}
	report, runErr := fakes.Run(context.Background(), fakes.Options{
		Controller:   *controller,
		Profile:      fakes.Profile(*profile),
		Scenario:     fakes.Scenario(*scenario),
		Routes:       routes,
		Timeout:      *timeout,
		Expectations: expectations,
	})
	if report.Fixture {
		if err := printReport(report); err != nil {
			fatal(errors.New("could not write replay report"))
		}
	}
	if runErr != nil {
		fatal(runErr)
	}
}

func parseExpectations(values []string) (map[fakes.Expectation]int, error) {
	expectations := make(map[fakes.Expectation]int, len(values))
	for _, value := range values {
		keyAndStatus := strings.SplitN(value, "=", 2)
		if len(keyAndStatus) != 2 {
			return nil, errors.New("expected-status override must be family.scenario=status")
		}
		key := strings.SplitN(keyAndStatus[0], ".", 2)
		if len(key) != 2 {
			return nil, errors.New("expected-status override must include family and scenario")
		}
		family, scenario := fakes.Family(key[0]), fakes.Scenario(key[1])
		if !validFamily(family) || !validScenario(scenario) {
			return nil, errors.New("unknown family or scenario in expected-status override")
		}
		status, err := strconv.Atoi(keyAndStatus[1])
		if err != nil || status < 100 || status > 599 {
			return nil, errors.New("expected HTTP status must be between 100 and 599")
		}
		expectation := fakes.Expectation{Family: family, Scenario: scenario}
		if _, exists := expectations[expectation]; exists {
			return nil, errors.New("duplicate expected-status override")
		}
		expectations[expectation] = status
	}
	return expectations, nil
}

func validFamily(value fakes.Family) bool {
	return value == fakes.TelemetryFamily || value == fakes.DiagnosticsFamily || value == fakes.FederatedFamily
}

func validScenario(value fakes.Scenario) bool {
	return value == fakes.ValidScenario || value == fakes.MalformedScenario || value == fakes.InterruptedScenario
}

func printReport(report fakes.Report) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(report)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "endpoint replay:", err)
	os.Exit(1)
}
