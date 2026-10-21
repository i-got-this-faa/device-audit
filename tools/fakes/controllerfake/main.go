package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "loopback listener for serve mode")
	scenario := flag.String("scenario", "serve", "serve, assignment, expiry, offline, duplicate or all")
	fixtures := flag.String("fixtures", "packages/contracts/fixtures/envelopes/v1-vectors.json", "public envelope vector file")
	now := flag.String("now", "", "fixed RFC3339 fixture clock for serve mode (default: system clock)")
	flag.Parse()

	switch *scenario {
	case "serve":
		serve(*listen, *now)
	case "all":
		runSuite(*fixtures)
	case ScenarioAssignment, ScenarioExpiry, ScenarioOffline, ScenarioDuplicate:
		runOne(*fixtures, *scenario)
	default:
		fmt.Fprintf(os.Stderr, "unknown fixture scenario %q\n", *scenario)
		os.Exit(2)
	}
}

func serve(address, fixedClock string) {
	ip := net.ParseIP(address)
	if ip == nil || !ip.IsLoopback() {
		fixtureFail(fmt.Errorf("fixture listener must be a literal loopback address"))
	}
	server, err := New(Config{Now: clockFromFlag(fixedClock)})
	if err != nil {
		fixtureFail(err)
	}
	httpServer := &http.Server{
		Addr:              address,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	slog.Info("fixture controller ready", "address", address, "mode", "fixture", "admission", "fixture_keys_only", "storage", "memory")
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fixtureFail(err)
	}
}

func runSuite(fixturePath string) {
	report, err := RunScenarios(context.Background(), fixturePath)
	if err != nil {
		fixtureFail(err)
	}
	writeReport(report)
	if !report.Passed {
		os.Exit(1)
	}
}

func runOne(fixturePath, name string) {
	report, err := RunScenarios(context.Background(), fixturePath)
	if err != nil {
		fixtureFail(err)
	}
	for _, result := range report.Scenarios {
		if result.Name == name {
			writeReport(ScenarioReport{Fixture: true, Scenarios: []ScenarioResult{result}, Passed: result.Result == "pass"})
			if result.Result != "pass" {
				os.Exit(1)
			}
			return
		}
	}
	fixtureFail(fmt.Errorf("scenario %q not found", name))
}

func writeReport(report ScenarioReport) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fixtureFail(err)
	}
}

func clockFromFlag(value string) func() time.Time {
	if value == "" {
		return nil
	}
	fixed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		fixtureFail(fmt.Errorf("invalid --now: %w", err))
	}
	return func() time.Time { return fixed }
}

func fixtureFail(err error) {
	fmt.Fprintf(os.Stderr, "controller fixture: %v\n", err)
	os.Exit(1)
}
