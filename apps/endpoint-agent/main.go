package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

func main() {
	controllerURL := flag.String("controller", "http://127.0.0.1:8080", "loopback development controller")
	deviceID := flag.String("device-id", "demo-device", "device ID; collection modes require it explicitly, --fixture defaults to demo-device")
	transport := flag.String("transport", "loopback", "loopback or mesh")
	enrollMode := flag.Bool("enroll", false, "enroll using bootstrap-token.v1 JSON on stdin")
	identityStatus := flag.Bool("identity-status", false, "verify stored admission and print public receipt")
	stateDir := flag.String("state-dir", "", "private identity directory, required for enrollment/status")
	enrollmentOrigin := flag.String("enrollment-origin", "", "trusted HTTPS controller origin")
	caFile := flag.String("ca-file", "", "optional enrollment CA PEM file")
	signEvidence := flag.Bool("sign-evidence", false, "sign a telemetry v2 payload from stdin with the admitted identity")
	meshServerKey := flag.String("mesh-server-key", "", "trusted controller X25519 public key hex")
	controllerAckKeyFile := flag.String("controller-ack-key-file", "", "pinned controller Ed25519 acknowledgement public key PEM")
	regionFile := flag.String("derp-region-file", "", "explicit self-hosted DERP region JSON")
	collectTelemetry := flag.Bool("collect-telemetry", false, "print one endpoint telemetry v2 payload for an explicit --device-id")
	collectErrors := flag.Bool("collect-errors", false, "print new System/Application error records and save read positions in --state-dir")
	sample := flag.Bool("sample", false, "run the configured sampling schedule and print one telemetry v2 payload per snapshot")
	samplingConfig := flag.String("sampling-config", "", "sampling configuration JSON; the built-in default when empty")
	samplingDuration := flag.Duration("sampling-duration", 5*time.Minute, "how long --sample runs, from 1s to 24h")
	samplingReport := flag.String("sampling-report", "", "new file for the sampling budget report")
	fixture := flag.Bool("fixture", false, "send synthetic fixture telemetry to a loopback development controller")
	runProbe := flag.Bool("run-probe", false, "run one allowlisted read-only diagnostic probe from a JSON request on stdin")
	service := flag.Bool("service", false, "run the signed sampling pipeline as the installed Windows service")
	serviceConfigPath := flag.String("service-config", "", "service configuration JSON, required with --service")
	flag.Parse()
	if *runProbe {
		if flag.NFlag() != 1 {
			fail(fmt.Errorf("--run-probe runs alone"))
		}
		os.Exit(runProbeRequest(context.Background(), workflows.NewCatalog(), os.Stdin, os.Stdout, os.Stderr))
	}
	if *service || *serviceConfigPath != "" {
		if !*service || *serviceConfigPath == "" || flag.NFlag() != 2 {
			fail(fmt.Errorf("--service runs alone and requires --service-config"))
		}
		if err := runService(*serviceConfigPath); err != nil {
			fail(err)
		}
		return
	}
	modes := 0
	for _, selected := range []bool{*enrollMode, *identityStatus, *signEvidence, *collectErrors} {
		if selected {
			modes++
		}
	}
	deviceSet := false
	flag.Visit(func(f *flag.Flag) { deviceSet = deviceSet || f.Name == "device-id" })
	if *sample {
		if modes > 0 || *collectTelemetry || *fixture || !deviceSet {
			fail(fmt.Errorf("--sample runs alone and requires an explicit --device-id"))
		}
		cfg, err := loadSamplingConfig(*samplingConfig)
		if err != nil {
			fail(fmt.Errorf("invalid sampling config: %s", err))
		}
		report, err := runSampling(context.Background(), telemetry.NewScheduler(cfg), *deviceID, *samplingDuration, os.Stdout, os.Stderr)
		if err != nil {
			fail(fmt.Errorf("endpoint sampling failed: %s", err))
		}
		if *samplingReport != "" {
			if err := writeSamplingReport(*samplingReport, report); err != nil {
				fail(err)
			}
		}
		fmt.Fprintln(os.Stderr, budgetSummary(report))
		if !report.Budget.Within() {
			fail(errBudgetExceeded)
		}
		return
	}
	if *collectTelemetry {
		if modes > 0 || *fixture || !deviceSet {
			fail(fmt.Errorf("--collect-telemetry runs alone and requires an explicit --device-id"))
		}
		payload, err := collectEndpointTelemetry(context.Background(), *deviceID)
		if err != nil {
			fail(fmt.Errorf("endpoint telemetry collection failed: %s", err))
		}
		if err := json.NewEncoder(os.Stdout).Encode(payload); err != nil {
			fail(fmt.Errorf("write endpoint telemetry"))
		}
		return
	}
	if modes > 0 && (*stateDir == "" || modes != 1) {
		fail(fmt.Errorf("choose one of enrollment, identity status, evidence signing or error collection and supply --state-dir"))
	}
	if *collectErrors {
		store, err := openIdentityStore(*stateDir, false)
		if err != nil {
			fail(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		err = store.collectErrorEvidence(ctx, telemetry.NewErrorCollector(), os.Stdout)
		cancel()
		store.close()
		if err != nil {
			fail(fmt.Errorf("endpoint error collection failed: %s", err))
		}
		return
	}
	if *signEvidence {
		payload, err := readEvidencePayload(os.Stdin)
		if err != nil {
			fail(err)
		}
		store, err := openIdentityStore(*stateDir, false)
		if err != nil {
			fail(err)
		}
		envelope, err := store.signEvidence(payload, time.Now())
		store.close()
		if err != nil {
			fail(fmt.Errorf("endpoint evidence signing failed: %s", err))
		}
		if err := json.NewEncoder(os.Stdout).Encode(envelope); err != nil {
			fail(fmt.Errorf("write signed evidence"))
		}
		return
	}
	if *enrollMode || *identityStatus {
		var client *http.Client
		var origin string
		var token contracts.BootstrapTokenV1
		var err error
		if *enrollMode {
			client, origin, err = enrollmentClient(*enrollmentOrigin, *caFile)
			if err != nil {
				fail(err)
			}
			defer client.CloseIdleConnections()
			token, err = readBootstrap(os.Stdin)
			if err != nil {
				fail(err)
			}
		}
		store, err := openIdentityStore(*stateDir, *enrollMode)
		if err != nil {
			fail(err)
		}
		var receipt contracts.EnrollmentAcceptedV1
		if *enrollMode {
			receipt, err = enroll(context.Background(), store, client, origin, token)
		} else {
			receipt, err = store.status()
		}
		store.close()
		if err != nil {
			fail(fmt.Errorf("endpoint identity operation failed: %s", err))
		}
		if err := json.NewEncoder(os.Stdout).Encode(receipt); err != nil {
			fail(fmt.Errorf("write public identity status"))
		}
		return
	}
	if *transport == "mesh" {
		controllerKey, err := loadControllerAckKey(*controllerAckKeyFile)
		if err != nil {
			fail(err)
		}
		ack, err := sendMeshEvidence(context.Background(), *stateDir, *meshServerKey, controllerKey, *regionFile, os.Stdin)
		if err != nil {
			fail(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(ack); err != nil {
			fail(fmt.Errorf("write evidence acknowledgement"))
		}
		return
	}
	if *transport != "loopback" {
		fail(fmt.Errorf("transport must be loopback or mesh"))
	}
	// Synthetic telemetry is never the default: it needs an explicit switch
	// and announces its provenance, so it cannot pass for a device reading.
	if !*fixture || modes > 0 || *collectTelemetry {
		fail(fmt.Errorf("choose a mode such as --sample or --collect-telemetry; synthetic loopback telemetry requires --fixture alone"))
	}
	fmt.Fprintln(os.Stderr, "provenance=fixture: sending synthetic telemetry, not a device measurement")
	u, err := url.Parse(*controllerURL)
	if err != nil {
		fail(err)
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme != "http" || ip == nil || !ip.IsLoopback() || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		fail(fmt.Errorf("fixture mode requires http://<literal-loopback-IP>:<port>"))
	}
	cpu, memory := 12.5, 40.0
	t := contracts.Telemetry{SchemaVersion: contracts.Version, DeviceID: *deviceID, CollectedAt: time.Now().UTC(), Source: "fixture", Metrics: contracts.Metrics{CPUPercent: &cpu, MemoryPercent: &memory}}
	if err := t.Validate(); err != nil {
		fail(err)
	}
	payload, err := json.Marshal(t)
	if err != nil {
		fail(err)
	}
	u.Path = "/v1/telemetry"
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Post(u.String(), "application/json", bytes.NewReader(payload))
	if err != nil {
		fail(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128<<10))
	if err != nil {
		fail(err)
	}
	if response.StatusCode != http.StatusAccepted {
		fail(fmt.Errorf("controller returned %s: %s", response.Status, body))
	}
	fmt.Print(string(body))
}

func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
