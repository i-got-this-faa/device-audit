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
	"os/signal"
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
	serviceConfigPath := flag.String("service-config", "", "service configuration JSON")
	checkServiceConfig := flag.Bool("check-service-config", false, "validate the service configuration and bundled model without starting")
	spoolNext := flag.Bool("spool-next", false, "write the oldest queued envelope without dequeuing it")
	spoolAck := flag.Bool("spool-ack", false, "retire the oldest queued envelope after verifying the accepted acknowledgement on stdin")
	spoolArchive := flag.Bool("spool-archive-expired", false, "preserve an expired head without acknowledging it")
	spoolMaintain := flag.Bool("spool-session", false, "emit heads and accept signed acknowledgements in one maintenance session")
	spoolDeliver := flag.Bool("spool-drain", false, "deliver the queued evidence over the configured mesh and retry transient failures")
	signedProbe := flag.Bool("run-assigned-probe", false, "run one signed diagnostic assignment from stdin for the admitted identity")
	diagnosticKey := flag.String("diagnostic-controller-key-file", "", "pinned controller Ed25519 diagnostic assignment public key PEM")
	features := flag.Bool("features", false, "read telemetry v2 payloads, one per line, from stdin and print the frozen feature vector as of --as-of")
	asOf := flag.String("as-of", "", "RFC 3339 time that ends the --features window")
	probeWorker := flag.Bool("probe-worker", false, "internal: read one isolated probe request")
	inferenceWorker := flag.Bool("inference-worker", false, "internal: read one isolated inference request")
	fitLocalCandidate := flag.Bool("fit-local-candidate", false, "fit one offline federated candidate from a local JSON request")
	trainFederatedUpdate := flag.Bool("train-federated-update", false, "fit and stage one budgeted signed update from a local round request")
	localTrainingWorker := flag.Bool("local-training-worker", false, "internal: fit one isolated local training candidate")
	trainingPublisherKey := flag.String("training-publisher-key-file", "", "pinned Ed25519 publisher key for local training")
	stageModel := flag.Bool("stage-approved-model", false, "download and verify the approved registry model over the admitted mesh")
	modelPublisherKey := flag.String("model-publisher-key-file", "", "pinned Ed25519 publisher key for model staging")
	flag.Parse()
	if *stageModel || *modelPublisherKey != "" {
		if !*stageModel || *stateDir == "" || *meshServerKey == "" || *regionFile == "" || *modelPublisherKey == "" || flag.NFlag() != 5 || flag.NArg() != 0 {
			fail(fmt.Errorf("--stage-approved-model requires --state-dir, --mesh-server-key, --derp-region-file and --model-publisher-key-file"))
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		metadata, err := stageApprovedModel(ctx, *stateDir, *meshServerKey, *regionFile, *modelPublisherKey)
		stop()
		if err != nil {
			fail(err)
		}
		fmt.Printf("staged %s %s in %s\n", metadata.Manifest.ModelVersion, metadata.Manifest.ArtifactSHA256, stagedModelFile)
		return
	}
	if *trainFederatedUpdate {
		if *stateDir == "" || *trainingPublisherKey == "" || flag.NFlag() != 3 || flag.NArg() != 0 {
			fail(fmt.Errorf("--train-federated-update requires --state-dir and --training-publisher-key-file"))
		}
		request, err := readLocalTrainingRequest(os.Stdin)
		if err != nil {
			fail(err)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		report, err := stageFederatedTraining(ctx, *stateDir, *trainingPublisherKey, request, trainingExecution{
			now: time.Now, power: checkTrainingPower, fit: runTrainingProcess,
		})
		stop()
		if err != nil {
			fail(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			fail(err)
		}
		return
	}
	if *fitLocalCandidate || *localTrainingWorker || *trainingPublisherKey != "" {
		if *fitLocalCandidate == *localTrainingWorker || *trainingPublisherKey == "" || flag.NFlag() != 2 || flag.NArg() != 0 {
			fail(fmt.Errorf("--fit-local-candidate runs alone and requires --training-publisher-key-file"))
		}
		if err := runLocalCandidate(context.Background(), *trainingPublisherKey, os.Stdin, os.Stdout, time.Now); err != nil {
			fail(err)
		}
		return
	}
	if *inferenceWorker {
		if flag.NFlag() != 1 || flag.NArg() != 0 {
			fail(fmt.Errorf("invalid inference worker arguments"))
		}
		os.Exit(runInferenceWorker(os.Stdin, os.Stdout, os.Stderr))
	}
	if *probeWorker {
		if flag.NFlag() != 1 || flag.NArg() != 0 {
			fail(fmt.Errorf("invalid probe worker arguments"))
		}
		os.Exit(runProbeWorker(os.Stdin, os.Stdout, os.Stderr))
	}
	if *signedProbe {
		if *stateDir == "" || *diagnosticKey == "" || flag.NFlag() != 3 || flag.NArg() != 0 {
			fail(fmt.Errorf("--run-assigned-probe requires --state-dir and --diagnostic-controller-key-file"))
		}
		os.Exit(runAssignedProbe(*stateDir, *diagnosticKey, os.Stdin, os.Stdout, os.Stderr))
	}
	var operation spoolOperation
	spoolModes := 0
	for _, mode := range []struct {
		active    bool
		operation spoolOperation
	}{
		{*spoolNext, spoolShowHead}, {*spoolAck, spoolAcceptHead}, {*spoolArchive, spoolArchiveHead}, {*spoolMaintain, spoolSession}, {*spoolDeliver, spoolDrain},
	} {
		if mode.active {
			operation = mode.operation
			spoolModes++
		}
	}
	if spoolModes > 0 {
		wantsKey := operation == spoolAcceptHead || operation == spoolSession
		expected := 2
		if wantsKey {
			expected++
		}
		if spoolModes != 1 || *serviceConfigPath == "" || wantsKey != (*controllerAckKeyFile != "") || flag.NFlag() != expected || flag.NArg() != 0 {
			fail(fmt.Errorf("choose one spool mode with --service-config; acknowledgement modes require --controller-ack-key-file"))
		}
		ctx := context.Background()
		if operation == spoolDrain {
			var stop context.CancelFunc
			ctx, stop = signal.NotifyContext(ctx, os.Interrupt)
			defer stop()
		}
		err := runSpoolCommand(ctx, *serviceConfigPath, *controllerAckKeyFile, operation, os.Stdin, os.Stdout, os.Stderr)
		if err != nil {
			fail(err)
		}
		return
	}
	if *features || *asOf != "" {
		if !*features || *asOf == "" || flag.NFlag() != 2 || flag.NArg() != 0 {
			fail(fmt.Errorf("--features runs alone and requires --as-of"))
		}
		if err := runFeatures(*asOf, os.Stdin, os.Stdout); err != nil {
			fail(err)
		}
		return
	}
	if *runProbe {
		if flag.NFlag() != 1 || flag.NArg() != 0 {
			fail(fmt.Errorf("--run-probe runs alone"))
		}
		req, err := workflows.ParseRequest(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "probe request rejected: %s\n", err)
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		data, err := workflows.NewProbeRunner(executeProbeWorker).Run(ctx, req)
		code := writeProbeOutcome(data, err, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if *checkServiceConfig {
		if *serviceConfigPath == "" || flag.NFlag() != 2 || flag.NArg() != 0 {
			fail(fmt.Errorf("--check-service-config runs alone and requires --service-config"))
		}
		if err := preflightServiceConfig(*serviceConfigPath); err != nil {
			fail(err)
		}
		return
	}
	if *service || *serviceConfigPath != "" {
		if !*service || *serviceConfigPath == "" || flag.NFlag() != 2 || flag.NArg() != 0 {
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
		controllerKey, err := loadControllerPublicKey(*controllerAckKeyFile)
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
