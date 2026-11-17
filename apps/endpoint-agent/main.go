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
)

func main() {
	controllerURL := flag.String("controller", "http://127.0.0.1:8080", "loopback development controller")
	deviceID := flag.String("device-id", "demo-device", "fixture device ID")
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
	flag.Parse()
	modes := 0
	for _, selected := range []bool{*enrollMode, *identityStatus, *signEvidence, *collectErrors} {
		if selected {
			modes++
		}
	}
	if *collectTelemetry {
		deviceSet := false
		flag.Visit(func(f *flag.Flag) { deviceSet = deviceSet || f.Name == "device-id" })
		if modes > 0 || !deviceSet {
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
