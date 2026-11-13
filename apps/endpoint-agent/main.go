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

	"github.com/i-got-this-faa/device-audit/networking/mesh"
	"github.com/i-got-this-faa/device-audit/packages/contracts"
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
	flag.Parse()
	modes := 0
	for _, selected := range []bool{*enrollMode, *identityStatus, *signEvidence} {
		if selected {
			modes++
		}
	}
	if modes > 0 && (*stateDir == "" || modes != 1) {
		fail(fmt.Errorf("choose one of enrollment, identity status or evidence signing and supply --state-dir"))
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
	if *transport != "loopback" {
		fail(mesh.ErrNotImplemented)
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
