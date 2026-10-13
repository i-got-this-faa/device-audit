package main

import (
	"bytes"
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
	flag.Parse()
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
