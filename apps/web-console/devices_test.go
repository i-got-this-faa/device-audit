package webconsole

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	replayfixtures "github.com/i-got-this-faa/device-audit/packages/contracts/fixtures/replay"
)

func TestReplayDeviceUsesSharedPayload(t *testing.T) {
	bundle, err := replayfixtures.Load()
	if err != nil {
		t.Fatal(err)
	}
	var envelope contracts.EvidenceEnvelopeV1
	if err := json.Unmarshal(bundle.Telemetry.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	var telemetry contracts.TelemetryV2
	if err := json.Unmarshal(payload, &telemetry); err != nil {
		t.Fatal(err)
	}
	view, status := FixtureDevices(url.Values{"fixture": {"empty-inventory"}}, bundle.DeviceID)
	if status != 200 || view.Detail == nil || len(view.Detail.Inventory.Components) != 0 {
		t.Fatalf("replay detail unavailable: %+v", view)
	}
	var found bool
	for _, device := range deviceFixtures.Devices {
		if device.ID == bundle.DeviceID {
			found = true
			if !reflect.DeepEqual(device.Telemetry, &telemetry) {
				t.Fatal("console drifted from TST02 replay payload")
			}
		}
	}
	if !found {
		t.Fatal("missing replay device")
	}
}

func TestDeviceMeasurementsAndEscaping(t *testing.T) {
	view, _ := FixtureDevices(nil, "fixture-laptop")
	inventory := *view.Detail.Inventory
	inventory.Components = append([]contracts.ComponentV2(nil), inventory.Components...)
	inventory.Components[0].Model = `<img src=x onerror=alert(1)>`
	view.Detail.Inventory = &inventory
	w := httptest.NewRecorder()
	if err := Render(w, 200, Page{Title: "Device detail", Section: "devices", Subject: "viewer", Devices: view}); err != nil {
		t.Fatal(err)
	}
	body := w.Body.String()
	for _, want := range []string{`class="sensor-value">0</span>`, "Sensor unavailable", "Sensor does not apply", "Collection permission denied", "Collection failed", "Model unknown", "&lt;img"} {
		if !strings.Contains(body, want) {
			t.Errorf("missing rendered %q", want)
		}
	}
	if strings.Contains(body, `<img src=x`) {
		t.Fatal("unescaped component model")
	}
	unknown, _ := FixtureDevices(url.Values{"fixture": {"unknown"}}, "fixture-unknown")
	if unknown.Detail.Inventory != nil {
		t.Fatal("unknown inventory became empty inventory")
	}
	for _, sensor := range unknown.Detail.Sensors {
		if sensor.Value != "Unknown" || sensor.Explanation != "Not reported in this sample." {
			t.Fatal("unreported metric became a measurement")
		}
	}
}

func TestFixtureSelectionFailures(t *testing.T) {
	for _, test := range []struct {
		query url.Values
		id    string
		want  int
	}{
		{url.Values{"fixture": {"missing"}}, "", http.StatusNotFound},
		{url.Values{"fixture": {"live", "error"}}, "", http.StatusNotFound},
		{nil, "unregistered-device", http.StatusNotFound},
		{url.Values{"fixture": {"offline"}}, "fixture-laptop", http.StatusNotFound},
		{url.Values{"fixture": {"error"}}, "fixture-laptop", http.StatusServiceUnavailable},
		{url.Values{"fixture": {"loading"}}, "fixture-laptop", http.StatusOK},
	} {
		view, status := FixtureDevices(test.query, test.id)
		if status != test.want || view.Detail != nil || len(view.Rows) != 0 {
			t.Errorf("%s/%s: status=%d view=%+v", test.query, test.id, status, view)
		}
	}
}
