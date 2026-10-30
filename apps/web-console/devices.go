package webconsole

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
)

//go:embed fixtures/devices.json
var deviceFixtureJSON []byte

type fixtureDevice struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	State     string                 `json:"state"`
	Telemetry *contracts.TelemetryV2 `json:"telemetry"`
}

type fixtureScenario struct {
	Name      string   `json:"name"`
	Label     string   `json:"label"`
	State     string   `json:"state"`
	DeviceIDs []string `json:"device_ids"`
}

type deviceCatalogue struct {
	Fixture   bool              `json:"fixture"`
	FixedTime time.Time         `json:"fixed_time"`
	Devices   []fixtureDevice   `json:"devices"`
	Scenarios []fixtureScenario `json:"scenarios"`
}

var deviceFixtures = loadDeviceFixtures()

func loadDeviceFixtures() deviceCatalogue {
	var catalogue deviceCatalogue
	if err := json.Unmarshal(deviceFixtureJSON, &catalogue); err != nil {
		panic(err)
	}
	if !catalogue.Fixture || catalogue.FixedTime.IsZero() {
		panic("device fixture marker and clock required")
	}
	for _, device := range catalogue.Devices {
		if device.Telemetry != nil {
			if err := device.Telemetry.Validate(); err != nil {
				panic(err)
			}
			if device.Telemetry.Source != "fixture" || device.Telemetry.DeviceID != device.ID {
				panic("device fixture provenance mismatch")
			}
		}
	}
	return catalogue
}

type ScenarioLink struct {
	Label, URL string
	Selected   bool
}

type Sensor struct {
	Name, Value, Unit, Explanation string
}

type DeviceRow struct {
	ID, Name, State, Status, URL, CollectedAt string
	Inventory                                 *contracts.InventoryV2
	Sensors                                   []Sensor
}

type DeviceView struct {
	State, FixedTime, ListURL string
	Scenarios                 []ScenarioLink
	Rows                      []DeviceRow
	Detail                    *DeviceRow
	IsDetail                  bool
}

// IsDeviceDetailPath extends the login return allowlist only to known fixture IDs.
func IsDeviceDetailPath(path string) bool {
	for _, device := range deviceFixtures.Devices {
		if path == "/console/devices/"+device.ID {
			return true
		}
	}
	return false
}

// FixtureDevices builds a presentation from local named fixtures, never a store fallback.
func FixtureDevices(query url.Values, deviceID string) (*DeviceView, int) {
	name := query.Get("fixture")
	if name == "" {
		name = "live"
	}
	view := &DeviceView{State: "not-found", FixedTime: deviceFixtures.FixedTime.Format(time.RFC3339), IsDetail: deviceID != ""}
	path := "/console/devices"
	if deviceID != "" {
		path += "/" + url.PathEscape(deviceID)
	}
	view.ListURL = "/console/devices?fixture=" + url.QueryEscape(name)
	var selected *fixtureScenario
	for _, scenario := range deviceFixtures.Scenarios {
		scenarioPath := path
		if view.IsDetail && scenario.State == "ready" && len(scenario.DeviceIDs) > 0 {
			scenarioID := scenario.DeviceIDs[0]
			for _, id := range scenario.DeviceIDs {
				if id == deviceID {
					scenarioID = id
				}
			}
			scenarioPath = "/console/devices/" + scenarioID
		}
		view.Scenarios = append(view.Scenarios, ScenarioLink{scenario.Label, scenarioPath + "?fixture=" + scenario.Name, scenario.Name == name})
		if scenario.Name == name {
			selected = &scenario
		}
	}
	if selected == nil || len(query["fixture"]) > 1 {
		return view, http.StatusNotFound
	}
	if deviceID != "" && !IsDeviceDetailPath(path) {
		return view, http.StatusNotFound
	}
	view.State = selected.State
	if selected.State == "error" {
		return view, http.StatusServiceUnavailable
	}
	if selected.State != "ready" {
		return view, http.StatusOK
	}
	for _, id := range selected.DeviceIDs {
		if view.IsDetail && id != deviceID {
			continue
		}
		for _, device := range deviceFixtures.Devices {
			if device.ID != id {
				continue
			}
			row := deviceRow(device, name)
			view.Rows = append(view.Rows, row)
			if device.ID == deviceID {
				view.Detail = &row
			}
		}
	}
	if view.IsDetail && view.Detail == nil {
		view.State = "not-found"
		return view, http.StatusNotFound
	}
	return view, http.StatusOK
}

func deviceRow(device fixtureDevice, scenario string) DeviceRow {
	row := DeviceRow{ID: device.ID, Name: device.Name, State: device.State,
		Status: strings.ToUpper(device.State[:1]) + device.State[1:] + " sample",
		URL:    "/console/devices/" + device.ID + "?fixture=" + scenario, CollectedAt: "Unknown: no sample received"}
	var metrics contracts.MetricsV2
	if device.Telemetry != nil {
		row.CollectedAt = device.Telemetry.CollectedAt.Format(time.RFC3339)
		row.Inventory = &device.Telemetry.Inventory
		metrics = device.Telemetry.Metrics
	}
	for _, item := range []struct {
		name, unit string
		metric     *contracts.MetricV2
	}{
		{"CPU utilization", "percent", metrics.CPUUtilization}, {"GPU utilization", "percent", metrics.GPUUtilization},
		{"Memory utilization", "percent", metrics.MemoryPercent}, {"Disk space used", "percent", metrics.DiskUsedPercent},
		{"Battery charge", "percent", metrics.BatteryPercent}, {"Temperature", "celsius", metrics.TemperatureC},
		{"Network latency", "milliseconds", metrics.NetworkLatencyMS},
	} {
		sensor := Sensor{Name: item.name, Value: "Unknown", Unit: item.unit, Explanation: "Not reported in this sample."}
		if item.metric != nil {
			if item.metric.Value != nil {
				sensor.Value = strconv.FormatFloat(*item.metric.Value, 'f', -1, 64)
				sensor.Explanation = "Fixture measurement."
			} else {
				switch item.metric.MissingReason {
				case "sensor_unavailable":
					sensor.Explanation = "Sensor unavailable on this fixture device."
				case "not_applicable":
					sensor.Explanation = "Sensor does not apply to this fixture device."
				case "permission_denied":
					sensor.Explanation = "Collection permission denied."
				case "collection_error":
					sensor.Explanation = "Collection failed; no measurement is available."
				default:
					panic(fmt.Sprintf("unsupported fixture missing reason %q", item.metric.MissingReason))
				}
			}
		}
		row.Sensors = append(row.Sensors, sensor)
	}
	return row
}
