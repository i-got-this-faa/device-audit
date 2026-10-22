// Package replay contains deterministic, public-key-only HTTP replay fixtures.
package replay

import (
	_ "embed"
	"encoding/json"
)

//go:embed v1.json
var encoded []byte

// Request stores a signed fixture body with out-of-band replay metadata.
type Request struct {
	FixtureID string          `json:"fixture_id"`
	Sequence  uint64          `json:"sequence"`
	Body      json.RawMessage `json:"body"`
}

// Diagnostics pairs a controller-signed assignment with its device-signed result.
type Diagnostics struct {
	Assignment          Request `json:"assignment"`
	Result              Request `json:"result"`
	ControllerPublicKey string  `json:"controller_public_key"`
}

// Federated contains unsigned round context and a signed device update.
type Federated struct {
	Round  json.RawMessage `json:"round"`
	Update Request         `json:"update"`
}

// Bundle contains the deterministic replay fixture set and public test keys.
type Bundle struct {
	Fixture         bool        `json:"fixture"`
	FixedTime       string      `json:"fixed_time"`
	DeviceID        string      `json:"device_id"`
	DevicePublicKey string      `json:"device_public_key"`
	Telemetry       Request     `json:"telemetry"`
	Diagnostics     Diagnostics `json:"diagnostics"`
	Federated       Federated   `json:"federated"`
}

// Load returns the embedded deterministic fixture bundle.
func Load() (Bundle, error) {
	var bundle Bundle
	err := json.Unmarshal(encoded, &bundle)
	return bundle, err
}
