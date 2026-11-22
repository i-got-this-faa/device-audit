package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/health"
)

// runFeatures reads one telemetry v2 payload per line, as --sample prints them,
// and writes the frozen feature vector for what they held at asOf. It reads no
// collector and signs nothing. Telemetry v2 has no SMART counter, so today the
// vector is always incomplete; the vector says so rather than an error.
func runFeatures(asOf string, in io.Reader, out io.Writer) error {
	at, err := time.Parse(time.RFC3339, asOf)
	if err != nil {
		return fmt.Errorf("--as-of must be an RFC 3339 time: %w", err)
	}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(nil, contracts.MaxEvidencePayloadBytes)
	var readings []health.SMARTReading
	for line := 1; scanner.Scan(); line++ {
		var telemetry contracts.TelemetryV2
		if err := json.Unmarshal(scanner.Bytes(), &telemetry); err != nil {
			return fmt.Errorf("telemetry line %d: %w", line, err)
		}
		if err := telemetry.Validate(); err != nil {
			return fmt.Errorf("telemetry line %d: %w", line, err)
		}
		readings = append(readings, health.ReadingFromTelemetry(telemetry))
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read telemetry: %w", err)
	}
	vector, err := health.Preprocess(at, readings)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(vector)
}
