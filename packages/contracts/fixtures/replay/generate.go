//go:build ignore

// Regenerate from the repository root with: go run packages/contracts/fixtures/replay/generate.go.
// The RFC 8032 seeds below are public test material, never operational keys.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"time"

	c "github.com/i-got-this-faa/device-audit/packages/contracts"
	replay "github.com/i-got-this-faa/device-audit/packages/contracts/fixtures/replay"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	must(err)
	return encoded
}

func signEvidence(e c.EvidenceEnvelopeV1, key ed25519.PrivateKey) c.EvidenceEnvelopeV1 {
	message, err := e.SigningBytes()
	must(err)
	e.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	must(e.VerifySignature(key.Public().(ed25519.PublicKey)))
	return e
}

func signAssignment(a c.DiagnosticAssignmentV1, key ed25519.PrivateKey) c.DiagnosticAssignmentV1 {
	message, err := a.SigningBytes()
	must(err)
	a.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	must(a.VerifySignature(key.Public().(ed25519.PublicKey)))
	return a
}

func signResult(r c.DiagnosticResultV1, key ed25519.PrivateKey) c.DiagnosticResultV1 {
	message, err := r.SigningBytes()
	must(err)
	r.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	must(r.VerifySignature(key.Public().(ed25519.PublicKey)))
	return r
}

func signUpdate(u c.FederatedUpdateV1, key ed25519.PrivateKey) c.FederatedUpdateV1 {
	message, err := u.SigningBytes()
	must(err)
	u.Signature = hex.EncodeToString(ed25519.Sign(key, message))
	must(u.VerifySignature(key.Public().(ed25519.PublicKey)))
	return u
}

func keyID(key ed25519.PrivateKey) string {
	id, err := c.SigningKeyIDV1(key.Public().(ed25519.PublicKey))
	must(err)
	return id
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func main() {
	deviceSeed, err := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	must(err)
	controllerSeed, err := hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	must(err)
	peerSeed, err := hex.DecodeString("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7")
	must(err)
	peerKey := ed25519.NewKeyFromSeed(peerSeed)
	deviceKey := ed25519.NewKeyFromSeed(deviceSeed)
	controllerKey := ed25519.NewKeyFromSeed(controllerSeed)
	deviceKeyID, controllerKeyID := keyID(deviceKey), keyID(controllerKey)
	peerKeyID := keyID(peerKey)
	fixedTime := time.Date(2026, 10, 19, 12, 30, 0, 0, time.UTC)
	const deviceID = "fixture-replay-device"
	const deploymentID = "fixture-replay-deployment"

	metricValue := 12.5
	telemetry := c.TelemetryV2{
		SchemaVersion: c.TelemetryV2Version,
		DeviceID:      deviceID,
		CollectedAt:   time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		Source:        "fixture",
		Metrics:       c.MetricsV2{CPUUtilization: &c.MetricV2{Value: &metricValue, Unit: "percent"}},
		Inventory:     c.InventoryV2{Components: []c.ComponentV2{}},
		LogReferences: []c.LogReferenceV2{},
	}
	must(telemetry.Validate())
	payload := mustJSON(telemetry)
	evidence := signEvidence(c.EvidenceEnvelopeV1{
		EnvelopeHeaderV1: c.EnvelopeHeaderV1{
			SchemaVersion: c.EvidenceEnvelopeV1Version,
			DeploymentID:  deploymentID,
			DeviceID:      deviceID,
			SigningKeyID:  deviceKeyID,
			Sequence:      2,
			IssuedAt:      "2026-10-19T12:00:00Z",
			ExpiresAt:     "2026-10-19T13:00:00Z",
		},
		PayloadSchemaVersion: c.TelemetryV2Version,
		PayloadBase64:        base64.StdEncoding.EncodeToString(payload),
		PayloadSHA256:        sha256Hex(payload),
	}, deviceKey)

	assignment := signAssignment(c.DiagnosticAssignmentV1{
		EnvelopeHeaderV1: c.EnvelopeHeaderV1{
			SchemaVersion: c.DiagnosticAssignmentV1Version,
			DeploymentID:  deploymentID,
			DeviceID:      deviceID,
			SigningKeyID:  controllerKeyID,
			Sequence:      1,
			IssuedAt:      "2026-10-19T12:00:00Z",
			ExpiresAt:     "2026-10-19T12:05:00Z",
		},
		AssignmentID: "fixture-replay-assignment",
		ProbeID:      "storage_health.v1",
		Arguments:    c.DiagnosticArgumentsV1{ComponentID: new("fixture-replay-storage")},
		Budget:       c.DiagnosticBudgetV1{WallSeconds: 60, MaxOutputBytes: 4096},
	}, controllerKey)
	assignmentBytes, err := assignment.SigningBytes()
	must(err)
	assignmentDigest, err := c.EnvelopeRequestSHA256V1(assignmentBytes, assignment.Signature)
	must(err)
	result := signResult(c.DiagnosticResultV1{
		EnvelopeHeaderV1: c.EnvelopeHeaderV1{
			SchemaVersion: c.DiagnosticResultV1Version,
			DeploymentID:  deploymentID,
			DeviceID:      deviceID,
			SigningKeyID:  deviceKeyID,
			Sequence:      3,
			IssuedAt:      "2026-10-19T12:00:30Z",
			ExpiresAt:     "2026-10-20T12:00:30Z",
		},
		AssignmentID:     assignment.AssignmentID,
		AssignmentSHA256: assignmentDigest,
		BootID:           "fixture-replay-boot",
		StartedAt:        new("2026-10-19T12:00:01Z"),
		FinishedAt:       "2026-10-19T12:00:30Z",
		State:            "succeeded",
		Evidence:         []c.DiagnosticEvidenceV1{{ReferenceID: "fixture-replay-evidence", SHA256: strings.Repeat("a", 64), SizeBytes: 1024}},
	}, deviceKey)
	must(result.CheckAssignment(assignment))

	round := c.FederatedRoundV1{
		SchemaVersion:    c.FederatedRoundV1Version,
		DeploymentID:     deploymentID,
		RoundID:          "fixture-replay-round",
		BaseModelVersion: "fixture-replay-base-v1",
		BaseModelSHA256:  strings.Repeat("b", 64),
		CandidateID:      "fixture-replay-candidate",
		FeatureVersion:   "fixture-replay-features-v1",
		ParameterCount:   2,
		OpenedAt:         "2026-10-19T12:00:00Z",
		Deadline:         "2026-10-19T13:00:00Z",
		MinParticipants:  2,
		Participants: []c.FederatedParticipantV1{
			{DeviceID: deviceID, SigningKeyID: deviceKeyID, Eligibility: "eligible"},
			{DeviceID: "fixture-replay-peer", SigningKeyID: peerKeyID, Eligibility: "eligible"},
		},
	}
	must(round.Validate())
	weightBytes := binary.BigEndian.AppendUint64(nil, math.Float64bits(0.25))
	weightBytes = binary.BigEndian.AppendUint64(weightBytes, math.Float64bits(-0.5))
	update := signUpdate(c.FederatedUpdateV1{
		EnvelopeHeaderV1: c.EnvelopeHeaderV1{
			SchemaVersion: c.FederatedUpdateV1Version,
			DeploymentID:  deploymentID,
			DeviceID:      deviceID,
			SigningKeyID:  deviceKeyID,
			Sequence:      4,
			IssuedAt:      "2026-10-19T12:10:00Z",
			ExpiresAt:     "2026-10-19T13:00:00Z",
		},
		RoundID:          round.RoundID,
		BaseModelVersion: round.BaseModelVersion,
		BaseModelSHA256:  round.BaseModelSHA256,
		CandidateID:      round.CandidateID,
		FeatureVersion:   round.FeatureVersion,
		SampleCount:      24,
		WeightsBase64:    base64.StdEncoding.EncodeToString(weightBytes),
		UpdateSHA256:     sha256Hex(weightBytes),
	}, deviceKey)
	must(update.CheckRound(round, fixedTime))

	bundle := replay.Bundle{
		Fixture:         true,
		FixedTime:       fixedTime.Format(time.RFC3339),
		DeviceID:        deviceID,
		DevicePublicKey: hex.EncodeToString(deviceKey.Public().(ed25519.PublicKey)),
		Telemetry: replay.Request{
			FixtureID: "fixture-replay-telemetry-v1",
			Sequence:  evidence.Sequence,
			Body:      mustJSON(evidence),
		},
		Diagnostics: replay.Diagnostics{
			Assignment: replay.Request{
				FixtureID: "fixture-replay-diagnostic-assignment-v1",
				Sequence:  assignment.Sequence,
				Body:      mustJSON(assignment),
			},
			Result: replay.Request{
				FixtureID: "fixture-replay-diagnostic-result-v1",
				Sequence:  result.Sequence,
				Body:      mustJSON(result),
			},
			ControllerPublicKey: hex.EncodeToString(controllerKey.Public().(ed25519.PublicKey)),
		},
		Federated: replay.Federated{
			Round: mustJSON(round),
			Update: replay.Request{
				FixtureID: "fixture-replay-federated-update-v1",
				Sequence:  update.Sequence,
				Body:      mustJSON(update),
			},
		},
	}
	encoded, err := json.MarshalIndent(bundle, "", "  ")
	must(err)
	must(os.WriteFile("packages/contracts/fixtures/replay/v1.json", append(encoded, '\n'), 0o644))
}
