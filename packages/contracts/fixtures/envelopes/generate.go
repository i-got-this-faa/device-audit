//go:build ignore

// Regenerate from the repository root with: go run packages/contracts/fixtures/envelopes/generate.go
// These are public RFC 8032 section 7.1 test seeds, never operational credentials.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
)

const enrollment = "device-audit.enrollment.v1"
const evidence = "device-audit.evidence.v1"
const ack = "device-audit.acknowledgement.v1"

type object = map[string]any

type vector struct {
	Name               string `json:"name"`
	Envelope           object `json:"envelope"`
	ContractValid      bool   `json:"contract_valid"`
	VerificationKey    string `json:"verification_key"`
	SignatureValid     bool   `json:"signature_valid"`
	SignatureError     string `json:"signature_error"`
	CanonicalHex       string `json:"canonical_hex"`
	RequestSHA256      string `json:"request_sha256"`
	Now                string `json:"now"`
	LastSequence       uint64 `json:"last_sequence"`
	FreshnessRejection string `json:"freshness_rejection"`
}

func mustHex(s string) []byte {
	value, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return value
}
func digest(data []byte) string           { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func keyID(key ed25519.PrivateKey) string { return "ed25519:" + digest(key[32:]) }
func clone(value object) object {
	encoded, _ := json.Marshal(value)
	var result object
	if err := json.Unmarshal(encoded, &result); err != nil {
		panic(err)
	}
	return result
}

// This independent framing implementation pins the protocol without importing the contract implementation.
func canonical(value object) []byte {
	fields := []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at"}
	switch value["schema_version"] {
	case enrollment:
		fields = append(fields, "public_key", "challenge_id")
	case evidence:
		fields = append(fields, "payload_schema_version", "payload_sha256")
	case ack:
		fields = []string{"schema_version", "deployment_id", "device_id", "controller_key_id", "request_schema_version", "request_key_id", "request_sequence", "request_sha256", "received_at", "status", "rejection_reason", "last_sequence"}
	}
	result := []byte("device-audit/signature/v1\x00")
	for _, field := range fields {
		text := ""
		switch v := value[field].(type) {
		case string:
			text = v
		case uint64:
			text = strconv.FormatUint(v, 10)
		case float64:
			text = strconv.FormatUint(uint64(v), 10)
		case nil:
		default:
			panic(field)
		}
		result = binary.BigEndian.AppendUint32(result, uint32(len(text)))
		result = append(result, text...)
	}
	return result
}
func sign(value object, key ed25519.PrivateKey) {
	value["signature"] = hex.EncodeToString(ed25519.Sign(key, canonical(value)))
}
func fingerprint(value object) string {
	return digest(append(canonical(value), mustHex(value["signature"].(string))...))
}

func main() {
	device := ed25519.NewKeyFromSeed(mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
	controller := ed25519.NewKeyFromSeed(mustHex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"))
	start := object{"schema_version": enrollment, "deployment_id": "deployment:fixture-01", "device_id": "asset:fixture-01", "signing_key_id": keyID(device), "sequence": uint64(1), "issued_at": "2026-10-15T12:00:00Z", "expires_at": "2026-10-15T12:10:00Z", "public_key": hex.EncodeToString(device[32:]), "challenge_id": "challenge:fixture-only-not-a-live-challenge"}
	sign(start, device)
	payload := []byte(`{"schema_version":"device-audit.telemetry.v2","device_id":"asset:fixture-01","collected_at":"2026-10-14T12:00:00Z","source":"fixture","metrics":{"cpu_utilization":{"value":0,"unit":"percent"},"gpu_utilization":{"value":null,"unit":"percent","missing_reason":"sensor_unavailable"}},"inventory":{"components":[{"id":"component:fixture","type":"cpu","model":"例"}]},"log_references":[]}`)
	report := clone(start)
	delete(report, "public_key")
	delete(report, "challenge_id")
	report["schema_version"], report["sequence"], report["expires_at"] = evidence, uint64(2), "2026-10-16T12:00:00Z"
	report["payload_schema_version"], report["payload_base64"], report["payload_sha256"] = "device-audit.telemetry.v2", base64.StdEncoding.EncodeToString(payload), digest(payload)
	sign(report, device)
	vectors := []vector{}
	add := func(name string, value object, valid bool, key ed25519.PrivateKey, sigValid bool, sigError string, last uint64, now, rejection string) {
		v := vector{Name: name, Envelope: value, ContractValid: valid, VerificationKey: hex.EncodeToString(key[32:]), SignatureValid: sigValid, SignatureError: sigError, Now: now, LastSequence: last, FreshnessRejection: rejection}
		if valid {
			v.CanonicalHex = hex.EncodeToString(canonical(value))
			if value["schema_version"] != ack {
				v.RequestSHA256 = fingerprint(value)
			}
		}
		vectors = append(vectors, v)
	}
	now := "2026-10-15T12:00:00Z"
	add("valid enrollment", start, true, device, true, "", 0, now, "")
	add("valid offline evidence with nullable metric", report, true, device, true, "", 1, now, "")
	add("wrong enrollment key", start, true, controller, false, "key_mismatch", 0, now, "")
	add("wrong evidence key", report, true, controller, false, "key_mismatch", 1, now, "")
	changed := clone(start)
	changed["challenge_id"] = "challenge:altered"
	add("altered enrollment challenge", changed, true, device, false, "invalid_signature", 0, now, "")
	changed = clone(report)
	changed["payload_base64"] = base64.StdEncoding.EncodeToString(append(payload, ' '))
	add("altered payload stale digest", changed, false, device, false, "", 1, now, "")
	changed = clone(changed)
	changed["payload_sha256"] = digest(append(payload, ' '))
	add("altered payload recomputed digest", changed, true, device, false, "invalid_signature", 1, now, "")
	changed = clone(report)
	changed["deployment_id"] = "deployment:other"
	add("altered deployment", changed, true, device, false, "invalid_signature", 1, now, "")
	add("enrollment freshness sequence already consumed", start, true, device, true, "", 1, now, "replay")
	add("replayed evidence after lost acknowledgement", report, true, device, true, "", 2, now, "replay")
	add("replayed evidence after controller restart", report, true, device, true, "", 7, now, "replay")
	add("expired at exact boundary", report, true, device, true, "", 1, "2026-10-16T12:00:00Z", "expired")
	add("expiry precedes replay classification", report, true, device, true, "", 2, "2026-10-16T12:00:00Z", "expired")
	add("future timestamp beyond skew", report, true, device, true, "", 1, "2026-10-15T11:54:59Z", "future_timestamp")
	add("future timestamp exact skew allowed", report, true, device, true, "", 1, "2026-10-15T11:55:00Z", "")
	changed = clone(report)
	changed["sequence"] = uint64(9007199254740991)
	sign(changed, device)
	add("sequence gaps and maximum", changed, true, device, true, "", 2, now, "")
	makeAck := func(request object, status string, reason any, last any) object {
		result := object{"schema_version": ack, "deployment_id": request["deployment_id"], "device_id": request["device_id"], "controller_key_id": keyID(controller), "request_schema_version": request["schema_version"], "request_key_id": request["signing_key_id"], "request_sequence": request["sequence"], "request_sha256": fingerprint(request), "received_at": now, "status": status, "rejection_reason": reason, "last_sequence": last}
		sign(result, controller)
		return result
	}
	accepted := makeAck(report, "accepted", nil, uint64(2))
	add("accepted durable evidence acknowledgement", accepted, true, controller, true, "", 0, "", "")
	add("accepted enrollment acknowledgement", makeAck(start, "accepted", nil, uint64(1)), true, controller, true, "", 0, "", "")
	add("wrong controller acknowledgement key", accepted, true, device, false, "key_mismatch", 0, "", "")
	for _, reason := range []string{"invalid_signature", "key_mismatch", "payload_digest_mismatch", "replay", "expired", "future_timestamp", "unknown_device", "revoked_key", "deployment_mismatch", "bootstrap_invalid", "challenge_expired", "challenge_reused", "enrollment_conflict", "unauthorized_peer", "storage_unavailable", "invalid_payload"} {
		var last any
		if reason == "replay" {
			last = uint64(2)
		}
		request := report
		if reason == "bootstrap_invalid" || reason == "challenge_expired" || reason == "challenge_reused" || reason == "enrollment_conflict" {
			request = start
		}
		add("explicit rejection "+reason, makeAck(request, "rejected", reason, last), true, controller, true, "", 0, "", "")
	}
	add("rejection with known never-enrolled mark", makeAck(report, "rejected", "unknown_device", uint64(0)), true, controller, true, "", 0, "", "")
	changed = clone(accepted)
	changed["request_sha256"] = digest([]byte("different request"))
	add("altered acknowledgement correlation", changed, true, controller, false, "invalid_signature", 0, "", "")
	invalids := []struct {
		name   string
		base   object
		change func(object)
	}{
		{"missing signature", report, func(v object) { delete(v, "signature") }},
		{"unknown mesh credential field", report, func(v object) { v["mesh_credential"] = "fixture-forbidden" }},
		{"null required sequence", report, func(v object) { v["sequence"] = nil }},
		{"zero evidence sequence", report, func(v object) { v["sequence"] = uint64(0) }},
		{"evidence enrollment sequence", report, func(v object) { v["sequence"] = uint64(1) }},
		{"sequence above safe integer", report, func(v object) { v["sequence"] = uint64(9007199254740992) }},
		{"noninitial enrollment sequence", start, func(v object) { v["sequence"] = uint64(2) }},
		{"fractional timestamp", report, func(v object) { v["issued_at"] = "2026-10-15T12:00:00.000Z" }},
		{"zero year timestamp", report, func(v object) { v["issued_at"] = "0001-01-01T00:00:00Z" }},
		{"equal validity timestamps", report, func(v object) { v["expires_at"] = v["issued_at"] }},
		{"excess enrollment lifetime", start, func(v object) { v["expires_at"] = "2026-10-15T12:10:01Z" }},
		{"excess evidence lifetime", report, func(v object) { v["expires_at"] = "2026-10-16T12:00:01Z" }},
		{"noncanonical base64 newline", report, func(v object) { v["payload_base64"] = v["payload_base64"].(string) + "\n" }},
		{"payload device mismatch", report, func(v object) {
			p := []byte(`{"schema_version":"device-audit.telemetry.v2","device_id":"other-device","collected_at":"2026-10-15T12:00:00Z","source":"fixture","metrics":{"cpu_utilization":{"value":0,"unit":"percent"}},"inventory":{"components":[]},"log_references":[]}`)
			v["payload_base64"] = base64.StdEncoding.EncodeToString(p)
			v["payload_sha256"] = digest(p)
		}},
		{"enrollment key fingerprint mismatch", start, func(v object) { v["public_key"] = hex.EncodeToString(controller[32:]) }},
		{"accepted with rejection reason", accepted, func(v object) { v["rejection_reason"] = "replay" }},
		{"accepted without durable mark", accepted, func(v object) { v["last_sequence"] = nil }},
		{"accepted wrong committed sequence", accepted, func(v object) { v["last_sequence"] = uint64(3) }},
		{"rejected without explicit reason", accepted, func(v object) { v["status"] = "rejected" }},
		{"unknown rejection reason", accepted, func(v object) { v["status"] = "rejected"; v["rejection_reason"] = "maybe" }},
		{"replay without known durable mark", accepted, func(v object) { v["status"] = "rejected"; v["rejection_reason"] = "replay"; v["last_sequence"] = nil }},
		{"replay mark below request sequence", accepted, func(v object) {
			v["status"] = "rejected"
			v["rejection_reason"] = "replay"
			v["last_sequence"] = uint64(1)
		}},
	}
	for _, invalid := range invalids {
		changed = clone(invalid.base)
		invalid.change(changed)
		add(invalid.name, changed, false, device, false, "", 0, now, "")
	}
	output := object{"description": "Public RFC 8032 test keys only. No live credentials. Schema, contract, signature and freshness are separate checks; no authorization or durable storage is implemented.", "vectors": vectors}
	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("packages/contracts/fixtures/envelopes/v1-vectors.json", append(encoded, '\n'), 0644); err != nil {
		panic(err)
	}
}
