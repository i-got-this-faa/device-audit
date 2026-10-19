//go:build ignore

// Regenerate with go run packages/contracts/fixtures/diagnostics/generate.go.
// Public RFC 8032 test seeds below are never operational keys.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	c "github.com/i-got-this-faa/device-audit/packages/contracts"
	"os"
)

type vector struct {
	Name           string          `json:"name"`
	Payload        json.RawMessage `json:"payload"`
	Valid          bool            `json:"valid"`
	SchemaValid    bool            `json:"schema_valid"`
	SignatureValid bool            `json:"signature_valid"`
	PublicKey      string          `json:"public_key"`
	CanonicalHex   string          `json:"canonical_hex"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func ptr[T any](v T) *T { return &v }
func main() {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	controller := ed25519.NewKeyFromSeed(seed)
	seed, _ = hex.DecodeString("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
	device := ed25519.NewKeyFromSeed(seed)
	keyID, _ := c.SigningKeyIDV1(controller.Public().(ed25519.PublicKey))
	a := c.DiagnosticAssignmentV1{EnvelopeHeaderV1: c.EnvelopeHeaderV1{SchemaVersion: c.DiagnosticAssignmentV1Version, DeploymentID: "deployment-a", DeviceID: "device-a", SigningKeyID: keyID, Sequence: 1, IssuedAt: "2026-10-19T12:00:00Z", ExpiresAt: "2026-10-19T12:05:00Z"}, AssignmentID: "assignment-a", ProbeID: "storage_health.v1", Arguments: c.DiagnosticArgumentsV1{ComponentID: ptr("storage-a")}, Budget: c.DiagnosticBudgetV1{WallSeconds: 60, MaxOutputBytes: 4096}}
	var vectors []vector
	add := func(name string, p any, valid, schemaValid, signatureValid bool, key ed25519.PrivateKey, message []byte) {
		raw, err := json.Marshal(p)
		must(err)
		vectors = append(vectors, vector{name, raw, valid, schemaValid, signatureValid, hex.EncodeToString(key[32:]), hex.EncodeToString(message)})
	}
	signA := func(a c.DiagnosticAssignmentV1) c.DiagnosticAssignmentV1 {
		m, err := a.SigningBytes()
		must(err)
		a.Signature = hex.EncodeToString(ed25519.Sign(controller, m))
		return a
	}
	a = signA(a)
	am, _ := a.SigningBytes()
	add("storage_assignment", a, true, true, true, controller, am)
	b := a
	b.AssignmentID = "assignment-errors"
	b.ProbeID = "system_errors.v1"
	b.Arguments = c.DiagnosticArgumentsV1{LookbackSeconds: ptr(uint32(3600)), MaxEntries: ptr(uint32(32))}
	b = signA(b)
	bm, _ := b.SigningBytes()
	add("errors_assignment", b, true, true, true, controller, bm)
	b = a
	b.DeviceID = "device-b"
	add("tampered_target", b, true, true, false, controller, nil)
	b = a
	b.Budget.WallSeconds = 0
	add("zero_wall_budget", b, false, false, false, controller, nil)
	b = a
	b.Budget.WallSeconds = 301
	add("excess_wall_budget", b, false, false, false, controller, nil)
	b = a
	b.ExpiresAt = "2026-10-19T12:00:30Z"
	add("budget_outlives_deadline", b, false, true, false, controller, nil)
	b = a
	b.ExpiresAt = b.IssuedAt
	add("empty_lifetime", b, false, true, false, controller, nil)
	b = a
	b.ProbeID = "shell.v1"
	add("shell_probe", b, false, false, false, controller, nil)
	b = a
	b.Arguments.LookbackSeconds = ptr(uint32(1))
	add("mixed_probe_arguments", b, false, false, false, controller, nil)
	raw, _ := json.Marshal(a)
	var fields map[string]any
	must(json.Unmarshal(raw, &fields))
	fields["command"] = "whoami"
	add("arbitrary_command", fields, false, false, false, controller, nil)
	fields = nil
	must(json.Unmarshal(raw, &fields))
	fields["arguments"].(map[string]any)["command"] = "whoami"
	add("nested_command", fields, false, false, false, controller, nil)
	digest, err := c.EnvelopeRequestSHA256V1(am, a.Signature)
	must(err)
	keyID, _ = c.SigningKeyIDV1(device.Public().(ed25519.PublicKey))
	r := c.DiagnosticResultV1{EnvelopeHeaderV1: c.EnvelopeHeaderV1{SchemaVersion: c.DiagnosticResultV1Version, DeploymentID: a.DeploymentID, DeviceID: a.DeviceID, SigningKeyID: keyID, Sequence: 2, IssuedAt: "2026-10-19T12:00:30Z", ExpiresAt: "2026-10-20T12:00:30Z"}, AssignmentID: a.AssignmentID, AssignmentSHA256: digest, BootID: "boot-original", StartedAt: ptr("2026-10-19T12:00:01Z"), FinishedAt: "2026-10-19T12:00:30Z", State: "succeeded", Evidence: []c.DiagnosticEvidenceV1{{ReferenceID: "evidence-a", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", SizeBytes: 1024}}}
	signR := func(r c.DiagnosticResultV1) c.DiagnosticResultV1 {
		m, err := r.SigningBytes()
		must(err)
		r.Signature = hex.EncodeToString(ed25519.Sign(device, m))
		return r
	}
	r = signR(r)
	rm, _ := r.SigningBytes()
	add("succeeded", r, true, true, true, device, rm)
	add("duplicate_succeeded_same_envelope", r, true, true, true, device, rm)
	for _, state := range []string{"failed", "cancelled", "expired", "rebooted", "rejected"} {
		q := r
		q.State = state
		q.Evidence = []c.DiagnosticEvidenceV1{}
		reason := map[string]string{"failed": "permission_denied", "cancelled": "cancel_requested", "expired": "deadline_exceeded", "rebooted": "agent_restarted", "rejected": "assignment_denied"}[state]
		q.Reason = &reason
		if state == "rejected" {
			q.StartedAt = nil
		}
		if state == "expired" || state == "rebooted" {
			q.FinishedAt = "2026-10-19T12:05:00Z"
			q.IssuedAt = q.FinishedAt
			q.ExpiresAt = "2026-10-20T12:05:00Z"
		}
		q = signR(q)
		m, _ := q.SigningBytes()
		add(state, q, true, true, true, device, m)
	}
	q := r
	q.Evidence = nil
	add("null_evidence", q, false, false, false, device, nil)
	q = r
	q.Reason = ptr("cancel_requested")
	add("success_with_cancel_reason", q, false, false, false, device, nil)
	q = r
	q.StartedAt = ptr("2026-10-19T12:01:00Z")
	add("finish_before_start", q, false, true, false, device, nil)
	q = r
	q.Evidence = append(append([]c.DiagnosticEvidenceV1{}, r.Evidence...), r.Evidence...)
	add("duplicate_evidence", q, false, true, false, device, nil)
	out, err := json.MarshalIndent(map[string]any{"vectors": vectors}, "", "  ")
	must(err)
	must(os.WriteFile("packages/contracts/fixtures/diagnostics/v1-vectors.json", append(out, '\n'), 0644))
}
