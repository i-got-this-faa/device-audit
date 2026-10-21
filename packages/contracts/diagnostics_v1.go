package contracts

import (
	"crypto/ed25519"
	"fmt"
	"strconv"
	"time"
)

const (
	DiagnosticAssignmentV1Version = "device-audit.diagnostic-assignment.v1"
	DiagnosticResultV1Version     = "device-audit.diagnostic-result.v1"
)

type DiagnosticArgumentsV1 struct {
	ComponentID     *string `json:"component_id"`
	LookbackSeconds *uint32 `json:"lookback_seconds"`
	MaxEntries      *uint32 `json:"max_entries"`
}

type DiagnosticBudgetV1 struct {
	WallSeconds    uint32 `json:"wall_seconds"`
	MaxOutputBytes uint32 `json:"max_output_bytes"`
}

// The signing key belongs to the controller. DeviceID is the sole target.
type DiagnosticAssignmentV1 struct {
	EnvelopeHeaderV1
	AssignmentID string                `json:"assignment_id"`
	ProbeID      string                `json:"probe_id"`
	Arguments    DiagnosticArgumentsV1 `json:"arguments"`
	Budget       DiagnosticBudgetV1    `json:"budget"`
	Signature    string                `json:"signature"`
}

type DiagnosticEvidenceV1 struct {
	ReferenceID string `json:"reference_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   uint32 `json:"size_bytes"`
}

// Results are terminal, signed by the target device, and kept off-chain.
type DiagnosticResultV1 struct {
	EnvelopeHeaderV1
	AssignmentID     string                 `json:"assignment_id"`
	AssignmentSHA256 string                 `json:"assignment_sha256"`
	BootID           string                 `json:"boot_id"`
	StartedAt        *string                `json:"started_at"`
	FinishedAt       string                 `json:"finished_at"`
	State            string                 `json:"state"`
	Reason           *string                `json:"reason"`
	Evidence         []DiagnosticEvidenceV1 `json:"evidence"`
	Signature        string                 `json:"signature"`
}

func (a *DiagnosticArgumentsV1) UnmarshalJSON(data []byte) error {
	type wire DiagnosticArgumentsV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"component_id", "lookback_seconds", "max_entries"}, "component_id", "lookback_seconds", "max_entries"); err != nil {
		return err
	}
	*a = DiagnosticArgumentsV1(v)
	return nil
}

func (b *DiagnosticBudgetV1) UnmarshalJSON(data []byte) error {
	type wire DiagnosticBudgetV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"wall_seconds", "max_output_bytes"}); err != nil {
		return err
	}
	*b = DiagnosticBudgetV1(v)
	return nil
}

func (e *DiagnosticEvidenceV1) UnmarshalJSON(data []byte) error {
	type wire DiagnosticEvidenceV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"reference_id", "sha256", "size_bytes"}); err != nil {
		return err
	}
	*e = DiagnosticEvidenceV1(v)
	return nil
}

func (a *DiagnosticAssignmentV1) UnmarshalJSON(data []byte) error {
	type wire DiagnosticAssignmentV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at", "assignment_id", "probe_id", "arguments", "budget", "signature"}); err != nil {
		return err
	}
	*a = DiagnosticAssignmentV1(v)
	return nil
}

func (r *DiagnosticResultV1) UnmarshalJSON(data []byte) error {
	type wire DiagnosticResultV1
	var v wire
	if err := decodeEnvelopeJSON(data, &v, []string{"schema_version", "deployment_id", "device_id", "signing_key_id", "sequence", "issued_at", "expires_at", "assignment_id", "assignment_sha256", "boot_id", "started_at", "finished_at", "state", "reason", "evidence", "signature"}, "started_at", "reason"); err != nil {
		return err
	}
	*r = DiagnosticResultV1(v)
	return nil
}

func (a DiagnosticAssignmentV1) validateBody() error {
	if err := a.EnvelopeHeaderV1.validate(DiagnosticAssignmentV1Version, 24*time.Hour); err != nil {
		return err
	}
	if !opaqueIDPattern.MatchString(a.AssignmentID) {
		return fmt.Errorf("invalid assignment ID")
	}
	if a.Budget.WallSeconds < 1 || a.Budget.WallSeconds > 300 || a.Budget.MaxOutputBytes < 1 || a.Budget.MaxOutputBytes > 1048576 {
		return fmt.Errorf("invalid diagnostic budget")
	}
	issued, _ := parseEnvelopeTime(a.IssuedAt)
	deadline, _ := parseEnvelopeTime(a.ExpiresAt)
	if issued.Add(time.Duration(a.Budget.WallSeconds) * time.Second).After(deadline) {
		return fmt.Errorf("wall budget exceeds assignment lifetime")
	}
	switch a.ProbeID {
	case "storage_health.v1":
		if a.Arguments.ComponentID == nil || !opaqueIDPattern.MatchString(*a.Arguments.ComponentID) || a.Arguments.LookbackSeconds != nil || a.Arguments.MaxEntries != nil {
			return fmt.Errorf("storage health requires only component_id")
		}
	case "system_errors.v1":
		if a.Arguments.ComponentID != nil || a.Arguments.LookbackSeconds == nil || *a.Arguments.LookbackSeconds < 1 || *a.Arguments.LookbackSeconds > 86400 || a.Arguments.MaxEntries == nil || *a.Arguments.MaxEntries < 1 || *a.Arguments.MaxEntries > 256 {
			return fmt.Errorf("system errors requires bounded lookback and entry count")
		}
	default:
		return fmt.Errorf("probe is not allowlisted")
	}
	return nil
}

func (a DiagnosticAssignmentV1) Validate() error {
	if err := a.validateBody(); err != nil {
		return err
	}
	return validateEnvelopeSignature(a.Signature)
}

func optionalDiagnosticString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
func optionalDiagnosticUint(v *uint32) string {
	if v == nil {
		return ""
	}
	return strconv.FormatUint(uint64(*v), 10)
}

func (a DiagnosticAssignmentV1) SigningBytes() ([]byte, error) {
	if err := a.validateBody(); err != nil {
		return nil, err
	}
	return canonicalEnvelopeFields(append(a.signingFields(), a.AssignmentID, a.ProbeID, optionalDiagnosticString(a.Arguments.ComponentID), optionalDiagnosticUint(a.Arguments.LookbackSeconds), optionalDiagnosticUint(a.Arguments.MaxEntries), strconv.FormatUint(uint64(a.Budget.WallSeconds), 10), strconv.FormatUint(uint64(a.Budget.MaxOutputBytes), 10))), nil
}

func (a DiagnosticAssignmentV1) VerifySignature(trustedControllerKey ed25519.PublicKey) error {
	message, err := a.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(trustedControllerKey, a.SigningKeyID, a.Signature, message)
}

// CanStart checks only scheduling time. Authorization and durable deduplication
// must happen separately, before any probe starts.
func (a DiagnosticAssignmentV1) CanStart(now time.Time) error {
	if err := a.Validate(); err != nil {
		return err
	}
	issued, _ := parseEnvelopeTime(a.IssuedAt)
	deadline, _ := parseEnvelopeTime(a.ExpiresAt)
	if now.IsZero() || now.Before(issued) || !now.Before(deadline) || now.Add(time.Duration(a.Budget.WallSeconds)*time.Second).After(deadline) {
		return fmt.Errorf("assignment cannot fit before deadline")
	}
	return nil
}

func (r DiagnosticResultV1) validateBody() error {
	if err := r.EnvelopeHeaderV1.validate(DiagnosticResultV1Version, 24*time.Hour); err != nil {
		return err
	}
	if r.Sequence < 2 || !opaqueIDPattern.MatchString(r.AssignmentID) || !fixedEnvelopeHex(r.AssignmentSHA256, 32) || !opaqueIDPattern.MatchString(r.BootID) || r.Evidence == nil || len(r.Evidence) > 8 {
		return fmt.Errorf("invalid result binding or evidence")
	}
	finished, err := parseEnvelopeTime(r.FinishedAt)
	if err != nil {
		return err
	}
	issued, _ := parseEnvelopeTime(r.IssuedAt)
	if finished.After(issued) {
		return fmt.Errorf("result issued before finish")
	}
	if r.StartedAt != nil {
		started, err := parseEnvelopeTime(*r.StartedAt)
		if err != nil {
			return err
		}
		if started.After(finished) {
			return fmt.Errorf("result finishes before start")
		}
	}
	switch r.State {
	case "succeeded":
		if r.StartedAt == nil || r.Reason != nil || len(r.Evidence) == 0 {
			return fmt.Errorf("success requires start and evidence, no reason")
		}
	case "failed":
		if r.StartedAt == nil || r.Reason == nil || (*r.Reason != "probe_error" && *r.Reason != "budget_exhausted" && *r.Reason != "permission_denied") {
			return fmt.Errorf("failure requires start and failure reason")
		}
	case "cancelled", "expired", "rebooted", "rejected":
		reasons := map[string]string{"cancelled": "cancel_requested", "expired": "deadline_exceeded", "rebooted": "agent_restarted", "rejected": "assignment_denied"}
		if r.Reason == nil || *r.Reason != reasons[r.State] || len(r.Evidence) != 0 {
			return fmt.Errorf("invalid terminal reason or evidence")
		}
		if r.State == "rebooted" && r.StartedAt == nil {
			return fmt.Errorf("reboot terminal requires prior start")
		}
		if r.State == "rejected" && r.StartedAt != nil {
			return fmt.Errorf("rejected assignment cannot have started")
		}
	default:
		return fmt.Errorf("invalid terminal state")
	}
	seen := map[string]bool{}
	for _, e := range r.Evidence {
		if !opaqueIDPattern.MatchString(e.ReferenceID) || !fixedEnvelopeHex(e.SHA256, 32) || e.SizeBytes < 1 || e.SizeBytes > 1048576 || seen[e.ReferenceID] {
			return fmt.Errorf("invalid or duplicate evidence reference")
		}
		seen[e.ReferenceID] = true
	}
	return nil
}

func (r DiagnosticResultV1) Validate() error {
	if err := r.validateBody(); err != nil {
		return err
	}
	return validateEnvelopeSignature(r.Signature)
}

func (r DiagnosticResultV1) SigningBytes() ([]byte, error) {
	if err := r.validateBody(); err != nil {
		return nil, err
	}
	fields := append(r.signingFields(), r.AssignmentID, r.AssignmentSHA256, r.BootID, optionalDiagnosticString(r.StartedAt), r.FinishedAt, r.State, optionalDiagnosticString(r.Reason), strconv.Itoa(len(r.Evidence)))
	for _, e := range r.Evidence {
		fields = append(fields, e.ReferenceID, e.SHA256, strconv.FormatUint(uint64(e.SizeBytes), 10))
	}
	return canonicalEnvelopeFields(fields), nil
}

func (r DiagnosticResultV1) VerifySignature(trustedDeviceKey ed25519.PublicKey) error {
	message, err := r.SigningBytes()
	if err != nil {
		return err
	}
	return verifyEnvelopeSignature(trustedDeviceKey, r.SigningKeyID, r.Signature, message)
}

// CheckAssignment correlates a terminal result with a previously authenticated
// assignment. It does not resolve evidence or commit terminal/replay state.
func (r DiagnosticResultV1) CheckAssignment(a DiagnosticAssignmentV1) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if err := a.Validate(); err != nil {
		return err
	}
	message, err := a.SigningBytes()
	if err != nil {
		return err
	}
	digest, err := EnvelopeRequestSHA256V1(message, a.Signature)
	if err != nil {
		return err
	}
	if r.DeploymentID != a.DeploymentID || r.DeviceID != a.DeviceID || r.AssignmentID != a.AssignmentID || r.AssignmentSHA256 != digest {
		return fmt.Errorf("result does not match assignment")
	}
	assigned, _ := parseEnvelopeTime(a.IssuedAt)
	deadline, _ := parseEnvelopeTime(a.ExpiresAt)
	finished, _ := parseEnvelopeTime(r.FinishedAt)
	if finished.Before(assigned) {
		return fmt.Errorf("result precedes assignment")
	}
	if r.StartedAt != nil {
		started, _ := parseEnvelopeTime(*r.StartedAt)
		if started.Before(assigned) || !started.Before(deadline) || started.Add(time.Duration(a.Budget.WallSeconds)*time.Second).After(deadline) {
			return fmt.Errorf("invalid execution start")
		}
		if r.State != "rebooted" && r.State != "expired" && finished.Sub(started) > time.Duration(a.Budget.WallSeconds)*time.Second {
			return fmt.Errorf("execution exceeds wall budget")
		}
	}
	if r.State == "succeeded" && finished.After(deadline) {
		return fmt.Errorf("success after deadline")
	}
	if r.State == "expired" && finished.Before(deadline) {
		return fmt.Errorf("expiry before deadline")
	}
	var total uint64
	for _, e := range r.Evidence {
		total += uint64(e.SizeBytes)
	}
	if total > uint64(a.Budget.MaxOutputBytes) {
		return fmt.Errorf("evidence exceeds output budget")
	}
	return nil
}
