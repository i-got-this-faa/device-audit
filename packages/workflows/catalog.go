package workflows

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

// DIA01 #36: the typed, read-only probe catalog.
//
// A probe runs only when its ID is on the CT06 allowlist and its arguments
// pass the CT06 typed check. There is no generic executor, shell, script, path
// or URL argument, and no probe writes state, changes ACLs or retries with more
// rights after a denial. Evidence is structured: event-log messages are reduced
// to a digest so command-like log text never appears in probe output.

const (
	// ProbeEvidenceSchema identifies one probe's evidence document.
	ProbeEvidenceSchema = "device-audit.probe-evidence.v1"
	// SourceStorageIOCTL marks evidence read from the local storage driver.
	SourceStorageIOCTL = "endpoint_storage_ioctl"
	// MaxStorageDisk bounds the OS disk numbers a component ID can name.
	MaxStorageDisk = 63
)

// FailureReason is a CT06 failed-result reason.
type FailureReason string

const (
	ReasonProbeError       FailureReason = "probe_error"
	ReasonBudgetExhausted  FailureReason = "budget_exhausted"
	ReasonPermissionDenied FailureReason = "permission_denied"
)

// Failure is a probe that started and did not succeed. Detail is a fixed word,
// never OS error text. Partial holds evidence collected before a denial, when
// there is any and it fits the output budget.
type Failure struct {
	Reason  FailureReason
	Detail  string
	Partial []byte
}

func (f *Failure) Error() string { return fmt.Sprintf("probe failed: %s (%s)", f.Reason, f.Detail) }

// ErrComponentNotFound means a well-formed component ID names no eligible
// local storage component.
var ErrComponentNotFound = errors.New("workflows: storage component not found")

// Request is one typed probe invocation. Its fields are the CT06 assignment's.
type Request struct {
	ProbeID   string                          `json:"probe_id"`
	Arguments contracts.DiagnosticArgumentsV1 `json:"arguments"`
	Budget    contracts.DiagnosticBudgetV1    `json:"budget"`
}

// MaxRequestBytes bounds one encoded Request.
const MaxRequestBytes = 4096

// ParseRequest strictly decodes and validates one JSON request. Unknown keys
// such as "command" or "shell" are rejected at every level, as is trailing data.
func ParseRequest(r io.Reader) (Request, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxRequestBytes+1))
	if err != nil || len(data) > MaxRequestBytes {
		return Request{}, errors.New("probe request is unreadable or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var req Request
	if err := decoder.Decode(&req); err != nil {
		return Request{}, errors.New("probe request is not a strict probe request")
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return Request{}, errors.New("probe request has trailing data")
	}
	return req, req.Validate()
}

// Validate applies the CT06 allowlist, argument and budget checks. A request
// that fails it never reaches an OS reader.
func (r Request) Validate() error {
	if err := r.Arguments.ValidateFor(r.ProbeID); err != nil {
		return err
	}
	if r.Budget.WallSeconds < 1 || r.Budget.WallSeconds > 300 || r.Budget.MaxOutputBytes < 1 || r.Budget.MaxOutputBytes > 1048576 {
		return errors.New("invalid diagnostic budget")
	}
	return nil
}

// Evidence is the document a successful probe returns.
type Evidence[T any] struct {
	Schema     string                          `json:"schema"`
	ProbeID    string                          `json:"probe_id"`
	Source     string                          `json:"source"`
	ObservedAt time.Time                       `json:"observed_at"`
	Arguments  contracts.DiagnosticArgumentsV1 `json:"arguments"`
	Body       T                               `json:"body"`
}

// StorageHealth is one disk's health. NVMe is nil when the disk does not speak
// NVMe; MissingReason then says why.
type StorageHealth struct {
	ComponentID   string      `json:"component_id"`
	BusType       string      `json:"bus_type"`
	NVMe          *NVMeHealth `json:"nvme_health"`
	MissingReason string      `json:"missing_reason,omitempty"`
}

// NVMeHealth is the bounded subset of the NVMe SMART / health log page.
// Counters are the log's low 64 bits; a value beyond that is a probe error.
// TemperatureCelsius is nil when the drive reports no composite temperature.
type NVMeHealth struct {
	CriticalWarningFlags    uint8  `json:"critical_warning_flags"`
	TemperatureCelsius      *int   `json:"composite_temperature_celsius"`
	AvailableSparePercent   uint8  `json:"available_spare_percent"`
	SpareThresholdPercent   uint8  `json:"available_spare_threshold_percent"`
	PercentageUsed          uint8  `json:"percentage_used"`
	MediaErrors             uint64 `json:"media_errors"`
	UnsafeShutdowns         uint64 `json:"unsafe_shutdowns"`
	PowerOnHours            uint64 `json:"power_on_hours"`
	ErrorLogEntries         uint64 `json:"error_log_entries"`
	WarningTemperatureMins  uint32 `json:"warning_temperature_minutes"`
	CriticalTemperatureMins uint32 `json:"critical_temperature_minutes"`
}

// SystemErrors is the system_errors.v1 body: one entry per selected log.
type SystemErrors struct {
	LookbackSeconds uint32           `json:"lookback_seconds"`
	MaxEntries      uint32           `json:"max_entries"`
	Logs            []SystemErrorLog `json:"logs"`
}

// SystemErrorLog is one log's read. More means max_entries cut the read short.
type SystemErrorLog struct {
	Log     string        `json:"log"`
	Outcome string        `json:"outcome"`
	Detail  string        `json:"detail,omitempty"`
	Records []ErrorDigest `json:"records"`
	Skipped int           `json:"skipped"`
	More    bool          `json:"more"`
}

// ErrorDigest is one error event without free log text. MessageSHA256 is the
// digest of the TEL07-bounded message, so it matches a --collect-errors record
// without copying the text; it is empty when no message was read. Any process
// can log under an unregistered source name, so Provider is kept only when it
// looks like a publisher name and is null otherwise; ProviderSHA256 is always set.
type ErrorDigest struct {
	RecordID       uint64    `json:"record_id"`
	Provider       *string   `json:"provider"`
	ProviderSHA256 string    `json:"provider_sha256"`
	EventID        uint16    `json:"event_id"`
	Level          uint8     `json:"level"`
	TimeCreated    time.Time `json:"time_created"`
	MessageSHA256  string    `json:"message_sha256"`
	MessageBytes   int       `json:"message_bytes"`
	MessageStatus  string    `json:"message_status"`
}

// DiskReader is the read-only storage boundary.
type DiskReader interface {
	// Health reads OS disk number n. It returns ErrComponentNotFound when the
	// disk is absent or not an eligible fixed disk.
	Health(ctx context.Context, n int) (StorageHealth, error)
}

// Catalog runs allowlisted probes against injected read-only providers.
type Catalog struct {
	Disks  DiskReader
	Events telemetry.EventLogReader
	Now    func() time.Time
}

// NewCatalog returns the catalog bound to this platform's readers.
func NewCatalog() Catalog {
	return Catalog{Disks: platformDiskReader{}, Events: telemetry.NewErrorCollector().Reader}
}

// Run validates req, runs its probe under the wall budget and returns the
// encoded evidence. A request error is returned as is and nothing runs; a
// started probe that does not succeed returns *Failure.
func (c Catalog) Run(ctx context.Context, req Request) ([]byte, error) {
	if err := req.Validate(); err != nil {
		return nil, err
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(req.Budget.WallSeconds)*time.Second)
	defer cancel()
	var encoded []byte
	var err error
	switch req.ProbeID {
	case contracts.DiagnosticProbeStorageHealthV1:
		encoded, err = c.storageHealth(ctx, req, now)
	case contracts.DiagnosticProbeSystemErrorsV1:
		encoded, err = c.systemErrors(ctx, req, now)
	default:
		// Validate already rejected it; keep the switch exhaustive.
		return nil, contracts.ErrDiagnosticProbeNotAllowlisted
	}
	// The event-log collector records a timeout per log rather than returning
	// it, so any failure once the wall budget is gone is budget exhaustion.
	if err != nil {
		if parentErr := context.Cause(ctx); errors.Is(parentErr, context.Canceled) {
			return nil, parentErr
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, &Failure{Reason: ReasonBudgetExhausted, Detail: "wall_budget"}
		}
	}
	var failure *Failure
	if errors.As(err, &failure) {
		if len(failure.Partial) > int(req.Budget.MaxOutputBytes) {
			failure.Partial = nil
		}
		return nil, failure
	}
	if err != nil {
		return nil, err
	}
	if len(encoded) > int(req.Budget.MaxOutputBytes) {
		return nil, &Failure{Reason: ReasonBudgetExhausted, Detail: "output_budget"}
	}
	return encoded, nil
}

// componentPattern is the only component ID form that names local storage. It
// is an OS disk number, not a serial number, path or other hardware identifier.
var componentPattern = regexp.MustCompile(`^storage:disk-(0|[1-9][0-9]?)$`)

// ParseStorageComponent returns the OS disk number a component ID names.
func ParseStorageComponent(id string) (int, error) {
	m := componentPattern.FindStringSubmatch(id)
	if m == nil {
		return 0, ErrComponentNotFound
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n > MaxStorageDisk {
		return 0, ErrComponentNotFound
	}
	return n, nil
}

// StorageComponentID is the component ID for OS disk number n.
func StorageComponentID(n int) string { return "storage:disk-" + strconv.Itoa(n) }

func (c Catalog) storageHealth(ctx context.Context, req Request, now func() time.Time) ([]byte, error) {
	if c.Disks == nil {
		return nil, errors.New("workflows: storage reader is not configured")
	}
	n, err := ParseStorageComponent(*req.Arguments.ComponentID)
	if err != nil {
		return nil, &Failure{Reason: ReasonProbeError, Detail: "component_not_found"}
	}
	health, err := readBounded(ctx, func(ctx context.Context) (StorageHealth, error) { return c.Disks.Health(ctx, n) })
	if err != nil {
		return nil, classify(err, "storage")
	}
	health.ComponentID = *req.Arguments.ComponentID
	return json.Marshal(Evidence[StorageHealth]{
		Schema: ProbeEvidenceSchema, ProbeID: req.ProbeID, Source: SourceStorageIOCTL,
		ObservedAt: now().UTC(), Arguments: req.Arguments, Body: health,
	})
}

func (c Catalog) systemErrors(ctx context.Context, req Request, now func() time.Time) ([]byte, error) {
	lookback, limit := *req.Arguments.LookbackSeconds, *req.Arguments.MaxEntries
	collector := telemetry.ErrorCollector{
		Reader: c.Events, Logs: []string{telemetry.LogSystem, telemetry.LogApplication},
		Limit: int(limit), Lookback: time.Duration(lookback) * time.Second, Now: now,
	}
	// No saved positions: the probe reads its lookback window and never moves
	// the --collect-errors read positions.
	batch, err := collector.Collect(ctx, nil)
	if err != nil {
		return nil, err
	}
	body := SystemErrors{LookbackSeconds: lookback, MaxEntries: limit, Logs: make([]SystemErrorLog, 0, len(batch.Logs))}
	var failed *Failure
	for _, l := range batch.Logs {
		entry := SystemErrorLog{Log: l.Log, Outcome: l.Outcome, Detail: l.Detail, Records: make([]ErrorDigest, 0, len(l.Records)), Skipped: l.Skipped, More: l.More}
		for _, r := range l.Records {
			entry.Records = append(entry.Records, digestRecord(r))
		}
		body.Logs = append(body.Logs, entry)
		switch {
		case l.Outcome == telemetry.LogPermissionDenied:
			failed = &Failure{Reason: ReasonPermissionDenied, Detail: "event_log_access_denied"}
		case l.Outcome != telemetry.LogRead && failed == nil:
			failed = &Failure{Reason: ReasonProbeError, Detail: "event_log_" + l.Outcome}
		}
	}
	encoded, err := json.Marshal(Evidence[SystemErrors]{
		Schema: ProbeEvidenceSchema, ProbeID: req.ProbeID, Source: batch.Provenance,
		ObservedAt: batch.CollectedAt, Arguments: req.Arguments, Body: body,
	})
	if err != nil {
		return nil, err
	}
	if failed != nil {
		failed.Partial = encoded
		return nil, failed
	}
	return encoded, nil
}

// providerPattern admits publisher names such as "Service Control Manager" or
// "Microsoft-Windows-Kernel-Power" and no shell metacharacters or path syntax.
var providerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$`)

func digestRecord(r telemetry.ErrorRecord) ErrorDigest {
	d := ErrorDigest{RecordID: r.RecordID, ProviderSHA256: digest(r.Provider), EventID: r.EventID, Level: r.Level,
		TimeCreated: r.TimeCreated, MessageBytes: r.MessageBytes, MessageStatus: r.MessageStatus}
	if providerPattern.MatchString(r.Provider) {
		d.Provider = &r.Provider
	}
	if r.MessageStatus != telemetry.MessageOversized && r.MessageStatus != telemetry.MessageUnavailable {
		d.MessageSHA256 = digest(r.Message)
	}
	return d
}

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// readBounded runs read so that a provider blocked in a system call cannot hold
// the probe past ctx. A late result is discarded.
func readBounded[T any](ctx context.Context, read func(context.Context) (T, error)) (T, error) {
	type outcome struct {
		v   T
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		v, err := read(ctx)
		done <- outcome{v, err}
	}()
	select {
	case out := <-done:
		return out.v, out.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// classify turns a reader error into a CT06 failure with a fixed detail word.
func classify(err error, prefix string) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return err
	case errors.Is(err, ErrComponentNotFound):
		return &Failure{Reason: ReasonProbeError, Detail: "component_not_found"}
	case errors.Is(err, telemetry.ErrPermissionDenied):
		return &Failure{Reason: ReasonPermissionDenied, Detail: prefix + "_access_denied"}
	default:
		return &Failure{Reason: ReasonProbeError, Detail: prefix + "_read_failed"}
	}
}
