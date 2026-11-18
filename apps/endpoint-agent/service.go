package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

// TEL02 #26: the Windows service host for the real collector pipeline.
//
// The service loads the admitted identity, runs the TEL08 sampling schedule,
// signs each snapshot with the crash-safe CT04 sequence and appends the signed
// envelope to a size-capped local evidence file. Delivery and a retrying spool
// are #27; this host never sends unsigned or fixture telemetry.

const (
	serviceConfigSchema = "device-audit.endpoint-service.v1"
	// serviceName is the installed service and the per-service SID name.
	serviceName        = "DeviceAuditEndpoint"
	evidenceLogFile    = "signed-evidence.jsonl"
	serviceLogFile     = "service.log"
	maxServiceConfig   = 16 << 10
	maxServiceLogBytes = 1 << 20
	minEvidenceCap     = 1 << 20
	maxEvidenceCap     = 1 << 30
	// maxTornTail bounds how far back a torn final record is searched for.
	// It is larger than any envelope a 256 KiB payload produces.
	maxTornTail = 1 << 20
)

// errEvidenceFull stops the service instead of silently dropping evidence.
var errEvidenceFull = errors.New("signed evidence file reached max_evidence_bytes; delivery and spooling (#27) are not implemented")

// serviceEnrollment is the one-time first-start enrollment. The bootstrap file
// holds a one-use bootstrap-token.v1 document and is deleted once read.
type serviceEnrollment struct {
	Origin        string  `json:"origin"`
	CAFile        *string `json:"ca_file"`
	BootstrapFile string  `json:"bootstrap_file"`
}

// serviceConfig is device-audit.endpoint-service.v1. Every path is absolute.
type serviceConfig struct {
	SchemaVersion    string             `json:"schema_version"`
	StateDir         string             `json:"state_dir"`
	EvidenceDir      string             `json:"evidence_dir"`
	MaxEvidenceBytes int64              `json:"max_evidence_bytes"`
	SamplingConfig   *string            `json:"sampling_config"`
	Enrollment       *serviceEnrollment `json:"enrollment"`
}

// loadServiceConfig strictly decodes one bounded configuration file.
func loadServiceConfig(path string) (serviceConfig, error) {
	var cfg serviceConfig
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("open service config")
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxServiceConfig+1))
	if err != nil || len(data) > maxServiceConfig {
		return cfg, errors.New("service config is unreadable or too large")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("service config: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return cfg, errors.New("service config has trailing data")
	}
	return cfg, cfg.validate()
}

func (c serviceConfig) validate() error {
	if c.SchemaVersion != serviceConfigSchema {
		return fmt.Errorf("service config schema must be %s", serviceConfigSchema)
	}
	paths := []string{c.StateDir, c.EvidenceDir}
	if c.SamplingConfig != nil {
		paths = append(paths, *c.SamplingConfig)
	}
	if e := c.Enrollment; e != nil {
		paths = append(paths, e.BootstrapFile)
		if e.CAFile != nil {
			paths = append(paths, *e.CAFile)
		}
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return errors.New("service config paths must be absolute")
		}
	}
	// The service deletes the bootstrap file and writes evidence; no other
	// path may name identity storage or anything inside it.
	for _, p := range paths[1:] {
		if within(c.StateDir, p) {
			return errors.New("service config paths must be outside state_dir")
		}
	}
	if c.MaxEvidenceBytes < minEvidenceCap || c.MaxEvidenceBytes > maxEvidenceCap {
		return fmt.Errorf("max_evidence_bytes must be from %d to %d", minEvidenceCap, maxEvidenceCap)
	}
	return nil
}

// within reports whether p is dir or inside it. filepath.Rel compares Windows
// paths case-insensitively.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// runServicePipeline runs until ctx ends or the pipeline fails. A clean stop
// returns nil after the sampling report is written.
func runServicePipeline(ctx context.Context, cfg serviceConfig, newScheduler func(telemetry.SamplingConfig) telemetry.Scheduler, logf func(string, ...any)) error {
	store, err := openIdentityStore(cfg.StateDir, cfg.Enrollment != nil)
	if err != nil {
		return err
	}
	defer store.close()
	receipt, err := admitService(ctx, store, cfg, logf)
	if err != nil {
		return err
	}
	logf("identity admitted: signing key %s, last receipt sequence %d", receipt.SigningKeyID, receipt.LastSequence)
	samplingPath := ""
	if cfg.SamplingConfig != nil {
		samplingPath = *cfg.SamplingConfig
	}
	sampling, err := loadSamplingConfig(samplingPath)
	if err != nil {
		return fmt.Errorf("invalid sampling config: %w", err)
	}
	sink, err := openEvidenceSink(cfg.EvidenceDir, cfg.MaxEvidenceBytes)
	if err != nil {
		return err
	}
	defer sink.close()
	if sink.repaired {
		logf("removed a torn final record from %s", evidenceLogFile)
	}
	unsigned := 0
	report, err := newScheduler(sampling).Run(ctx, func(sample telemetry.SensorSample) error {
		payload, err := telemetry.EndpointTelemetryV2(sample, receipt.DeviceID)
		if err != nil {
			// A snapshot with no known metric is not valid telemetry v2. It is
			// counted rather than padded; sampling continues.
			if unsigned++; unsigned == 1 {
				logf("snapshot without any known metric was not signed")
			}
			return nil
		}
		data, err := json.Marshal(payload)
		if err != nil {
			return errors.New("encode sampled telemetry")
		}
		envelope, err := store.signEvidence(data, time.Now())
		if err != nil {
			return fmt.Errorf("sign evidence: %w", err)
		}
		return sink.append(envelope)
	})
	if err != nil {
		return err
	}
	name := "sampling-report-" + report.EndedAt.Format("20060102T150405.000000000Z") + ".json"
	if err := writeSamplingReport(filepath.Join(cfg.EvidenceDir, name), report); err != nil {
		return err
	}
	logf("%s; %d snapshots, %d not signed, last sequence %d", budgetSummary(report), report.Emits, unsigned, sink.lastSequence)
	return nil
}

// admitService returns the stored admission, enrolling first when none exists
// and a bootstrap file was provisioned. The bootstrap file is deleted as soon
// as it is read: the token is one-use and must not stay on disk.
func admitService(ctx context.Context, store *identityStore, cfg serviceConfig, logf func(string, ...any)) (contracts.EnrollmentAcceptedV1, error) {
	_, statErr := store.root.Lstat(receiptFile)
	if statErr == nil {
		receipt, err := store.status()
		if err == nil && cfg.Enrollment != nil {
			removeBootstrap(cfg.Enrollment.BootstrapFile, logf, "identity is already admitted")
		}
		return receipt, err
	}
	if !errors.Is(statErr, os.ErrNotExist) {
		return contracts.EnrollmentAcceptedV1{}, errors.New("inspect admission receipt")
	}
	if cfg.Enrollment == nil {
		return contracts.EnrollmentAcceptedV1{}, errors.New("no admitted identity and no enrollment configured")
	}
	// Validate the local TLS configuration first, so a configuration mistake
	// does not consume the one-use credential.
	caFile := ""
	if cfg.Enrollment.CAFile != nil {
		caFile = *cfg.Enrollment.CAFile
	}
	client, origin, err := enrollmentClient(cfg.Enrollment.Origin, caFile)
	if err != nil {
		return contracts.EnrollmentAcceptedV1{}, err
	}
	defer client.CloseIdleConnections()
	f, err := os.Open(cfg.Enrollment.BootstrapFile)
	if err != nil {
		return contracts.EnrollmentAcceptedV1{}, errors.New("no admitted identity and no readable bootstrap file")
	}
	token, err := readBootstrap(f)
	f.Close()
	removeBootstrap(cfg.Enrollment.BootstrapFile, logf, "bootstrap read")
	if err != nil {
		return contracts.EnrollmentAcceptedV1{}, err
	}
	logf("enrolling with the provisioned bootstrap credential")
	return enroll(ctx, store, client, origin, token)
}

func removeBootstrap(path string, logf func(string, ...any), why string) {
	err := os.Remove(path)
	switch {
	case err == nil:
		logf("bootstrap file removed (%s)", why)
	case !errors.Is(err, os.ErrNotExist):
		logf("bootstrap file could not be removed (%s); remove it manually", why)
	}
}

// evidenceSink appends one signed envelope per line and syncs each line.
type evidenceSink struct {
	f            *os.File
	size, max    int64
	lastSequence uint64
	repaired     bool
}

// openEvidenceSink opens the evidence file for append. A final line without
// its newline is a record torn by a crash; it is truncated, leaving a
// sequence gap that CT04 allows.
func openEvidenceSink(dir string, max int64) (*evidenceSink, error) {
	f, err := os.OpenFile(filepath.Join(dir, evidenceLogFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, errors.New("open signed evidence file")
	}
	s := &evidenceSink{f: f, max: max}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, errors.New("inspect signed evidence file")
	}
	s.size = info.Size()
	if s.size > 0 {
		tail := make([]byte, min(s.size, maxTornTail))
		if _, err := f.ReadAt(tail, s.size-int64(len(tail))); err != nil {
			f.Close()
			return nil, errors.New("read signed evidence tail")
		}
		if tail[len(tail)-1] != '\n' {
			keep := int64(bytes.LastIndexByte(tail, '\n') + 1)
			if keep == 0 && s.size > int64(len(tail)) {
				f.Close()
				return nil, errors.New("signed evidence file ends in an unbounded torn record")
			}
			s.size -= int64(len(tail)) - keep
			if f.Truncate(s.size) != nil || f.Sync() != nil {
				f.Close()
				return nil, errors.New("truncate torn signed evidence record")
			}
			s.repaired = true
		}
	}
	if _, err := f.Seek(s.size, io.SeekStart); err != nil {
		f.Close()
		return nil, errors.New("seek signed evidence file")
	}
	return s, nil
}

func (s *evidenceSink) append(envelope contracts.EvidenceEnvelopeV1) error {
	line, err := json.Marshal(envelope)
	if err != nil {
		return errors.New("encode signed evidence")
	}
	line = append(line, '\n')
	if s.size+int64(len(line)) > s.max {
		return errEvidenceFull
	}
	if _, err := s.f.Write(line); err != nil {
		return errors.New("write signed evidence")
	}
	if err := s.f.Sync(); err != nil {
		return errors.New("sync signed evidence")
	}
	s.size += int64(len(line))
	s.lastSequence = envelope.Sequence
	return nil
}

func (s *evidenceSink) close() { s.f.Close() }

// serviceLog appends timestamped lines to service.log and stops at its cap.
// Messages are fixed text and public identifiers, never keys or tokens.
type serviceLog struct {
	path string
	mu   sync.Mutex
}

func (l *serviceLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || info.Size() >= maxServiceLogBytes {
		return
	}
	fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
}
