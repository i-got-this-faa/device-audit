package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"github.com/i-got-this-faa/device-audit/packages/workflows"
)

// TEL02 #26: the Windows service host for the real collector pipeline.
//
// The service loads the admitted identity, runs the TEL08 sampling schedule,
// signs each snapshot with the CT04 sequence and queues it for delivery.

const (
	serviceConfigSchema = "device-audit.endpoint-service.v1"
	// serviceName is the installed service and the per-service SID name.
	serviceName        = "DeviceAuditEndpoint"
	serviceLogFile     = "service.log"
	maxServiceConfig   = 16 << 10
	maxServiceLogBytes = 1 << 20
	minEvidenceCap     = 1 << 20
	maxEvidenceCap     = 1 << 30
)

// serviceEnrollment is the one-time first-start enrollment. The bootstrap file
// holds a one-use bootstrap-token.v1 document and is deleted once read.
type serviceEnrollment struct {
	Origin        string  `json:"origin"`
	CAFile        *string `json:"ca_file"`
	BootstrapFile string  `json:"bootstrap_file"`
}

// serviceConfig is device-audit.endpoint-service.v1. Every path is absolute.
type serviceConfig struct {
	SchemaVersion      string             `json:"schema_version"`
	StateDir           string             `json:"state_dir"`
	EvidenceDir        string             `json:"evidence_dir"`
	MaxEvidenceBytes   int64              `json:"max_evidence_bytes"`
	MaxEvidenceRecords int                `json:"max_evidence_records,omitempty"`
	SamplingConfig     *string            `json:"sampling_config"`
	Enrollment         *serviceEnrollment `json:"enrollment"`
	Delivery           *deliveryConfig    `json:"delivery,omitempty"`
	Inference          *inferenceConfig   `json:"inference,omitempty"`
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
	if d := c.Delivery; d != nil {
		if _, err := contracts.NetworkPublicKeyV1(d.MeshServerKey); err != nil {
			return errors.New("delivery requires a valid mesh_server_key")
		}
		paths = append(paths, d.DERPRegionFile, d.ControllerAckKeyFile)
		if d.DiagnosticControllerKeyFile != "" {
			if within(c.EvidenceDir, d.DiagnosticControllerKeyFile) {
				return errors.New("diagnostic controller key must be outside the writable evidence directory")
			}
			paths = append(paths, d.DiagnosticControllerKeyFile)
		}
	}
	if c.Inference != nil {
		for _, p := range c.Inference.paths() {
			if within(c.EvidenceDir, p) {
				return errors.New("inference configuration must be outside the writable evidence directory")
			}
			paths = append(paths, p)
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
	if c.MaxEvidenceRecords < 0 || c.MaxEvidenceRecords > maxSpoolRecords {
		return fmt.Errorf("max_evidence_records must be between 1 and %d, or omitted for the default", maxSpoolRecords)
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
	return runServicePipelineWithInference(ctx, cfg, newScheduler, logf, executeInferenceWorker)
}

func runServicePipelineWithInference(ctx context.Context, cfg serviceConfig, newScheduler func(telemetry.SamplingConfig) telemetry.Scheduler, logf func(string, ...any), runInference inferenceRunner) error {
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
	i, err := store.load(false)
	if err != nil {
		return err
	}
	sink, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, i.signing.Public().(ed25519.PublicKey), receipt)
	if err != nil {
		return err
	}
	defer sink.close()
	if sink.recoveredTail {
		logf("preserved torn legacy evidence in %s", spoolLegacyTail)
	}
	var sequenceMu sync.Mutex
	var diagnostics *diagnosticDelivery
	if cfg.Delivery != nil && cfg.Delivery.DiagnosticControllerKeyFile != "" {
		key, err := loadControllerPublicKey(cfg.Delivery.DiagnosticControllerKeyFile)
		if err != nil {
			return fmt.Errorf("configure diagnostic assignment authority: %w", err)
		}
		boot, err := diagnosticBootID()
		if err != nil {
			return err
		}
		diagnostics = &diagnosticDelivery{
			store: store, identity: i, receipt: receipt, authority: key, bootID: boot,
			runner: workflows.NewProbeRunner(executeProbeWorker), sequenceMu: &sequenceMu,
		}
	} else if cfg.Delivery != nil {
		if err := store.requireNoDiagnosticJob(); err != nil {
			return err
		}
	}
	var wake chan struct{}
	var deliveryDone chan error
	ctx, stopDelivery := context.WithCancel(ctx)
	defer stopDelivery()
	if cfg.Delivery != nil {
		sender, err := cfg.Delivery.sender(store, i)
		if err != nil {
			return fmt.Errorf("configure spool delivery: %w", err)
		}
		wake = make(chan struct{}, 1)
		deliveryDone = make(chan error, 1)
		go func() {
			var err error
			if diagnostics != nil {
				diagnostics.transport = sender
				err = diagnostics.run(ctx, sink, sender.controllerKey, sender.send, wake, logf)
			} else {
				err = drainEvidence(ctx, sink, sender.controllerKey, sender.send, wake, logf)
			}
			sender.close()
			if errors.Is(err, errDeliveryBlocked) {
				logf("spool delivery stopped: %v", err)
				err = nil
			} else if err != nil {
				stopDelivery()
			}
			deliveryDone <- err
		}()
	}
	inference := startServiceInference(ctx, cfg.Inference, runInference, logf)
	defer inference.close()
	unsigned, overflow := 0, 0
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
		sequenceMu.Lock()
		envelope, err := store.signEvidence(data, time.Now())
		if err != nil {
			sequenceMu.Unlock()
			return fmt.Errorf("sign evidence: %w", err)
		}
		err = sink.append(envelope)
		sequenceMu.Unlock()
		if errors.Is(err, errEvidenceFull) {
			if overflow++; overflow == 1 {
				logf("%s", errEvidenceFull)
			}
			return nil
		} else if err != nil {
			return err
		}
		inference.observe(payload, envelope.PayloadSHA256, time.Now())
		select {
		case wake <- struct{}{}:
		default:
		}
		return nil
	})
	if deliveryDone != nil {
		// Join the worker before closing the spool or reading the final mark.
		stopDelivery()
		err = errors.Join(err, <-deliveryDone)
	}
	if err != nil {
		if overflow > 0 {
			logf("%d snapshots rejected by spool before sampling failed", overflow)
		}
		return err
	}
	logf("%s; %d snapshots, %d not signed, %d rejected by spool, last spool sequence %d", budgetSummary(report), report.Emits, unsigned, overflow, sink.lastSequence())
	name := "sampling-report-" + report.EndedAt.Format("20060102T150405.000000000Z") + ".json"
	return writeSamplingReport(filepath.Join(cfg.EvidenceDir, name), report)
}

// admitService returns the stored admission, enrolling first when none exists
// and a bootstrap file was provisioned. The one-use bootstrap file is deleted
// once admission is confirmed, or at once when it is invalid or expired; after
// a failed enrollment it stays in its protected directory for the retry.
func admitService(ctx context.Context, store *identityStore, cfg serviceConfig, logf func(string, ...any)) (contracts.EnrollmentAcceptedV1, error) {
	_, statErr := store.root.Lstat(receiptFile)
	if statErr == nil {
		receipt, err := store.status()
		if err == nil && cfg.Enrollment != nil {
			removeBootstrap(cfg.Enrollment.BootstrapFile, cfg.StateDir, logf, "identity is already admitted")
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
	if err != nil {
		// Invalid or expired: it can never be redeemed.
		removeBootstrap(cfg.Enrollment.BootstrapFile, cfg.StateDir, logf, "bootstrap unusable")
		return contracts.EnrollmentAcceptedV1{}, err
	}
	logf("enrolling with the provisioned bootstrap credential")
	receipt, err := enroll(ctx, store, client, origin, token)
	if err != nil {
		// A failure before redemption, such as an unreachable controller, must
		// stay retryable after an SCM restart. A consumed token is rejected by
		// the controller, and the token expires on its own.
		logf("bootstrap file kept for retry after a failed enrollment")
		return receipt, err
	}
	removeBootstrap(cfg.Enrollment.BootstrapFile, cfg.StateDir, logf, "identity admitted")
	return receipt, nil
}

// removeBootstrap deletes the bootstrap file unless its directory is identity
// storage under another name, such as a junction to state_dir. Identity
// storage has no subdirectories, so comparing the parent directory by file
// identity covers every alias.
func removeBootstrap(path, stateDir string, logf func(string, ...any), why string) {
	parent, perr := os.Stat(filepath.Dir(path))
	state, serr := os.Stat(stateDir)
	if perr != nil || serr != nil || os.SameFile(parent, state) {
		logf("bootstrap file not removed (%s): its directory is identity storage or unreadable", why)
		return
	}
	err := os.Remove(path)
	switch {
	case err == nil:
		logf("bootstrap file removed (%s)", why)
	case !errors.Is(err, os.ErrNotExist):
		logf("bootstrap file could not be removed (%s); remove it manually", why)
	}
}

// serviceLog keeps the active log and one previous log.
// Messages are fixed text and public identifiers, never keys or tokens.
type serviceLog struct {
	path string
	mu   sync.Mutex
}

func (l *serviceLog) printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	line := fmt.Sprintf("%s %s\n", time.Now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	if len(line) > maxServiceLogBytes {
		return
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return
	}
	if info.Size() > maxServiceLogBytes-int64(len(line)) {
		if f.Close() != nil || os.Rename(l.path, l.path+".previous") != nil {
			return
		}
		f, err = os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
		if err != nil {
			return
		}
	}
	defer f.Close()
	f.WriteString(line)
}
