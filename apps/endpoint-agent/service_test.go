package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/contracts"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// testServiceConfig samples cpu and memory every 5 s and emits every 5 s.
func testServiceConfig(t *testing.T, stateDir string) serviceConfig {
	t.Helper()
	dir := t.TempDir()
	sampling := filepath.Join(dir, "sampling.json")
	writeJSON(t, sampling, map[string]any{
		"schema_version": telemetry.SamplingConfigSchema, "emit_interval": "5s",
		"budget":  map[string]any{"max_cpu_percent_one_core": 100, "max_rss_bytes": telemetry.MaxSamplingRSSBytes},
		"sources": []map[string]string{{"source": telemetry.SensorCPU, "interval": "5s", "deadline": "2s"}, {"source": telemetry.SensorMemory, "interval": "5s", "deadline": "2s"}},
	})
	evidence := filepath.Join(dir, "evidence")
	if err := os.Mkdir(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	makeTestEvidencePrivate(t, evidence)
	return serviceConfig{SchemaVersion: serviceConfigSchema, StateDir: stateDir, EvidenceDir: evidence, MaxEvidenceBytes: minEvidenceCap, SamplingConfig: &sampling}
}

// cpuSource schedules a cpu source that returns 75 % unless broken is set, or
// hangs when hang is set, beside a healthy memory source. Without a healthy
// source a broken snapshot has no known metric and is rightly not signed.
func cpuSource(broken *atomic.Bool, hang bool) func(telemetry.SamplingConfig) telemetry.Scheduler {
	specs := map[string]telemetry.SensorSource{}
	for _, s := range telemetry.SensorSourceSpecs() {
		specs[s.Name] = s
	}
	cpu, memory := specs[telemetry.SensorCPU], specs[telemetry.SensorMemory]
	cpu.Read = func(ctx context.Context) ([]telemetry.SensorReading, error) {
		if hang {
			select {} // a provider stuck in a system call that ignores ctx
		}
		if broken.Load() {
			return nil, errors.New("provider failed")
		}
		return telemetry.CPUReadings(telemetry.SystemTimes{}, telemetry.SystemTimes{Idle: 50, Kernel: 100, User: 100})
	}
	memory.Read = func(context.Context) ([]telemetry.SensorReading, error) { return telemetry.MemoryReadings(100, 40) }
	return func(cfg telemetry.SamplingConfig) telemetry.Scheduler {
		return telemetry.Scheduler{Config: cfg, Sources: []telemetry.SensorSource{cpu, memory}}
	}
}

func readEnvelopes(t *testing.T, i *identity, receipt contracts.EnrollmentAcceptedV1, dir string) []contracts.EvidenceEnvelopeV1 {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "spool-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var out []contracts.EvidenceEnvelopeV1
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, verifyEnvelope(t, i, receipt, data))
	}
	return out
}

func cpuValue(t *testing.T, envelope contracts.EvidenceEnvelopeV1) *float64 {
	t.Helper()
	payload, err := base64.StdEncoding.DecodeString(envelope.PayloadBase64)
	if err != nil {
		t.Fatal(err)
	}
	var telemetryV2 contracts.TelemetryV2
	if err := json.Unmarshal(payload, &telemetryV2); err != nil {
		t.Fatal(err)
	}
	m := telemetryV2.Metrics.CPUUtilization
	if m == nil || (m.Value == nil && m.MissingReason == "") {
		t.Fatal("cpu metric is neither known nor explained")
	}
	return m.Value
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The pipeline signs every snapshot with the admitted identity, keeps
// sampling through a collector failure, stops cleanly on cancellation and
// continues the same identity and sequence after a restart.
func TestServicePipelineRecoversAndRestarts(t *testing.T) {
	s, stateDir, i, receipt := admittedStore(t)
	s.close()
	cfg := testServiceConfig(t, stateDir)
	var broken atomic.Bool
	broken.Store(true)
	var log bytes.Buffer
	logf := func(format string, args ...any) { log.WriteString(format + "\n") }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runServicePipeline(ctx, cfg, cpuSource(&broken, false), logf) }()
	waitFor(t, "a signed snapshot", 20*time.Second, func() bool { return len(readEnvelopes(t, i, receipt, cfg.EvidenceDir)) > 0 })
	if v := cpuValue(t, readEnvelopes(t, i, receipt, cfg.EvidenceDir)[0]); v != nil {
		t.Fatal("a failed collector produced a value")
	}
	broken.Store(false)
	waitFor(t, "sampling to recover", 20*time.Second, func() bool {
		envelopes := readEnvelopes(t, i, receipt, cfg.EvidenceDir)
		return cpuValue(t, envelopes[len(envelopes)-1]) != nil
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("pipeline did not stop after cancellation")
	}
	reports, _ := filepath.Glob(filepath.Join(cfg.EvidenceDir, "sampling-report-*.json"))
	if len(reports) != 1 {
		t.Fatalf("sampling reports = %v", reports)
	}
	first := readEnvelopes(t, i, receipt, cfg.EvidenceDir)

	// Restart: the same stored identity, a sequence above every earlier one.
	ctx, cancel = context.WithCancel(context.Background())
	go func() { done <- runServicePipeline(ctx, cfg, cpuSource(&broken, false), logf) }()
	waitFor(t, "a snapshot after restart", 20*time.Second, func() bool { return len(readEnvelopes(t, i, receipt, cfg.EvidenceDir)) > len(first) })
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	all := readEnvelopes(t, i, receipt, cfg.EvidenceDir)
	for n := 1; n < len(all); n++ {
		if all[n].Sequence <= all[n-1].Sequence {
			t.Fatalf("sequence did not increase: %d then %d", all[n-1].Sequence, all[n].Sequence)
		}
	}
	if strings.Contains(log.String(), "enrolling") {
		t.Fatal("an admitted identity was enrolled again")
	}
}

func TestServiceSpoolOverflowMatchesSignedSequenceGap(t *testing.T) {
	const retained, rejected = 3, 2
	for _, tc := range []struct {
		name       string
		maxRecords int
		freeBytes  int64
	}{
		{name: "records", maxRecords: retained},
		{name: "exact_bytes"},
		{name: "one_byte_remaining", freeBytes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, stateDir, identity, receipt := admittedStore(t)
			t.Cleanup(store.close)
			cfg := testServiceConfig(t, stateDir)
			cfg.MaxEvidenceRecords = tc.maxRecords
			deviceKey := identity.signing.Public().(ed25519.PublicKey)
			openSpool := func() *evidenceSpool {
				t.Helper()
				spool, err := openEvidenceSpool(cfg.EvidenceDir, cfg.MaxEvidenceBytes, cfg.MaxEvidenceRecords, deviceKey, receipt)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(spool.close)
				return spool
			}
			spool := openSpool()
			var original [][]byte
			var first, last contracts.EvidenceEnvelopeV1
			for n := range retained {
				envelope, err := store.signEvidence(testPayload(receipt.DeviceID), time.Now())
				if err != nil {
					t.Fatal(err)
				}
				record, err := json.Marshal(envelope)
				if err != nil {
					t.Fatal(err)
				}
				if tc.maxRecords == 0 {
					targetSize := cfg.MaxEvidenceBytes - tc.freeBytes
					size := targetSize / retained
					if n == retained-1 {
						size = targetSize - spool.size
					}
					record = append(record, bytes.Repeat([]byte(" "), int(size)-len(record)-1)...)
				}
				record = append(record, '\n')
				if err := spool.appendBytes(record, envelope.Sequence); err != nil {
					t.Fatal(err)
				}
				if n == 0 {
					first = envelope
				}
				last = envelope
				original = append(original, record)
			}
			initialSize := spool.size
			if tc.maxRecords == 0 && initialSize != cfg.MaxEvidenceBytes-tc.freeBytes {
				t.Fatalf("prefill left %d bytes free, want %d", cfg.MaxEvidenceBytes-initialSize, tc.freeBytes)
			}
			spool.close()
			store.close()

			log := &serviceLog{path: filepath.Join(cfg.EvidenceDir, serviceLogFile)}
			previousLog := log.path + ".previous"
			if err := os.WriteFile(previousLog, []byte("older log\n"), 0600); err != nil {
				t.Fatal(err)
			}
			fullLog := bytes.Repeat([]byte("old log\n"), maxServiceLogBytes/len("old log\n"))
			if err := os.WriteFile(log.path, fullLog, 0600); err != nil {
				t.Fatal(err)
			}
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 11*time.Second)
				defer cancel()
				if err := runServicePipeline(ctx, cfg, cpuSource(new(atomic.Bool), false), log.printf); err != nil {
					t.Fatal(err)
				}
			})
			if previous, err := os.ReadFile(previousLog); err != nil || !bytes.Equal(previous, fullLog) {
				t.Fatalf("full log was not retained as the previous log: %v", err)
			}
			logs, err := os.ReadFile(log.path)
			if err != nil {
				t.Fatal(err)
			}
			summary := fmt.Sprintf("%d snapshots, 0 not signed, %d rejected by spool, last spool sequence %d", rejected, rejected, last.Sequence)
			if len(logs) > maxServiceLogBytes || !bytes.Contains(logs, []byte(summary)) {
				t.Fatalf("unexpected overflow accounting in rotated log: %s", logs)
			}

			spool = openSpool()
			if len(spool.queue) != retained || spool.size != initialSize {
				t.Fatalf("overflow changed spool usage: records=%d bytes=%d", len(spool.queue), spool.size)
			}
			for n, record := range spool.queue {
				data, envelope, err := spool.read(recordName(record.sequence))
				if err != nil || envelope.Sequence != first.Sequence+uint64(n) || !bytes.Equal(data, original[n]) {
					t.Fatalf("overflow changed retained envelope %d: %v", n, err)
				}
			}
			controller, key, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := spool.acknowledge(controller, spoolTestAck(t, key, first)); err != nil {
				t.Fatal(err)
			}
			spool.close()

			// A new pipeline run uses the durable sequence state after space
			// becomes available.
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer cancel()
				if err := runServicePipeline(ctx, cfg, cpuSource(new(atomic.Bool), false), func(string, ...any) {}); err != nil {
					t.Fatal(err)
				}
			})
			envelopes := readEnvelopes(t, identity, receipt, cfg.EvidenceDir)
			if len(envelopes) != retained {
				t.Fatalf("after restart retained %d envelopes, want %d", len(envelopes), retained)
			}
			if next := envelopes[len(envelopes)-1].Sequence; next != last.Sequence+rejected+1 {
				t.Fatalf("last retained sequence %d, next signed sequence %d, want %d missing sequences", last.Sequence, next, rejected)
			}
		})
	}
}

// A provider stuck in a system call cannot hold the service past Stop.
func TestServicePipelineStopsWithHungProvider(t *testing.T) {
	s, stateDir, _, _ := admittedStore(t)
	s.close()
	cfg := testServiceConfig(t, stateDir)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runServicePipeline(ctx, cfg, cpuSource(new(atomic.Bool), true), func(string, ...any) {})
	}()
	time.Sleep(time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("hung provider held the pipeline after cancellation")
	}
}

// First start enrolls from the bootstrap file and deletes it; without an
// admitted identity or a bootstrap file the service fails explicitly.
func TestServiceAdmission(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "private")
	cfg := testServiceConfig(t, stateDir)
	logf := func(string, ...any) {}
	if err := runServicePipeline(context.Background(), cfg, cpuSource(new(atomic.Bool), false), logf); err == nil {
		t.Fatal("started without an identity directory or enrollment")
	}
	server, caFile, requests, _ := fixtureEnrollmentServer(t)
	bootstrap := filepath.Join(t.TempDir(), "bootstrap.json")
	cfg.Enrollment = &serviceEnrollment{Origin: server.URL, CAFile: &caFile, BootstrapFile: bootstrap}
	if err := runServicePipeline(context.Background(), cfg, cpuSource(new(atomic.Bool), false), logf); err == nil || !strings.Contains(err.Error(), "bootstrap") {
		t.Fatalf("missing bootstrap = %v", err)
	}
	writeJSON(t, bootstrap, testToken())
	store, err := openIdentityStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	// A local TLS mistake is caught before the one-use credential is consumed.
	missingCA := filepath.Join(t.TempDir(), "absent.pem")
	broken := cfg
	broken.Enrollment = &serviceEnrollment{Origin: server.URL, CAFile: &missingCA, BootstrapFile: bootstrap}
	if _, err := admitService(context.Background(), store, broken, logf); err == nil {
		t.Fatal("enrolled with a missing CA file")
	}
	if _, err := os.Stat(bootstrap); err != nil {
		t.Fatal("a CA mistake consumed the bootstrap file")
	}
	// An unreachable controller fails before redemption; the credential stays
	// for the SCM retry, and the retry below enrolls with it.
	down, downCA, _, _ := fixtureEnrollmentServer(t)
	down.Close()
	offline := cfg
	offline.Enrollment = &serviceEnrollment{Origin: down.URL, CAFile: &downCA, BootstrapFile: bootstrap}
	if _, err := admitService(context.Background(), store, offline, logf); err == nil {
		t.Fatal("enrolled against a stopped controller")
	}
	if _, err := os.Stat(bootstrap); err != nil {
		t.Fatal("a transport failure consumed the bootstrap file")
	}
	receipt, err := admitService(context.Background(), store, cfg, logf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bootstrap); !errors.Is(err, os.ErrNotExist) || requests.Load() != 2 {
		t.Fatalf("bootstrap kept (%v) or wrong request count %d", err, requests.Load())
	}
	// A bootstrap dropped beside an admitted identity is removed, not redeemed.
	writeJSON(t, bootstrap, testToken())
	again, err := admitService(context.Background(), store, cfg, logf)
	store.close()
	if err != nil || again != receipt || requests.Load() != 2 {
		t.Fatalf("re-admission: %v, requests %d", err, requests.Load())
	}
	if _, err := os.Stat(bootstrap); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("unused bootstrap left on disk")
	}
}

// linkDir makes link another name for the target directory: a junction on
// Windows, which needs no privilege, and a symlink elsewhere.
func linkDir(t *testing.T, link, target string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
			t.Fatalf("mklink /J: %v %s", err, out)
		}
		return
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// A bootstrap path that reaches identity storage through a directory alias
// passes the textual config check, so cleanup must refuse it by file identity.
func TestBootstrapCleanupSparesIdentityAliases(t *testing.T) {
	s, stateDir, _, receipt := admittedStore(t)
	s.close()
	alias := filepath.Join(t.TempDir(), "alias")
	linkDir(t, alias, stateDir)
	cfg := testServiceConfig(t, stateDir)
	cfg.Enrollment = &serviceEnrollment{Origin: "https://controller.example.org", BootstrapFile: filepath.Join(alias, receiptFile)}
	if err := cfg.validate(); err != nil {
		t.Fatalf("alias path should reach the runtime check: %v", err)
	}
	store, err := openIdentityStore(stateDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	got, err := admitService(context.Background(), store, cfg, func(string, ...any) {})
	if err != nil || got != receipt {
		t.Fatalf("admission through alias config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDir, receiptFile)); err != nil {
		t.Fatal("bootstrap cleanup deleted the admission receipt through an alias")
	}
}

func TestServiceConfigIsStrict(t *testing.T) {
	cfg := testServiceConfig(t, filepath.Join(t.TempDir(), "private"))
	path := filepath.Join(t.TempDir(), "service.json")
	writeJSON(t, path, cfg)
	if _, err := loadServiceConfig(path); err != nil {
		t.Fatal(err)
	}
	valid, _ := os.ReadFile(path)
	for name, mutate := range map[string]func(string) string{
		"unknown key": func(s string) string { return strings.Replace(s, `{`, `{"command":"whoami",`, 1) },
		"wrong schema": func(s string) string {
			return strings.Replace(s, serviceConfigSchema, "device-audit.endpoint-service.v0", 1)
		},
		"relative path": func(s string) string { return strings.Replace(s, `"evidence_dir":"`, `"evidence_dir":"evidence`, 1) },
		"evidence cap": func(s string) string {
			return strings.Replace(s, `"max_evidence_bytes":1048576`, `"max_evidence_bytes":1024`, 1)
		},
		"trailing data": func(s string) string { return s + `{}` },
	} {
		mutated := mutate(string(valid))
		if mutated == string(valid) {
			t.Fatalf("%s: mutation did not apply", name)
		}
		if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadServiceConfig(path); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	// The bootstrap file is deleted after reading and evidence is written, so
	// neither may point into identity storage. Windows paths ignore case.
	inside := []string{filepath.Join(cfg.StateDir, receiptFile), cfg.StateDir}
	if runtime.GOOS == "windows" {
		inside = append(inside, strings.ToUpper(filepath.Join(cfg.StateDir, receiptFile)))
	}
	for _, p := range inside {
		bad := cfg
		bad.Enrollment = &serviceEnrollment{Origin: "https://controller.example.org", BootstrapFile: p}
		if bad.validate() == nil {
			t.Fatalf("bootstrap_file %s inside state_dir accepted", p)
		}
	}
	bad := cfg
	bad.EvidenceDir = filepath.Join(cfg.StateDir, "evidence")
	if bad.validate() == nil {
		t.Fatal("evidence_dir inside state_dir accepted")
	}
}
