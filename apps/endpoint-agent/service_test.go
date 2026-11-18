package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
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
	data, err := os.ReadFile(filepath.Join(dir, evidenceLogFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	var out []contracts.EvidenceEnvelopeV1
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, maxTornTail)
	for scanner.Scan() {
		out = append(out, verifyEnvelope(t, i, receipt, scanner.Bytes()))
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
	server, caFile, requests := fixtureEnrollmentServer(t)
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
}

// A torn final record from a crash is truncated; a full file stops the
// pipeline instead of dropping evidence.
func TestEvidenceSinkTornTailAndCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, evidenceLogFile)
	if err := os.WriteFile(path, []byte("{\"sequence\":2}\n{\"seq"), 0o600); err != nil {
		t.Fatal(err)
	}
	sink, err := openEvidenceSink(dir, 200)
	if err != nil || !sink.repaired || sink.size != int64(len("{\"sequence\":2}\n")) {
		t.Fatalf("torn tail: %v %+v", err, sink)
	}
	envelope := contracts.EvidenceEnvelopeV1{PayloadBase64: strings.Repeat("A", 300)}
	if err := sink.append(envelope); !errors.Is(err, errEvidenceFull) {
		t.Fatalf("over cap = %v", err)
	}
	sink.close()
	data, _ := os.ReadFile(path)
	if string(data) != "{\"sequence\":2}\n" {
		t.Fatalf("file after cap = %q", data)
	}
}
