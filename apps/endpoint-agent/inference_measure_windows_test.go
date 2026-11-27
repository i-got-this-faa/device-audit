package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/health"
	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

const inferenceSweepCadence = time.Minute

type sweepStarts struct {
	mu       sync.Mutex
	previous map[string]time.Time
	count    map[string]int
	maxDelay time.Duration
}

func (s *sweepStarts) record(source string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if previous := s.previous[source]; !previous.IsZero() {
		s.maxDelay = max(s.maxDelay, at.Sub(previous)-inferenceSweepCadence)
	}
	s.previous[source] = at
	s.count[source]++
}

// snapshot includes sources that have stopped starting sweeps and returns
// independent counters because a provider may still run after cancellation.
func (s *sweepStarts) snapshot(at time.Time) (map[string]int, time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delay := s.maxDelay
	for _, previous := range s.previous {
		delay = max(delay, at.Sub(previous)-inferenceSweepCadence)
	}
	return maps.Clone(s.count), delay
}

func TestInferenceSweepSnapshot(t *testing.T) {
	starts := sweepStarts{previous: make(map[string]time.Time), count: make(map[string]int)}
	start := time.Now()
	starts.record("stalled", start)
	starts.record("stalled", start.Add(inferenceSweepCadence))
	starts.record("healthy", start)
	starts.record("healthy", start.Add(2*inferenceSweepCadence))
	counts, delay := starts.snapshot(start.Add(4 * inferenceSweepCadence))
	starts.record("stalled", start.Add(4*inferenceSweepCadence))
	if counts["stalled"] != 2 || counts["healthy"] != 2 || delay != 2*inferenceSweepCadence {
		t.Fatalf("counts=%v delay=%s", counts, delay)
	}
}

// TestMeasureInferenceWindows is an opt-in physical-host harness. It replays
// a caller-provided CT03 workload through the built agent while the real
// Windows providers run on their own 60-second sampling schedules.
func TestMeasureInferenceWindows(t *testing.T) {
	reportFile := os.Getenv("DEVICE_AUDIT_INFERENCE_REPORT")
	if reportFile == "" {
		t.Skip("use Measure-InferenceBudget.ps1")
	}
	var req inferenceRequest
	request, err := readInferenceFile(os.Getenv("DEVICE_AUDIT_INFERENCE_REQUEST"), 32<<10)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(request, &req); err != nil {
		t.Fatal(err)
	}
	var host struct {
		Physical          bool   `json:"physical"`
		CPUModel          string `json:"cpu_model"`
		LogicalProcessors int    `json:"logical_processors"`
		OSBuildFamily     int    `json:"os_build_family"`
		HardwareClass     string `json:"hardware_class"`
	}
	if err := json.Unmarshal([]byte(os.Getenv("DEVICE_AUDIT_INFERENCE_HOST")), &host); err != nil {
		t.Fatal(err)
	}
	if _, err := health.ModelInput(req.Features); err != nil {
		t.Fatalf("qualification requires a complete reviewed CT03 workload: %v", err)
	}
	manifest, artifact, _, err := loadInferenceBundle(req.Config)
	if err != nil {
		t.Fatalf("qualification requires an approved model bundle: %v", err)
	}
	artifactBytes := len(artifact)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	cfg := telemetry.DefaultSamplingConfig()
	cfg.EmitInterval = telemetry.Duration(inferenceSweepCadence)
	for i := range cfg.Sources {
		cfg.Sources[i].Interval = telemetry.Duration(inferenceSweepCadence)
	}
	scheduler := telemetry.NewScheduler(cfg)
	starts := sweepStarts{previous: make(map[string]time.Time), count: make(map[string]int)}
	sweeps := make(chan struct{}, 1)
	for i := range scheduler.Sources {
		src := &scheduler.Sources[i]
		read, name := src.Read, src.Name
		src.Read = func(ctx context.Context) ([]telemetry.SensorReading, error) {
			starts.record(name, time.Now())
			return read(ctx)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := scheduler.Run(ctx, func(telemetry.SensorSample) error {
			select {
			case sweeps <- struct{}{}:
			default:
			}
			return nil
		})
		done <- err
	}()

	const count = 30
	var latencies []float64
	var maxCPU time.Duration
	var peak uint64
	var failures []string
	var attempts []map[string]any
	var last time.Time
	minInterval := time.Duration(1<<63 - 1)
	executable := os.Getenv("DEVICE_AUDIT_INFERENCE_EXE")
	waitSweep := func() {
		t.Helper()
		select {
		case <-sweeps:
		case err := <-done:
			t.Fatalf("Windows sampling stopped early: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	waitSweep()
	for i := 0; i < count; i++ {
		if !last.IsZero() {
			timer := time.NewTimer(time.Until(last.Add(inferenceCadence)))
			select {
			case <-timer.C:
			case err := <-done:
				timer.Stop()
				t.Fatalf("Windows sampling stopped early: %v", err)
			case <-ctx.Done():
				timer.Stop()
				t.Fatal(ctx.Err())
			}
		}
		at := time.Now()
		if !last.IsZero() {
			minInterval = min(minInterval, at.Sub(last))
		}
		last = at
		result, usage, err := measureInferenceProcess(ctx, req, executable, "--inference-worker")
		ms := float64(usage.Latency) / float64(time.Millisecond)
		cpu := float64(usage.CPU) / float64(time.Millisecond)
		entry := map[string]any{"elapsed_ms": ms, "cpu_ms": cpu, "peak_working_set_bytes": usage.PeakRSS}
		if err != nil || result.Model == nil || usage.PeakRSS == 0 {
			reason := "prediction or accounting unavailable"
			if err != nil {
				reason = err.Error()
			}
			failures = append(failures, fmt.Sprintf("attempt %d: %s", i+1, reason))
			entry["failure"] = reason
		} else {
			entry["status"] = result.Health.Status
		}
		attempts = append(attempts, entry)
		latencies = append(latencies, ms)
		maxCPU = max(maxCPU, usage.CPU)
		peak = max(peak, usage.PeakRSS)
		t.Logf("measured attempt %d/%d", i+1, count)
	}
	// Discard any buffered notification so a post-inference sweep is observed.
	select {
	case <-sweeps:
	default:
	}
	waitSweep()
	counts, maxDelay := starts.snapshot(time.Now())
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	sort.Float64s(latencies)
	var maxSweepDelay any = float64(maxDelay) / float64(time.Millisecond)
	for _, schedule := range cfg.Sources {
		if counts[schedule.Source] < 2 {
			maxSweepDelay = nil
			break
		}
	}
	report := map[string]any{
		"schema_version": "device-audit.resource-report.v1", "budget": "endpoint_inference",
		"policy_sha256": inferencePolicy, "host": host, "artifact_bytes": artifactBytes,
		"artifact_sha256": manifest.ArtifactSHA256, "request_sha256": fmt.Sprintf("%x", sha256.Sum256(request)),
		"model_version": manifest.ModelVersion, "sweep_starts_by_source": counts,
		"go_version": telemetry.CurrentHost().GoVersion, "os_version": telemetry.CurrentHost().OSVersion,
		"predictions": count - len(failures), "attempts": attempts, "failures": failures,
		"prediction_interval_seconds": minInterval.Seconds(),
		"peak_working_set_bytes":      peak, "cpu_ms_per_prediction_max": float64(maxCPU) / float64(time.Millisecond),
		"latency_max_ms": latencies[len(latencies)-1], "latency_p95_ms": latencies[(95*len(latencies)+99)/100-1],
		"concurrent_sampling_cadence_seconds": int(inferenceSweepCadence.Seconds()),
		"max_sweep_start_delay_ms":            maxSweepDelay,
	}
	file, err := os.OpenFile(reportFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		t.Fatal(err)
	}
}
