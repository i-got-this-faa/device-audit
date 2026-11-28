package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
)

func TestTrainingPowerPolicy(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  telemetry.PowerStatus
		allowed bool
	}{
		{"AC", telemetry.PowerStatus{ACLineStatus: 1, BatteryLifePercent: 20}, true},
		{"AC no battery", telemetry.PowerStatus{ACLineStatus: 1, BatteryFlag: 128, BatteryLifePercent: 255}, true},
		{"unplugged", telemetry.PowerStatus{ACLineStatus: 0, BatteryLifePercent: 99}, false},
		{"low", telemetry.PowerStatus{ACLineStatus: 1, BatteryLifePercent: 19}, false},
		{"critical", telemetry.PowerStatus{ACLineStatus: 1, BatteryFlag: 4, BatteryLifePercent: 30}, false},
		{"unknown charge", telemetry.PowerStatus{ACLineStatus: 1, BatteryLifePercent: 255}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trainingPowerAllowed(tc.status); got != tc.allowed {
				t.Fatalf("training allowed = %v, want %v", got, tc.allowed)
			}
		})
	}
}

func TestWindowsBudgetedTrainingWorker(t *testing.T) {
	if err := checkTrainingPower(); err != nil {
		t.Skipf("host power is ineligible: %v", err)
	}
	exe := filepath.Join(t.TempDir(), "endpoint-agent.exe")
	if output, err := exec.Command("go", "build", "-o", exe, ".").CombinedOutput(); err != nil {
		t.Fatalf("build endpoint: %v %s", err, output)
	}
	store, dir, _, receipt := admittedStore(t)
	store.close()
	_, key, data := budgetedTrainingFixture(t, time.Now().UTC().Truncate(time.Second), receipt)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	cfg := telemetry.DefaultSamplingConfig()
	cfg.EmitInterval = telemetry.Duration(5 * time.Second)
	scheduler := telemetry.NewScheduler(cfg)
	cpuRead := make(chan struct{}, 1)
	for i := range scheduler.Sources {
		if scheduler.Sources[i].Name != telemetry.SensorCPU {
			continue
		}
		read := scheduler.Sources[i].Read
		scheduler.Sources[i].Read = func(ctx context.Context) ([]telemetry.SensorReading, error) {
			select {
			case cpuRead <- struct{}{}:
			default:
			}
			return read(ctx)
		}
	}
	emitted := make(chan telemetry.SensorSample, 1)
	samplingDone := make(chan error, 1)
	go func() {
		_, err := scheduler.Run(ctx, func(sample telemetry.SensorSample) error {
			select {
			case emitted <- sample:
			default:
			}
			return nil
		})
		samplingDone <- err
	}()
	select {
	case <-cpuRead:
	case err := <-samplingDone:
		t.Fatalf("Windows sensor scheduler stopped before training: %v", err)
	case <-ctx.Done():
		t.Fatal("Windows sensor scheduler did not start")
	}
	report, err := stageFederatedTraining(ctx, dir, key, data, trainingExecution{
		now: time.Now, power: checkTrainingPower,
		fit: func(ctx context.Context, key string, data []byte) ([]byte, inferenceUsage, error) {
			return runWindowsTrainingWorker(ctx, exe, key, data)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.ElapsedMS <= 0 || report.ElapsedMS > float64(trainingTimeLimit.Milliseconds()) ||
		report.PeakWorkingSetBytes == 0 || report.PeakWorkingSetBytes > trainingMemoryLimit {
		t.Fatalf("worker accounting out of budget: %+v", report)
	}
	select {
	case sample := <-emitted:
		if _, err := telemetry.EndpointTelemetryV2(sample, "training-fixture"); err != nil {
			t.Fatalf("Windows sampling yielded no usable telemetry: %v", err)
		}
	case err := <-samplingDone:
		t.Fatalf("Windows sensor scheduler stopped without a snapshot: %v", err)
	case <-ctx.Done():
		t.Fatal("Windows sensor scheduler did not emit after training")
	}
	cancel()
	if err := <-samplingDone; err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture worker: %.3f ms wall, %.3f ms CPU, %d bytes peak working set", report.ElapsedMS, report.CPUTimeMS, report.PeakWorkingSetBytes)
}
