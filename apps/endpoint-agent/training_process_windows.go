package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"time"
	"unsafe"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
	"golang.org/x/sys/windows"
)

const trainingMemoryLimit = 256 << 20

func checkTrainingPower() error {
	status, err := telemetry.WindowsPowerStatus()
	if err != nil {
		return err
	}
	if !trainingPowerAllowed(status) {
		return errors.New("training requires AC power and a battery above the low-power threshold")
	}
	return nil
}

func trainingPowerAllowed(status telemetry.PowerStatus) bool {
	const noBattery, lowOrCritical = 128, 2 | 4
	return status.ACLineStatus == 1 && status.BatteryFlag != 255 &&
		(status.BatteryFlag&noBattery != 0 ||
			(status.BatteryFlag&lowOrCritical == 0 && status.BatteryLifePercent >= 20 && status.BatteryLifePercent <= 100))
}

func runTrainingProcess(ctx context.Context, publisherKey string, request []byte) ([]byte, inferenceUsage, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, inferenceUsage{}, err
	}
	return runWindowsTrainingWorker(ctx, executable, publisherKey, request)
}

func runWindowsTrainingWorker(ctx context.Context, executable, publisherKey string, request []byte) ([]byte, inferenceUsage, error) {
	var usage inferenceUsage
	if err := checkTrainingPower(); err != nil {
		return nil, usage, err
	}
	current := windows.CurrentProcess()
	var allowed, system uintptr
	mask := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetProcessAffinityMask")
	if err := mask.Find(); err != nil {
		return nil, usage, err
	}
	ok, _, err := mask.Call(uintptr(current), uintptr(unsafe.Pointer(&allowed)), uintptr(unsafe.Pointer(&system)))
	if ok == 0 {
		return nil, usage, err
	}
	if allowed == 0 {
		return nil, usage, errors.New("no available logical processor for training")
	}
	affinity := allowed & -allowed
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	go func() {
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := checkTrainingPower(); err != nil {
					cancel(err)
					return
				}
			}
		}
	}()
	output := &limitedWorkerOutput{limit: 8 << 10, cancel: func() { cancel(errors.New("training result exceeds size limit")) }}
	errOutput := &limitedWorkerOutput{limit: 1024, cancel: func() { cancel(errors.New("training error exceeds size limit")) }}
	cmd := exec.CommandContext(ctx, executable, "--local-training-worker", "--training-publisher-key-file", publisherKey)
	cmd.Stdout, cmd.Stderr, cmd.WaitDelay = output, errOutput, 100*time.Millisecond
	start := time.Now()
	usage, err = runBudgetedWindowsChild(ctx, cmd, request, trainingTimeLimit, trainingMemoryLimit, affinity)
	usage.Latency = time.Since(start)
	if cause := context.Cause(ctx); cause != nil {
		return nil, usage, cause
	}
	if err != nil {
		if len(errOutput.data) != 0 && !errors.Is(err, errInferenceCPU) && !errors.Is(err, errInferenceMemory) {
			return nil, usage, errors.New(string(errOutput.data))
		}
		return nil, usage, err
	}
	if err := checkTrainingPower(); err != nil {
		return nil, usage, err
	}
	return output.data, usage, nil
}
