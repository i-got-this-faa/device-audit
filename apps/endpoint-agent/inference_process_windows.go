package main

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/i-got-this-faa/device-audit/packages/telemetry"
	"golang.org/x/sys/windows"
)

const inferenceMemoryLimit = 64 << 20
const inferenceCPULimit = 250 * time.Millisecond

func runInferenceChild(ctx context.Context, cmd *exec.Cmd, data []byte) (inferenceUsage, error) {
	var usage inferenceUsage
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return usage, err
	}
	defer windows.CloseHandle(job)
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return usage, err
	}
	defer windows.CloseHandle(port)
	association := struct {
		Key  uintptr
		Port windows.Handle
	}{Key: 1, Port: port}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&association)), uint32(unsafe.Sizeof(association))); err != nil {
		return usage, err
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_TIME |
				windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			ActiveProcessLimit: 1, PerJobUserTimeLimit: int64(inferenceCPULimit / (100 * time.Nanosecond)),
		},
		ProcessMemoryLimit: inferenceMemoryLimit,
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return usage, err
	}

	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW | windows.BELOW_NORMAL_PRIORITY_CLASS}
	cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		return usage, err
	}
	defer input.Close()
	if err := cmd.Start(); err != nil {
		return usage, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(cmd.Process.Pid))
	if err == nil {
		defer windows.CloseHandle(process)
		err = windows.AssignProcessToJobObject(job, process)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return usage, err
	}
	// The worker reads to EOF before loading any model or feature payload.
	_, writeErr := input.Write(data)
	input.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	// A job working-set limit requires a privilege the worker launcher may
	// lack. The kernel caps commit while the parent monitors resident memory.
	workingSetExceeded := func() bool {
		_, peak, err := telemetry.WindowsProcessWorkingSet(process)
		return err == nil && peak > inferenceMemoryLimit
	}
	childErr, breach := waitForProbeJob(job, port, inferenceCPULimit, inferenceMemoryLimit, workingSetExceeded, func() {
		_ = windows.TerminateJobObject(job, 1)
	}, exited)

	if signal, signalErr := windows.WaitForSingleObject(job, 0); breach == "" && childErr != nil && signalErr == nil && signal == windows.WAIT_OBJECT_0 {
		breach = "cpu_budget"
	}

	var creation, exit, kernel, user windows.Filetime
	timesErr := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user)
	ticks := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	usage.CPU = time.Duration(ticks(kernel)+ticks(user)) * 100 * time.Nanosecond
	_, usage.PeakRSS, err = telemetry.WindowsProcessWorkingSet(process)
	switch {
	case ctx.Err() != nil:
		return usage, ctx.Err()
	case breach == "cpu_budget":
		return usage, errInferenceCPU
	case breach == "memory_budget":
		return usage, errInferenceMemory
	case timesErr != nil || err != nil || usage.PeakRSS == 0:
		return usage, errors.New("inference worker accounting unavailable")
	case usage.CPU > inferenceCPULimit:
		return usage, errInferenceCPU
	case usage.PeakRSS > inferenceMemoryLimit:
		return usage, errInferenceMemory
	default:
		return usage, errors.Join(writeErr, childErr)
	}
}
