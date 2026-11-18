package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"github.com/i-got-this-faa/device-audit/packages/workflows"
	"golang.org/x/sys/windows"
)

const (
	probeMemoryLimit     = 64 << 20
	probeMemoryThreshold = 56 << 20
	probeCPULimit        = 5 * time.Second
)

func probeWorkerReady() bool {
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if windows.QueryInformationJobObject(0, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil) != nil {
		return false
	}
	const required = windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_TIME |
		windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	basic := limits.BasicLimitInformation
	return basic.LimitFlags&required == required && basic.ActiveProcessLimit == 1 &&
		limits.ProcessMemoryLimit > 0 && limits.ProcessMemoryLimit <= probeMemoryLimit &&
		basic.PerJobUserTimeLimit > 0 && basic.PerJobUserTimeLimit <= int64(probeCPULimit/(100*time.Nanosecond))
}

func executeProbeWorker(ctx context.Context, req workflows.Request) ([]byte, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, probeWorkerError("worker_image_unavailable")
	}
	return runWindowsProbeProcess(ctx, req, executable, []string{"--probe-worker"}, probeCPULimit, probeMemoryThreshold)
}

func runWindowsProbeProcess(ctx context.Context, req workflows.Request, executable string, args []string, cpu time.Duration, memoryThreshold uintptr) ([]byte, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, probeWorkerError("worker_isolation_unavailable")
	}
	defer windows.CloseHandle(job)
	port, err := windows.CreateIoCompletionPort(windows.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, probeWorkerError("worker_isolation_unavailable")
	}
	defer windows.CloseHandle(port)
	association := struct {
		Key  uintptr
		Port windows.Handle
	}{Key: 1, Port: port}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectAssociateCompletionPortInformation,
		uintptr(unsafe.Pointer(&association)), uint32(unsafe.Sizeof(association))); err != nil {
		return nil, probeWorkerError("worker_isolation_unavailable")
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | windows.JOB_OBJECT_LIMIT_JOB_TIME |
				windows.JOB_OBJECT_LIMIT_PROCESS_MEMORY | windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
			ActiveProcessLimit:  1,
			PerJobUserTimeLimit: int64(cpu / (100 * time.Nanosecond)),
		},
		ProcessMemoryLimit: probeMemoryLimit,
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, probeWorkerError("worker_isolation_unavailable")
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(childCtx, executable, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_NO_WINDOW | windows.BELOW_NORMAL_PRIORITY_CLASS}
	cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, probeWorkerError("worker_pipe_unavailable")
	}
	defer input.Close()
	// A small allowance is for the local failure wrapper, not evidence.
	output := &limitedProbeOutput{limit: int(req.Budget.MaxOutputBytes) + 512, cancel: cancel}
	cmd.Stdout = output
	cmd.WaitDelay = time.Second
	if cmd.Start() != nil {
		return nil, probeWorkerError("worker_start_failed")
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		cancel()
		_ = cmd.Wait()
		return nil, probeWorkerError("worker_isolation_unavailable")
	}
	// The worker cannot invoke a provider until it has read and validated
	// this request. Send it only after the kernel limits are in place.
	writeErr := json.NewEncoder(input).Encode(req)
	input.Close()
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	err, resource := waitForProbeJob(job, port, cpu, memoryThreshold, cancel, exited)
	if resource != "" {
		return nil, &workflows.Failure{Reason: workflows.ReasonBudgetExhausted, Detail: resource}
	}
	if output.exceeded {
		return nil, &workflows.Failure{Reason: workflows.ReasonBudgetExhausted, Detail: "output_budget"}
	}
	if result, _ := windows.WaitForSingleObject(job, 0); result == windows.WAIT_OBJECT_0 {
		return nil, &workflows.Failure{Reason: workflows.ReasonBudgetExhausted, Detail: "cpu_budget"}
	}
	if writeErr != nil {
		return nil, probeWorkerError("worker_pipe_failed")
	}
	data := bytes.TrimSuffix(output.data, []byte("\n"))
	if err == nil && json.Valid(data) {
		return data, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		var failure probeFailure
		if json.Unmarshal(data, &failure) == nil && failure.Schema == probeFailureSchema {
			return nil, &workflows.Failure{Reason: workflows.FailureReason(failure.Reason), Detail: failure.Detail, Partial: failure.PartialEvidence}
		}
	}
	return nil, probeWorkerError("worker_exited")
}

// The kernel enforces the hard ceilings. Poll accounting as Windows checks
// the CPU limit periodically, and use memory-limit notifications to report
// denied allocations. Peak committed memory also triggers termination independently of notifications.
func waitForProbeJob(job, port windows.Handle, cpu time.Duration, memoryThreshold uintptr, cancel context.CancelFunc, exited <-chan error) (error, string) {
	const processMemoryLimitMessage = 9
	for {
		var msg uint32
		var key uintptr
		var overlapped *windows.Overlapped
		if windows.GetQueuedCompletionStatus(port, &msg, &key, &overlapped, 50) == nil && memoryThreshold != 0 && key == 1 && msg == processMemoryLimitMessage {
			cancel()
			return <-exited, "memory_budget"
		}
		var memory windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		if memoryThreshold != 0 && windows.QueryInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&memory)), uint32(unsafe.Sizeof(memory)), nil) == nil &&
			memory.PeakProcessMemoryUsed >= memoryThreshold {
			cancel()
			return <-exited, "memory_budget"
		}
		var accounting struct {
			UserTime, KernelTime, PeriodUserTime, PeriodKernelTime           int64
			PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
		}
		if windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil) == nil &&
			accounting.UserTime+accounting.KernelTime >= int64(cpu/(100*time.Nanosecond)) {
			cancel()
			return <-exited, "cpu_budget"
		}
		select {
		case err := <-exited:
			// Drain events posted before process exit, including a denied
			// allocation the worker had time to handle.
			for windows.GetQueuedCompletionStatus(port, &msg, &key, &overlapped, 0) == nil {
				if memoryThreshold != 0 && key == 1 && msg == processMemoryLimitMessage {
					return err, "memory_budget"
				}
			}
			return err, ""
		default:
		}
	}
}

func probeWorkerError(detail string) *workflows.Failure {
	return &workflows.Failure{Reason: workflows.ReasonProbeError, Detail: detail}
}

type limitedProbeOutput struct {
	data     []byte
	limit    int
	exceeded bool
	cancel   context.CancelFunc
}

func (w *limitedProbeOutput) Write(p []byte) (int, error) {
	if len(p) > w.limit-len(w.data) {
		w.exceeded = true
		w.cancel()
		return 0, errors.New("probe worker output limit reached")
	}
	w.data = append(w.data, p...)
	return len(p), nil
}
