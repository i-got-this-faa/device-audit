//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

type runConfig struct {
	Role       string `json:"role"`
	RepoRoot   string `json:"repo_root"`
	OutputDir  string `json:"output_dir"`
	Pwsh       string `json:"pwsh"`
	Samples    int    `json:"samples"`
	Iterations int    `json:"iterations"`
	Baseline   string `json:"baseline"`
	HostRole   string `json:"host_role"`
	Service    string `json:"service"`
}

type runStatus struct {
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Finished string `json:"finished_at"`
}

type serviceHandler struct {
	configPath string
}

func (h *serviceHandler) Execute(args []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- executeConfig(ctx, h.configPath) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			if err != nil {
				return false, 1
			}
			return false, 0
		case request := <-requests:
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				cancel()
				status <- svc.Status{State: svc.StopPending}
			case svc.Interrogate:
				status <- request.CurrentStatus
			}
		}
	}
}

func executeConfig(ctx context.Context, path string) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg runConfig
	if err := json.Unmarshal(encoded, &cfg); err != nil {
		return err
	}
	baseline, err := time.ParseDuration(cfg.Baseline)
	if err != nil {
		return err
	}
	plan := Plan{
		Role: cfg.Role, RepoRoot: cfg.RepoRoot, OutputDir: cfg.OutputDir, Pwsh: cfg.Pwsh,
		Samples: cfg.Samples, Iterations: cfg.Iterations, Baseline: baseline, HostRole: cfg.HostRole,
	}
	measurements, err := plan.Measurements()
	if err != nil {
		return writeStatus(cfg.OutputDir, err)
	}
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		return err
	}
	logPath := filepath.Join(cfg.OutputDir, "service.log")
	if err := writeAttestation(filepath.Join(cfg.OutputDir, "attestation.json"), cfg.Service, computerName(), cfg.Pwsh); err != nil {
		return writeStatus(cfg.OutputDir, err)
	}
	appendLog(logPath, "attestation written")
	for _, measurement := range measurements {
		if err := ctx.Err(); err != nil {
			return writeStatus(cfg.OutputDir, err)
		}
		appendLog(logPath, "start "+measurement.Name)
		cmd := exec.CommandContext(ctx, measurement.File, measurement.Args...)
		cmd.Dir = cfg.RepoRoot
		cmd.Env = commandEnv(cfg.OutputDir)
		logger := newLineLog(logPath, computerName())
		cmd.Stdout = logger
		cmd.Stderr = logger
		runErr := cmd.Run()
		logger.flush()
		if runErr != nil {
			return writeStatus(cfg.OutputDir, fmt.Errorf("%s: %w", measurement.Name, runErr))
		}
		appendLog(logPath, "finish "+measurement.Name)
	}
	return writeStatus(cfg.OutputDir, nil)
}

func writeStatus(dir string, runErr error) error {
	status := runStatus{OK: runErr == nil, Finished: time.Now().UTC().Format(time.RFC3339)}
	if runErr != nil {
		status.Error = RedactEvidence(runErr.Error(), computerName())
	}
	encoded, err := json.MarshalIndent(status, "", "  ")
	if err != nil {
		return err
	}
	if dir != "" {
		_ = os.MkdirAll(dir, 0o755)
		_ = os.WriteFile(filepath.Join(dir, "status.json"), append(encoded, '\n'), 0o644)
	}
	return runErr
}

func commandEnv(output string) []string {
	env := make([]string, 0, len(os.Environ())+2)
	for _, item := range os.Environ() {
		upper := strings.ToUpper(item)
		if strings.HasPrefix(upper, "TEMP=") || strings.HasPrefix(upper, "TMP=") {
			continue
		}
		env = append(env, item)
	}
	return append(env, "TEMP="+output, "TMP="+output)
}

type lineLog struct {
	path string
	host string
	mu   sync.Mutex
	buf  []byte
}

func newLineLog(path, host string) *lineLog { return &lineLog{path: path, host: host} }

func (l *lineLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf = append(l.buf, p...)
	for {
		i := bytes.IndexByte(l.buf, '\n')
		if i < 0 {
			break
		}
		appendLog(l.path, RedactEvidence(string(l.buf[:i]), l.host))
		l.buf = l.buf[i+1:]
	}
	return len(p), nil
}

func (l *lineLog) flush() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(bytes.TrimSpace(l.buf)) > 0 {
		appendLog(l.path, RedactEvidence(string(l.buf), l.host))
	}
	l.buf = nil
}

func appendLog(path, text string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer file.Close()
	_, _ = fmt.Fprintf(file, "%s %s\n", time.Now().UTC().Format(time.RFC3339), text)
}
