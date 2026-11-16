package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// HostedRunnerRole is the only host label this service records.
	// A hosted VM does not satisfy the two-physical-machine gate.
	HostedRunnerRole = "github_hosted_windows_runner_not_physical_target"
)

// Plan is the fixed measurement set. It cannot carry an arbitrary command.
type Plan struct {
	Role       string
	RepoRoot   string
	OutputDir  string
	Pwsh       string
	Samples    int
	Iterations int
	Baseline   time.Duration
	HostRole   string
}

type measurement struct {
	Name string
	File string
	Args []string
}

func (p Plan) validate() error {
	switch p.Role {
	case "local_service", "denied":
	default:
		return fmt.Errorf("collectorservice: role must be local_service or denied")
	}
	if p.HostRole != HostedRunnerRole {
		return fmt.Errorf("collectorservice: host role must identify the hosted runner")
	}
	if p.RepoRoot == "" || p.OutputDir == "" || p.Pwsh == "" {
		return fmt.Errorf("collectorservice: repo, output directory and pwsh are required")
	}
	if windowsBase(p.Pwsh) != "pwsh.exe" {
		return fmt.Errorf("collectorservice: pwsh must be pwsh.exe")
	}
	if p.Samples < 1 || p.Samples > 30 {
		return fmt.Errorf("collectorservice: samples must be from 1 to 30")
	}
	if p.Iterations < 1 || p.Iterations > 50_000_000 {
		return fmt.Errorf("collectorservice: iterations are outside 1..50000000")
	}
	if p.Baseline <= 0 || p.Baseline > 30*time.Second {
		return fmt.Errorf("collectorservice: baseline must be from 1ns to 30s")
	}
	return nil
}

// Measurements returns the sensor probe and the synthetic harness at both
// candidate cadences. Paths are derived from the plan; none are caller commands.
func (p Plan) Measurements() ([]measurement, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	probe := windowsJoin(p.RepoRoot, "tools", "probes", "Measure-WindowsSensors.ps1")
	harness := windowsJoin(p.RepoRoot, "bin", "collectorbudget.exe")
	samples := strconv.Itoa(p.Samples)
	iterations := strconv.Itoa(p.Iterations)
	baseline := p.Baseline.String()
	sensor := func(interval int, file string) measurement {
		return measurement{
			Name: file,
			File: p.Pwsh,
			Args: []string{
				"-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", probe,
				"-OutputPath", windowsJoin(p.OutputDir, file),
				"-Samples", samples, "-IntervalSeconds", strconv.Itoa(interval),
			},
		}
	}
	synthetic := func(interval, file string) measurement {
		return measurement{
			Name: file,
			File: harness,
			Args: []string{
				"-output", windowsJoin(p.OutputDir, file),
				"-interval", interval, "-samples", samples, "-repeats", "1",
				"-baseline", baseline, "-iterations", iterations, "-token", "planned",
			},
		}
	}
	return []measurement{
		sensor(15, "sensors-15s.json"),
		sensor(60, "sensors-60s.json"),
		synthetic("15s", "harness-15s.json"),
		synthetic("60s", "harness-60s.json"),
	}, nil
}

func windowsBase(path string) string {
	path = strings.ReplaceAll(path, "/", `\`)
	if i := strings.LastIndex(path, `\`); i >= 0 {
		return path[i+1:]
	}
	return path
}

func windowsJoin(parts ...string) string {
	cleaned := make([]string, 0, len(parts))
	for i, part := range parts {
		part = strings.ReplaceAll(part, "/", `\`)
		if i > 0 {
			part = strings.Trim(part, `\`)
		}
		if part != "" {
			cleaned = append(cleaned, part)
		}
	}
	return strings.Join(cleaned, `\`)
}
