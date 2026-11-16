package main

import (
	"strings"
	"testing"
	"time"
)

func TestMeasurementsAreFixed(t *testing.T) {
	plan := Plan{
		Role: "local_service", RepoRoot: `C:\repo`, OutputDir: `C:\out`,
		Pwsh: `C:\Program Files\PowerShell\7\pwsh.exe`, Samples: 30,
		Iterations: 200000, Baseline: 2 * time.Second, HostRole: HostedRunnerRole,
	}
	got, err := plan.Measurements()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("commands = %d", len(got))
	}
	if !strings.Contains(strings.Join(got[0].Args, " "), "Measure-WindowsSensors.ps1") || !containsArg(got[0].Args, "15") || !containsArg(got[0].Args, "30") {
		t.Fatalf("sensor 15 = %#v", got[0])
	}
	if !containsArg(got[1].Args, "60") || !strings.HasSuffix(got[1].Args[len(got[1].Args)-1], "sensors-60s.json") && !containsArg(got[1].Args, "60") {
		t.Fatalf("sensor 60 = %#v", got[1])
	}
	if got[2].File != `C:\repo\bin\collectorbudget.exe` || !containsArg(got[2].Args, "15s") || !containsArg(got[2].Args, "planned") {
		t.Fatalf("harness 15 = %#v", got[2])
	}
	if !containsArg(got[3].Args, "60s") {
		t.Fatalf("harness 60 = %#v", got[3])
	}
	plan.Pwsh = `C:\Windows\System32\cmd.exe`
	if _, err := plan.Measurements(); err == nil {
		t.Fatal("an arbitrary executable was accepted as pwsh")
	}
	plan.Pwsh = `C:\Program Files\PowerShell\7\pwsh.exe`
	plan.HostRole = "physical"
	if _, err := plan.Measurements(); err == nil {
		t.Fatal("a physical host role was accepted")
	}
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want || strings.HasSuffix(arg, want) {
			return true
		}
	}
	return false
}
