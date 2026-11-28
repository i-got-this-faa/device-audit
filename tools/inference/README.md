# Windows inference budget evidence, ML08 #104

The Windows service launches a fresh worker at most once per hour. It assigns
the worker to a Windows job before providing the inference request. The job
limits the child to one process, 64 MiB of committed memory, and 250 ms of
user CPU time. The parent monitors user plus kernel CPU time and the 64 MiB
peak working-set budget while the worker runs and checks both again at exit.
An inference that exceeds 1 s is discarded and a child that reaches the 2 s
timeout is terminated. The service
logs the budget category and emits `unknown` with `model_unavailable`.
Telemetry sampling has its own goroutine and the next inference starts a new
worker. Windows CI injects CPU load, an allocation that exceeds the job cap,
a hang and a crash. The test uses the production launcher and a test-only
child mode, then launches a fresh child to score a complete fixture.

## Physical-host fault verification

On the selected HP Victus (Ryzen 5 5600H, 12 logical processors, Windows
11 build 26200, Go 1.27.4), the original worker launch failed with Windows
error 1314 under the interactive account. Replacing the privileged job
working-set setting with parent monitoring let the same account run both
tests below. The subprocess test rejected a hang, memory pressure, CPU
pressure and a crash as `unknown`/`model_unavailable`, then recovered in a
fresh worker. Separately, the service pipeline test continued writing signed
telemetry after an injected worker failure.

```powershell
go test -count=1 -v -run '^TestInference' ./apps/endpoint-agent
```

## Physical run

Run from the repository checkout with PowerShell 7, Go and Python on the
selected physical HP Victus. Leave it awake on AC throughout the run. Pass one
local JSON request containing `config` and `features`. The former is the
inference object described in the [agent guide](../../apps/endpoint-agent/README.md#isolated-inference-worker-ml03-34).
The latter is a complete, reviewed CT03 feature vector with no device
identifiers. Use an approved signed artifact and a matching passing evaluation
report. Archive the exact commit, artifact and input digest with the result.

```powershell
pwsh -File tools/inference/Measure-InferenceBudget.ps1 `
  -Request .\artifacts\inference-request.json `
  -Report .\artifacts\inference-resource-report.json `
  -AttestPhysicalVictus
go test -count=1 -v -run '^TestInferenceSubprocess$' ./apps/endpoint-agent
```

The command refuses a mismatched host attestation. It starts the real Windows
sensor scheduler at 60-second source and emission cadences, then runs 30
worker processes at least one hour apart. Allow at least 29 hours. It records
each attempt, CPU (user plus kernel), Windows peak working set, wall latency,
nearest-rank p95, minimum prediction interval and the largest gap beyond the
60-second start interval for any configured source. Missed sweeps count
toward that gap. After the final worker, it waits for another telemetry
sweep before stopping the scheduler. It writes an ML05 resource report
and runs the existing resource gate. The harness runs from the caller's
Windows account, so capture service-token evidence separately if making a
LocalService qualification claim. The hosted CI job and a run without the
physical attestation are development evidence.

The current archive model failed ML05, and telemetry v2 provides no SMART
input for this model. Physical-host measurements using a reviewed complete
input and an eligible signed model remain pending. Keep the issue open until
that evidence is recorded. This implementation does not qualify endpoint
prediction for release.
