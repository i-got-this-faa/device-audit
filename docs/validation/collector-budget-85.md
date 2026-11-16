# Collector permissions and overhead, TEL04 #85

Status on 16 November 2026: **permission gate, cadence scheduler and synthetic
sampler measurements are recorded; physical Windows qualification is still open**.
No production cadence or resource budget is approved. The harness records below
are measurements of this process on a Linux development host. They are not
Windows sensor readings, LocalService results, or a second physical machine.

## Harness evidence, 16 November 2026

The Go sampler in `packages/telemetry` checks a fixed minimum-permission catalog,
runs the 15-second and 60-second candidate cadences without catch-up sweeps, and
records this process's CPU, RSS and per-source query time. `AttestNativeToken`
returns an error on every OS. `QualifiesServiceAccess` stays false. The production
`Collector` implementation returns `ErrNotImplemented`.

The catalog allows an attempt at CPU, memory, fixed-volume space, local interface
counters, battery charge, ACPI thermal, GPU engine plus an already-installed
`nvidia-smi`, and System/Application log metadata plus a bounded error-presence
read. It rejects administrator, LocalSystem, SeDebug, Event Log Readers as a
group, WMI namespace ACL changes and the Security log. Denial of one source
keeps a null value and does not skip later sources. A timed-out source does the
same. Sequential RSS samples are reported as a peak, not a sum.

### Host and commands

Measured on 16 November 2026 with Go 1.27.1, `linux/amd64`, Ubuntu 24.04,
`Intel(R) Xeon(R) Processor`, 4 cores, 16,780,623,872 bytes physical memory.
`getconf CLK_TCK` printed `100`, so process CPU from `/proc/self/stat` moves in
10 ms ticks. A recorded CPU of 0.000 ms means no full tick was charged; it is
not a calibrated zero. No hostname, serial or device identifier was recorded.

```sh
getconf CLK_TCK
go test -bench='Benchmark' -benchmem -benchtime=50ms -count=1 ./packages/telemetry
go run ./tools/probes/collectorbudget \
  -output artifacts/collector-budget/harness-15s.json \
  -interval 15s -samples 3 -repeats 2 -baseline 2s -iterations 200000
go run ./tools/probes/collectorbudget \
  -output artifacts/collector-budget/harness-60s.json \
  -interval 60s -samples 3 -repeats 2 -baseline 2s -iterations 200000
```

Both candidate runs used the same eight synthetic sources and 200,000 integer
iterations each. Successful readings use metric `synthetic_work`, unit
`iteration` and provenance `harness_synthetic`. The committed copies are
[harness-15s.json](collector-budget-85-harness-15s.json) and
[harness-60s.json](collector-budget-85-harness-60s.json). `make collector-budget`
repeats those two commands and refuses to overwrite an existing file.

One `benchtime=50ms` run printed:

```text
cpu: Intel(R) Xeon(R) Processor
BenchmarkPermissionCompare-4       4401      12431 ns/op    11291 B/op    101 allocs/op
BenchmarkSyntheticSweep-4           164     335966 ns/op   148918 B/op    456 allocs/op
```

`BenchmarkSyntheticSweep` times one in-process sweep of 1,000 iterations with
the inter-sweep wait disabled. It is not a 15-second or 60-second cadence run.

### Measured windows

Each probe window is three start-to-start sweeps. The runner sleeps only the
remainder of the interval and does not insert catch-up sweeps. No sweep overran.

| Run | Window | Wall (ms) | Process CPU (ms) | One core (%) | Four-core host (%) | RSS peak (bytes) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 15s repeat 0 | baseline | 2001.082 | 0.000 | 0.000000 | 0.000000 | 4,591,616 |
| 15s repeat 0 | probe | 30007.576 | 0.000 | 0.000000 | 0.000000 | 4,591,616 |
| 15s repeat 1 | baseline | 2001.075 | 0.000 | 0.000000 | 0.000000 | 4,591,616 |
| 15s repeat 1 | probe | 30010.296 | 10.000 | 0.033322 | 0.008330 | 4,984,832 |
| 60s repeat 0 | baseline | 2001.083 | 0.000 | 0.000000 | 0.000000 | 4,591,616 |
| 60s repeat 0 | probe | 120063.592 | 0.000 | 0.000000 | 0.000000 | 4,722,688 |
| 60s repeat 1 | baseline | 2001.203 | 0.000 | 0.000000 | 0.000000 | 4,722,688 |
| 60s repeat 1 | probe | 120098.428 | 0.000 | 0.000000 | 0.000000 | 4,853,760 |

The only non-zero process-CPU sample was one 10 ms tick inside the second 15-second
probe. Sweep wall time stayed between 1.093 ms and 2.229 ms. Per-source query time
stayed between 0.100 ms and 0.205 ms. The 15-second run's longest query was
0.204928 ms; the 60-second run's longest query was 0.184859 ms. All 48 source
results in each run were `success`. RSS figures are this one process; they are
not a sum of per-source peaks and they exclude WMI, CIM and `nvidia-smi`.

### Harness ceiling, not a production budget

The runner keeps the worker deadline at its 10-second floor because ten times
either observed maximum query is still below that floor, and it clamps any
larger recommendation at 30 seconds. On this host the synthetic sampler did not
need a shorter deadline, and neither candidate cadence overran. The observed RSS
peak was 4,984,832 bytes. `production_budget_approved` is false in both files.
Do not use these ceilings for the Windows collector, provider-host CPU or
service-token cost.

### Windows CI sampler run

Check scaffold run [43851349580](https://github.com/i-got-this-faa/device-audit/actions/runs/43851349580)
on `windows-2025` uploaded one synthetic report for commit `ab9050d`. The
committed copy is [collector-budget-85-windows-ci.json](collector-budget-85-windows-ci.json).
The runner reported Go 1.27.1, `windows/amd64`, OS version 10.0.26100,
`AMD EPYC 7763 64-Core Processor` (the registry value keeps trailing spaces),
4 visible cores and 17,174,360,064 bytes of physical memory. The command was
one 15-second candidate window: 2 sweeps, 1 repeat, a 1-second baseline and
200,000 iterations per source.

| Window | Wall (ms) | Process CPU (ms) | One core (%) | Four-core host (%) | RSS peak (bytes) |
| --- | ---: | ---: | ---: | ---: | ---: |
| baseline | 1000.169 | 0.000 | 0.000000 | 0.000000 | 8,273,920 |
| probe | 15002.218 | 15.625 | 0.104151 | 0.026038 | 8,314,880 |

Neither sweep overran. Sweep walls were 1.647 ms and 1.8375 ms. All 16 source
results were synthetic successes. The longest query was 0.7775 ms. Eleven of
the sixteen queries stayed at 0.000 ms because the process clock did not advance
during that call. The only non-zero process-CPU sample was 15.625 ms.
`production_budget_approved` is false. This is a GitHub-hosted runner, not
either physical Windows target and not a LocalService token.

## Earlier status, 13 November 2026

The record at that date was **blocked on physical Windows target access**.
No sensor measurements were performed in that Linux session. No production
cadence or resource budget was approved. The harness section above does not
replace that limit.

## Confirmed available evidence

The [release scope](../roadmap/release-scope.md) selects one physical HP Victus
15-fb0xxx, Windows 11 Home Single Language 25H2 x64, build-family 26200. It
explicitly records the second physical target as unavailable. The current host
is Linux. Linked environments show only `pico`, unreachable; no Windows host is
linked. A Linux development host, another boot of the same laptop, CI or a VM
does not supply the required second physical Windows machine.

The [19 October probe record](windows-2026-10-19.md) contains one laptop's real
interactive-token observations and 15-/60-second prototype runs. ACPI thermal
access was denied. Workloads differed between cadence runs. The recorded worker
CPU sums exclude the coordinator, WMI provider hosts and NVIDIA subprocess, and
working-set peaks are individual workers rather than whole-system memory. The
[21 October record](windows-probe-2026-10-21.md) also leaves native denied-event
query behavior unqualified. Neither record establishes LocalService access or
full collector overhead on two targets.

## What must be measured when targets are available

Use the existing [read-only probe harness](../../tools/probes/README.md).
Record exact Windows build, PowerShell and collector revision, CPU/RAM and
driver/tool versions without exporting hostnames, serials, event contents or
private identifiers. Use private target attestations to establish that slots
refer to distinct physical machines.

For each target, compare the actual selected LocalService/per-service-SID token
with an independently provisioned denied-permission token. Do not grant admin,
change source ACLs on a working machine, or install unrestricted execution just
to obtain sensor values. The current measurement script labels its context
`interactive_token_not_service_qualification`; invoking it from an interactive
administrator shell cannot relabel that evidence as a service result. Native
service-token orchestration/attestation must be established before using the
probe outputs to satisfy this issue.

| Measurement | Required comparison |
|---|---|
| CPU, memory, disk, network, battery, thermal, GPU | Provider/value/unit or explicit missing reason under each actual token |
| WHEA/disk/Kernel-Power/Application Error/WER | Provider registration, log association and real denied/read query outcomes; no raw event payload |
| Candidate cadences | 15 and 60 seconds with equal workloads and repeated baseline/probe windows; no catch-up bursts |
| Per-source latency | Query and worker elapsed time, success/denial/timeout distinguished |
| CPU overhead | Process-tree and attributable provider-host CPU deltas, normalized to measured elapsed time and reported core-count basis |
| Memory overhead | Coordinator, workers/subprocesses and attributable provider-host peak/steady memory; do not sum sequential peaks as concurrent memory |
| Failure paths | Denied or timed-out source preserves null/reason and does not prevent later sources; source cleanup outcomes remain explicit |

These existing commands are **interactive development probes only**, after the
operator has supplied the selected Windows target and an existing output folder:

```powershell
./tools/probes/Measure-WindowsSensors.ps1 -OutputPath results/interactive-15s.json -Samples 30 -IntervalSeconds 15
./tools/probes/Measure-WindowsSensors.ps1 -OutputPath results/interactive-60s.json -Samples 30 -IntervalSeconds 60
```

The scripts reject non-Windows hosts and existing output files. Preserve local
raw reports privately and use `Export-WindowsProbeEvidence.ps1` for minimized
source-availability output after review. That exporter does not by itself
establish distinct targets, service tokens or whole-system resource budgets.

## Exit condition

Attach both physical target/token matrices, controlled baseline/cadence runs,
per-source latency and full resource accounting, then recommend explicit CPU,
memory, timeout and cadence budgets supported by those measurements. Verify the
actual production collector once it exists; PowerShell subprocess startup cost
does not predict a persistent Go collector's cost. Retain #85 as incomplete
until the missing hardware/token evidence and reviewed PR/merge gates are met.
