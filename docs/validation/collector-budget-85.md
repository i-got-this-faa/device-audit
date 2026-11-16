# Collector permissions and overhead, TEL04 #85

Status on 16 November 2026: **the permission gate, cadence scheduler, Linux
synthetic sampler, and one GitHub-hosted Windows service-token run are recorded.
Physical Windows qualification is still open.** No production cadence or resource
budget is approved. The Linux harness section is not a Windows sensor reading.
The hosted-runner section is a `windows-2025` VM, not a physical machine and
not the missing second physical target.

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
`production_budget_approved` is false. This short check is a GitHub-hosted
runner under the CI account. It is not a LocalService token and not either
physical Windows target.

## Hosted Windows service tokens, 16 November 2026

Workflow run [43859814735](https://github.com/i-got-this-faa/device-audit/actions/runs/43859814735)
on `windows-2025` completed successfully for commit `470f036`. The artifact is
`service-token-budget` (artifact id 14232297886). The runner is a hosted VM.
It does not satisfy the two-physical-machine requirement, and this section does
not close #85.

The job installed `collectorservice` twice. `DeviceAuditLocal` ran as
`NT AUTHORITY\LocalService` with a per-service SID. `DeviceAuditDenied` ran as
local user `deviceaudit-denied` with its own per-service SID. That account
received "Log on as a service" and read/execute on the checkout plus modify on
its output directory. It was not added to Administrators, Event Log Readers or
Performance Log Users. Sensor, WMI and event-log ACLs were not changed. Each
service then ran `Measure-WindowsSensors.ps1` and `collectorbudget` at 15s and
60s, 30 sweeps, no catch-up. The synthetic harness still reports
`qualification = not_windows_service_or_physical_target` and
`production_budget_approved = false`. `AttestNativeToken` is unchanged and
still returns an error.

The host recorded by the harness was Go 1.27.1, `windows/amd64`, OS 10.0.26100,
`AMD EPYC 7763 64-Core Processor` (the registry value keeps trailing spaces),
4 visible cores and 17,174,360,064 bytes of physical memory. The probe recorded
PowerShell 7.6.9 and OS version 10.0.26100.0. No hostname, machine SID or
logon SID is published; those fields are `<host>`, `S-1-5-21-<local>-` and
`S-1-5-5-<logon>`.

### Tokens

`whoami /all` and the structured token are in
[local-attestation.json](collector-budget-85-hosted-runner/local-attestation.json)
and [denied-attestation.json](collector-budget-85-hosted-runner/denied-attestation.json).
`TokenElevation` is true for both because a service logon is not a filtered UAC
token. The probe's own `elevated` field is false for both: neither token is in
Administrators.

| | LocalService | Denied account |
| --- | --- | --- |
| Service | `DeviceAuditLocal` | `DeviceAuditDenied` |
| Account | `NT AUTHORITY\LOCAL SERVICE` | `<host>\deviceaudit-denied` |
| Account SID | `S-1-5-19` | `S-1-5-21-<local>-1003` |
| Service SID | `S-1-5-80-1555716268-1227767556-2535967203-2823475634-3040544233` | `S-1-5-80-2847218047-604107344-1038059165-2347674844-19511672` |
| Integrity | `S-1-16-16384` System | `S-1-16-12288` High |
| Administrators | no | no |
| Probe context | `local_service_token` | `low_privilege_token` |
| Enabled privileges | `SeChangeNotifyPrivilege`, `SeImpersonatePrivilege`, `SeCreateGlobalPrivilege` | the same three |
| Finished | 2026-11-16T12:54:09Z | 2026-11-16T14:07:31Z |

LocalService also had `SeAssignPrimaryTokenPrivilege`, `SeIncreaseQuotaPrivilege`,
`SeSystemtimePrivilege`, `SeAuditPrivilege`, `SeIncreaseWorkingSetPrivilege` and
`SeTimeZonePrivilege` present and disabled. The denied account had
`SeIncreaseWorkingSetPrivilege` present and disabled. Neither token had
`SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, `SeSecurityPrivilege`
or `SeTakeOwnershipPrivilege`. Neither was in Event Log Readers
(`S-1-5-32-573`) or Performance Log Users (`S-1-5-32-559`). LocalService's
token also contained eight unknown `S-1-5-32-*` groups; none is `S-1-5-32-544`.

### Sensor access

Thirty sweeps at each cadence. No sweep overran. Battery charge was
`not_applicable` for both tokens. ACPI thermal was `sensor_unavailable` for
both. `nvidia-smi` was `not_applicable` for both. System and Application
provider registration and the bounded recent-error query succeeded for both
tokens: each of the five providers was enabled and the recent-error boolean was
0. That is a reading on this VM, not a claim that the denied account is blocked
from those logs.

The formatted processor counter returned one `_Total` row under LocalService
and no single `_Total` row under the denied account, so the denied CPU reading
is null with `missing_reason = sensor_unavailable` and no source
`failure_reason`. The GPU engine class returned 32 instances under LocalService
and zero under the denied account, recorded as `not_applicable`. Memory, two
fixed volumes and eleven up non-loopback interfaces returned numbers for both
tokens. Ranges below are the readings as recorded. Network rates and GPU
engines are source-local instances and are not a host total. Worker CPU and
working-set figures are each PowerShell worker, not WMI provider-host cost, and
sequential peaks are not summed.

| Token | Cadence | Sweep wall (ms) | CPU % | Memory % | Disk % (2 volumes) | GPU engines |
| --- | --- | --- | ---: | ---: | ---: | --- |
| LocalService | 15s | 5622.411–8766.430 | 0–11, mean 3.1 | 18.5118–19.3209 | 2.4118–79.3967 | 0–14 across 32 engines |
| LocalService | 60s | 5623.364–6966.266 | 0–64, mean 4.6 | 18.6108–19.9022 | 2.4124–79.3107 | 0–14 across 32 engines |
| Denied | 15s | 5163.799–7822.401 | null, `sensor_unavailable` | 19.0049–20.1171 | 2.4133–80.1433 | null, `not_applicable` |
| Denied | 60s | 5160.218–6450.443 | null, `sensor_unavailable` | 18.9921–19.2043 | 2.4136–80.1454 | null, `not_applicable` |

Under LocalService the slowest worker query was the 15s CPU sample at 2429.398 ms.
Worker wall stayed under the 10-second deadline. The largest worker peak
working set was the events worker, 118,833,152 bytes. Under the denied account
the slowest query was the 15s CPU sample at 2077.502 ms and the largest worker
peak was the events worker, 118,837,248 bytes. Every worker reported
`worker_kill_failed = false` and `worker_wait_failed = false`.

### Synthetic harness under the same tokens

The harness burns 200,000 iterations per source. Its values are
`synthetic_work`, not sensor percents. Copies:

- [local-harness-15s.json](collector-budget-85-hosted-runner/local-harness-15s.json)
- [local-harness-60s.json](collector-budget-85-hosted-runner/local-harness-60s.json)
- [denied-harness-15s.json](collector-budget-85-hosted-runner/denied-harness-15s.json)
- [denied-harness-60s.json](collector-budget-85-hosted-runner/denied-harness-60s.json)

| Token | Window | Wall (ms) | Process CPU (ms) | One core (%) | Four-core host (%) | RSS peak (bytes) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| LocalService 15s | baseline | 2000.199 | 0.000 | 0.000000 | 0.000000 | 8,089,600 |
| LocalService 15s | probe | 435012.105 | 46.875 | 0.010776 | 0.002694 | 8,646,656 |
| LocalService 60s | baseline | 2000.246 | 0.000 | 0.000000 | 0.000000 | 8,265,728 |
| LocalService 60s | probe | 1740012.538 | 0.000 | 0.000000 | 0.000000 | 8,663,040 |
| Denied 15s | baseline | 2000.433 | 0.000 | 0.000000 | 0.000000 | 8,118,272 |
| Denied 15s | probe | 435010.992 | 78.125 | 0.017959 | 0.004490 | 8,663,040 |
| Denied 60s | baseline | 2000.434 | 0.000 | 0.000000 | 0.000000 | 8,245,248 |
| Denied 60s | probe | 1740025.904 | 93.750 | 0.005388 | 0.001347 | 8,806,400 |

No harness sweep overran. All 240 source results in each run were synthetic
successes. Maximum query time was 0.7828 ms, 0.8004 ms, 0.7999 ms and 3.8274 ms.
The recommended worker deadline stayed at the 10-second floor. Many queries
were 0.000 ms because the process clock did not advance (168, 159, 164 and 161
of 240). A recorded CPU of 0.000 ms is a 15.625 ms tick that did not complete,
not a calibrated zero. RSS is this one process.

## Earlier status, 13 November 2026

The record at that date was **blocked on physical Windows target access**.
No sensor measurements were performed in that Linux session. No production
cadence or resource budget was approved. The harness section above does not
replace that limit.

## Confirmed available evidence

The [release scope](../roadmap/release-scope.md) selects one physical HP Victus
15-fb0xxx, Windows 11 Home Single Language 25H2 x64, build-family 26200. It
explicitly records the second physical target as unavailable. The current development host is Linux. A Linux development host, another boot
of the same laptop, CI or a VM does not supply the required second physical
Windows machine. The hosted-runner section above is that kind of VM.

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

For each physical target, compare the actual selected LocalService/per-service-SID
token with an independently provisioned denied-permission token. Do not grant
admin, change source ACLs on a working machine, or install unrestricted
execution just to obtain sensor values. The probe labels `S-1-5-19` as
`local_service_token`. Any other elevated token stays
`interactive_token_not_service_qualification`, so an interactive administrator
shell cannot relabel itself as a service result. The hosted-runner section is
one VM's service measurement. It does not by itself satisfy this issue.

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
