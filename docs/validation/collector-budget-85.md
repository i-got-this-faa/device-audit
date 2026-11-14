# Collector permissions and overhead, TEL04 #85

Status on 13 November 2026: **blocked on physical Windows target access**.
No new sensor measurements were performed in this Linux session. No production
cadence or resource budget is approved by this record.

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
