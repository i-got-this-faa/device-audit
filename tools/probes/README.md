# Windows source-availability probes

This read-only development harness advances TEL01 #21 and TEL04 #85. It is
separate from the production endpoint collector, diagnostic catalog and wire
contracts. It cannot enroll a device, submit telemetry, install a service,
elevate, change permissions, run remediation or accept commands from a server.
Only the eight named sources in the script are allowed.

Use the Nix development shell to run the portable regression suite with pinned
PowerShell 7.6.7 on Linux or macOS:

```sh
nix develop --command pwsh -NoLogo -NoProfile -File tools/probes/Test-WindowsProbe.ps1
```

The default shell and `nix develop .#powershell` include PowerShell. On Windows,
use an existing PowerShell 7 session; no new package or driver is installed.
NVIDIA measurements additionally require the existing vendor tool
at `%SystemRoot%\System32\nvidia-smi.exe`; absence remains explicit missing data.

```powershell
New-Item -ItemType Directory -Force tools/probes/results
./tools/probes/Test-WindowsProbe.ps1
./tools/probes/Measure-WindowsSensors.ps1 `
  -OutputPath tools/probes/results/interactive-15s.json `
  -Samples 3 -IntervalSeconds 15
./tools/probes/Measure-WindowsSensors.ps1 `
  -OutputPath tools/probes/results/interactive-60s.json `
  -Samples 3 -IntervalSeconds 60
```

Output parents must already exist. Existing files are never overwritten. The
maximum run is bounded by 30 sweeps, 300-second start-to-start intervals and a
30-second worker deadline per source. Defaults are three sweeps, a 15-second
interval and a 10-second worker deadline. Late sweeps run without catch-up bursts
and record `cadence_overrun`. Each source runs in a separate child process.
When the deadline expires, the result keeps `timeout`; worker-tree termination
and a bounded cleanup wait are attempted. `worker_kill_failed` and
`worker_wait_failed` report cleanup outcomes separately without exposing error
text. Termination is not guaranteed, and the bounded wait may extend the
configured deadline by up to one second.
CIM calls also have a three-second operation timeout (five seconds for CPU).
The deadline is not a hard real-time guarantee.

The script records the current interactive token's elevation status. It does
not impersonate a service account or prove that an unelevated account is free
of additional group permissions. Use a separately provisioned test environment
to compare the selected service token and real denied permissions. Never change
this machine's permissions just to turn a missing reading into a successful one.

## Meaning of readings

Every numeric reading has an explicit name, unit and source-local instance.
Zero is retained only when actually returned by the provider. Null is never
converted to zero. Missing readings carry `sensor_unavailable`, `not_applicable`,
`permission_denied`, `collection_error`, `timeout` or `worker_error`. Every
reading includes its fixed provider and `provenance = real`. Source-wide failure
and worker timeout/error also emit the catalog's expected metrics as null with
units, provider and reason;
`failure_reason` remains on the source result. A worker failure has no provider
timing or resource result. Missing fields must not be treated as measured zeros.

| Source | Provider and measurement | Important limit |
| --- | --- | --- |
| CPU | CIM `Win32_PerfFormattedData_PerfOS_Processor`, `_Total.PercentProcessorTime`, percent | Provider-formatted interval, not an instantaneous load or accuracy calibration |
| Memory | CIM `Win32_OperatingSystem`, `(TotalVisibleMemorySize-FreePhysicalMemory)/TotalVisibleMemorySize*100`, percent | OS-visible physical memory; invalid/null capacities remain missing |
| Disk | CIM `Win32_LogicalDisk` with `DriveType=3`, `(Size-FreeSpace)/Size*100`, percent | Space utilization, not SMART health, I/O or disk failure probability; at most 32 volumes |
| Network | .NET `NetworkInterface.GetIPStatistics`, received/sent byte deltas divided by elapsed seconds across a 250 ms window | At most 32 up non-loopback/non-tunnel interfaces; virtual adapters may overlap. Never sum these into a host total. No remote request, ping or latency measurement |
| Battery | CIM `Win32_Battery.EstimatedChargeRemaining`, percent | At most eight batteries; charge is not battery health/lifetime. No battery is `not_applicable` |
| Thermal | CIM `root/wmi:MSAcpi_ThermalZoneTemperature.CurrentTemperature`, tenths Kelvin converted to Celsius | At most 32 ACPI zones; not necessarily CPU/GPU die temperatures. Denial stays explicit |
| GPU | Fixed NVIDIA `--query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader,nounits`, percent/Celsius; CIM GPU engine utilization, percent | At most 16 NVIDIA GPUs and bounded anonymous GPU engines. Engine values are not a summed adapter total. `N/A` remains missing; no driver is installed |
| Errors | System/Application metadata, selected provider registration/log association and a bounded recent critical/error query | WHEA, disk, Kernel-Power, Application Error and Windows Error Reporting only. No Security log, event payload export, ingestion, bookmarks or rollover proof |

Instance indexes are scoped to the current source invocation; they are not
stable component identities across sweeps. Counter reset, invalid capacity and
disappearing-interface failures do not yield negative rates or fabricated zeros.

For each selected error provider, registration and expected-log association are
checked separately from a read of at most one critical/error event from the last
24 hours. A successful query with no matching events is a genuine zero for the
boolean presence metric, not a claim that the device is error-free. Permission
denial, missing provider/log association and other query failures remain null
with reasons. Event messages, payloads and identifiers are not serialized.

The proposed telemetry v2 contract has no throughput field and requires further
provider/provenance decisions. This report's schema is a **local lab format**;
it is not sent as v2 telemetry or accepted by the controller.

## Measurements, privacy and reproduction

`query_ms` measures the source query, including network's sampling window.
`worker_wall_ms` includes process launch, PowerShell startup, query, serialization
and exit. `worker_cpu_ms` is that PowerShell worker's lifetime CPU through its
final resource snapshot; `worker_peak_working_set_bytes` is its process peak at
that point. CPU includes interpreter startup and may exceed elapsed wall time
because threads execute concurrently. It excludes the coordinator, WMI provider
hosts, the NVIDIA subprocess and JSON work after the snapshot. Sequential worker
peaks are not simultaneous peaks and must not be added together. These figures
measure this prototype's cost, not a future Go service's cost or full system
overhead. Short runs are not a soak or a calibrated performance benchmark.

The report contains OS version/architecture, token elevation, timestamps, numeric
readings, provider labels and resource costs. Startup no longer depends on
successful hardware metadata CIM queries, so denial cannot abort the whole run.
It omits host/user names, serials, device IDs, paths, MAC/IP addresses, adapter
names, event contents, raw errors and credentials. Reports stay local and
`results/` is ignored by Git. No telemetry upload is built into the harness.

### Export minimized evidence

Run the probe separately on each authorized physical target. Keep raw reports
local. After reviewing them, export one or two reports with fixed anonymous slots:

```powershell
./tools/probes/Export-WindowsProbeEvidence.ps1 `
  -ReportPath tools/probes/results/target-1.json,tools/probes/results/target-2.json `
  -OutputPath tools/probes/results/evidence.md
```

The exporter accepts only current real-provenance lab reports and checks catalog
coverage, providers, units, numeric bounds and missing reasons. It reconstructs
Markdown from fixed metric/provider names, numeric ranges and allowlisted reasons.
It does not copy environment strings, timestamps, instances or arbitrary input
text. Input is capped at 8 MiB per report. Output is created without overwriting.
Fixture and legacy reports are rejected rather than relabeled. The unchanged
19 October evidence remains valid for its original probe version; do not retrofit
new metrics into that historical measurement.

Two files or slots do not prove two machines. Confirm distinct physical targets
privately and record target class, OS/build, token context and access limitations
in the reviewed evidence narrative, without publishing device identifiers.
Ranges combine source-local instances across sweeps, not stable components or
host totals. Review the Markdown before publishing it. Export performs no upload.

The [19 October run](../../docs/validation/windows-2026-10-19.md) records one
physical laptop. #21 and #85 remain open until the second selected machine,
service/denied-token checks and review requirements are met. Other Windows
tasks keep their contract, identity, pipeline and model dependencies.
The [21 October implementation checks](../../docs/validation/windows-probe-2026-10-21.md)
record Linux-only regression and worker smoke evidence, with the exact remaining
physical-target prerequisite. They do not add Windows measurements.

Provider references: [Windows performance counters](https://learn.microsoft.com/en-us/windows/win32/perfctrs),
[physical memory](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem),
[disk space](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk),
[battery charge](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-battery),
[Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent),
[NVIDIA query reference](https://docs.nvidia.com/deploy/nvidia-smi/index.html).
