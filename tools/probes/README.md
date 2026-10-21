# Windows source-availability probes

This read-only development harness advances TEL01 #21 and TEL04 #85. It is
separate from the production endpoint collector, diagnostic catalog and wire
contracts. It cannot enroll a device, submit telemetry, install a service,
elevate, change permissions, run remediation or accept commands from a server.
Only the eight named sources in the script are allowed.

Use an existing PowerShell 7 session on Windows. No new package or driver is
installed. NVIDIA measurements additionally require the existing vendor tool
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
and record `cadence_overrun`. Each source runs in a separate child process. A
timeout kills its process tree, records `timeout` and proceeds to the next source.
CIM calls also have a three-second operation timeout (five seconds for CPU).
Windows process cleanup and provider cancellation may take additional time;
the deadline is not a hard real-time guarantee.

The script records the current interactive token's elevation status. It does
not impersonate a service account or prove that an unelevated account is free
of additional group permissions. Use a separately provisioned test environment
to compare the selected service token and real denied permissions. Never change
this machine's permissions just to turn a missing reading into a successful one.

## Meaning of readings

Every numeric reading has an explicit name, unit and source-local instance.
Zero is retained only when actually returned by the provider. Null is never
converted to zero. Missing readings carry `sensor_unavailable`, `not_applicable`,
`permission_denied` or `collection_error`. A source-wide failure instead records
`failure_reason` and an empty readings array: every metric from that source is
unavailable. A worker failure/timeout has no provider timing or resource result;
those missing fields must not be treated as measured zeros.

| Source | Provider and measurement | Important limit |
| --- | --- | --- |
| CPU | CIM `Win32_PerfFormattedData_PerfOS_Processor`, `_Total.PercentProcessorTime`, percent | Provider-formatted interval, not an instantaneous load or accuracy calibration |
| Memory | CIM `Win32_OperatingSystem`, `(TotalVisibleMemorySize-FreePhysicalMemory)/TotalVisibleMemorySize*100`, percent | OS-visible physical memory; invalid/null capacities remain missing |
| Disk | CIM `Win32_LogicalDisk` with `DriveType=3`, `(Size-FreeSpace)/Size*100`, percent | Space utilization, not SMART health, I/O or disk failure probability; at most 32 volumes |
| Network | .NET `NetworkInterface.GetIPStatistics`, received/sent byte deltas divided by elapsed seconds across a 250 ms window | At most 32 up non-loopback/non-tunnel interfaces; virtual adapters may overlap. Never sum these into a host total. No remote request, ping or latency measurement |
| Battery | CIM `Win32_Battery.EstimatedChargeRemaining`, percent | At most eight batteries; charge is not battery health/lifetime. No battery is `not_applicable` |
| Thermal | CIM `root/wmi:MSAcpi_ThermalZoneTemperature.CurrentTemperature`, tenths Kelvin converted to Celsius | At most 32 ACPI zones; not necessarily CPU/GPU die temperatures. Denial stays explicit |
| GPU | Fixed NVIDIA `--query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader,nounits`, percent/Celsius | At most 16 NVIDIA GPUs. Does not qualify AMD/integrated GPU utilization. `N/A` remains missing |
| Errors | `Get-WinEvent -ListLog System,Application`: enabled flag and record count | Metadata availability only. No event payloads, bookmarks, error selection/ingestion or rollover proof |

Instance indexes are scoped to the current source invocation; they are not
stable component identities across sweeps. Counter reset, invalid capacity and
disappearing-interface failures do not yield negative rates or fabricated zeros.
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

The report contains OS/build, model, CPU/GPU models and driver versions, token
elevation, timestamps, numeric readings, provider labels and resource costs.
It omits host/user names, serials, device IDs, paths, MAC/IP addresses, adapter
names, event contents, raw errors and credentials. Reports stay local and
`results/` is ignored by Git. Inspect before sharing; the committed evidence
record contains aggregate observations instead of raw reports. No telemetry
upload is built into the harness.

The [19 October run](../../docs/validation/windows-2026-10-19.md) records one
physical laptop. #21 and #85 remain open until the second selected machine,
service/denied-token checks and review requirements are met. Other Windows
tasks keep their contract, identity, pipeline and model dependencies.

Provider references: [Windows performance counters](https://learn.microsoft.com/en-us/windows/win32/perfctrs),
[physical memory](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-operatingsystem),
[disk space](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-logicaldisk),
[battery charge](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-battery),
[Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent),
[NVIDIA query reference](https://docs.nvidia.com/deploy/nvidia-smi/index.html).
