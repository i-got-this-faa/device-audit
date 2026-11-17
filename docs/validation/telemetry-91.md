# CPU, memory, disk and network collectors, TEL05 #91

Status on 17 November 2026: **the four collectors, their failure-path tests, the
endpoint payload and a real run on the HP Victus target are recorded. The second
physical target and service-token runs are not.** No support claim follows.

## What was built

`packages/telemetry/resources*.go` adds four sources to the #92
`SensorCollector`. Each runs in its own goroutine under its own deadline, and
an error, timeout or panic is recorded on that source only. Every source result
carries `observed_at`, `query_ms` and `provenance = endpoint_sensor`. Every
reading carries metric, unit, provider and an index label.

| Source | Metric | Unit | Windows provider | Capability |
| --- | --- | --- | --- | --- |
| `cpu` | `cpu_utilization` | percent | `kernel32!GetSystemTimes`, two reads 250 ms apart; busy = kernel + user − idle | `read_perfos_processor` |
| `memory` | `memory_used` | percent | `kernel32!GlobalMemoryStatusEx`, (TotalPhys − AvailPhys) / TotalPhys | `read_os_memory` |
| `disk` | `volume_used` | percent | `GetDiskFreeSpaceExW` for each `DRIVE_FIXED` root, (total − total free) / total | `read_fixed_volume_space` |
| `network` | `network_received_rate`, `network_sent_rate` | bytes_per_second | `iphlpapi!GetIfTable2Ex` `InOctets`/`OutOctets`, two reads 250 ms apart, hardware non-filter interfaces only | `read_local_interface_counters` |

No PowerShell, WMI/COM session, shell or install is used. These Go providers
replace the probe's CIM and .NET classes for the collector only; each source
still maps to its #85 catalog capability. Volume roots and interface LUIDs stay
inside the collector. Labels are `total`, `physical`, `volume-N` and
`interface-N`. At most 26 volumes and 16 interfaces are read.

### Null reasons

Rates come from two counter reads inside one source read. A rate is never
negative and an unavailable value is never zero.

| Case | Reason | Detail |
| --- | --- | --- |
| A CPU counter or an interface octet counter moved backwards | `collection_error` | `counter_reset` |
| CPU counters did not advance | `collection_error` | `no_elapsed_ticks` |
| Idle time above kernel + user, available memory above total, free space above size | `collection_error` | `out_of_range` |
| Interface not up in either read | `sensor_unavailable` | `interface_down` |
| Interface present in the first read and gone in the second | `sensor_unavailable` | `interface_removed` |
| No hardware interfaces | `sensor_unavailable` | `no_hardware_interfaces` |
| Volume query denied (`ERROR_ACCESS_DENIED`) | `permission_denied` | `volume_access_denied` |
| Volume not ready (`ERROR_NOT_READY`) | `sensor_unavailable` | `volume_not_ready` |
| Volume reports size 0 / no fixed volumes | `sensor_unavailable` | `volume_size_zero` / `no_fixed_volumes` |
| `GetSystemTimes`, `GlobalMemoryStatusEx` or `GetIfTable2Ex` denied | `permission_denied` | `system_times_access_denied` / `memory_status_access_denied` / `interface_table_access_denied` |

A denied or not-ready volume is null for that volume only, and the other
volumes stay known. An up interface with no traffic is a known `0`. An interface
that appears only in the second read has no baseline and is not reported.

### Mapping to telemetry v2

`SensorSample.MetricsV2()` now also fills `cpu_utilization`, `memory_percent`
and `disk_used_percent` (the fullest fixed volume). No wire contract changed.
v2 has no network-rate field, so the rates stay in the collector sample and the
availability report. Adding them, or provider metadata, to the wire needs a
separate contract PR. These aggregations are provisional, not health inputs.

### Endpoint payload

`telemetry.EndpointTelemetryV2` builds a validated v2 payload with
`source = endpoint` from one sample. `endpoint-agent --collect-telemetry
--device-id <id>` prints it. The existing `--sign-evidence` accepts it only when
`device_id` matches the admission receipt. `UnimplementedCollector` and
`ErrNotImplemented` are removed, because nothing called them and a real
collector now exists.

## Tests

`packages/telemetry/resources_test.go` runs on every OS:

- `TestCPUReadings`: utilization, and idle, kernel and user counter resets,
  no elapsed ticks and idle above total.
- `TestDiskReadingsDeniedVolumeStaysNull`: a denied volume, a not-ready volume,
  a zero-size volume and free above size beside a known 75 % volume.
- `TestNetworkReadingsCounterResetAndUnavailableInterfaces`: a receive counter
  reset beside a valid send rate, an interface down for the whole window, one
  removed and one that went down between reads, an idle up interface (known
  0), one with no baseline, and no negative value anywhere.
- `TestResourceSourcesThroughCollector`: those nulls pass through the
  collector with provider, unit, observation time and provenance. A provider
  that returns a negative rate gets `collection_error` / `out_of_range`.
- `TestEndpointTelemetryV2`: JSON round trip and `Validate`; an all-null sample,
  an invalid device ID and a zero collection time are refused.

`apps/endpoint-agent/telemetry_test.go` collects with the real platform
collector. On Windows it signs the payload through `signEvidence` and verifies
the envelope, and a payload for another device is refused. On other OSes the
all-null sample is refused instead of carrying a fabricated value.

## HP Victus run, 17 November 2026

The [release-scope](../roadmap/release-scope.md) target: HP Victus 15-fb0xxx,
Windows 11 Home Single Language 25H2 build 26200, Ryzen 5 5600H (12 logical
processors), 16,473,231,360 bytes of OS-visible memory. Go 1.27.4,
`windows/amd64`, interactive standard user, not elevated. The report's
`host.role` field is the code's fixed `development_or_ci_not_physical_target`
label, because the process cannot attest which machine it ran on. This record,
not the report, attributes the run to the Victus.

```powershell
New-Item -ItemType Directory -Force artifacts/sensors
go run ./tools/probes/sensoravailability -output artifacts/sensors/victus-interactive.json -samples 3 -interval 15s
```

The committed copy is [telemetry-91-victus.json](telemetry-91-victus.json). It
contains no hostname, user name, adapter or interface name, LUID or zone name.

| Source | Metric | Result over 3 samples | Max query (ms) |
| --- | --- | --- | ---: |
| `cpu` | `cpu_utilization` | 43.750 – 52.083 % | 250.662 |
| `memory` | `memory_used` | 78.731 – 82.439 % | 0 |
| `disk` | `volume_used` | one fixed volume, 90.996 % | 0.507 |
| `network` | `network_received_rate` | `interface-0` known 38,775.559 – 357,381.895 B/s; `interface-1` null `sensor_unavailable` / `interface_down` | 254.159 |
| `network` | `network_sent_rate` | `interface-0` known 572.654 – 46,839.423 B/s; `interface-1` null `interface_down` | 254.159 |
| `battery` | `battery_charge` | 100 % | 0.319 |
| `thermal` | `acpi_zone_temperature` | 69.85 – 70.85 °C | 300.209 |
| `gpu_engine` | `gpu_adapter_utilization` | three adapters, 0 – 32.323 % | 254.713 |
| `gpu_vendor` | `nvidia_gpu_utilization`, `nvidia_gpu_temperature` | 32 – 36 %, 55 – 57 °C | 70.197 |

The mapped v2 fields in each sample were all known: `cpu_utilization`,
`memory_percent`, `disk_used_percent`, `battery_percent`, `temperature_c` and
`gpu_utilization`. The second hardware interface was down for the whole run,
which is the real unavailable-interface case: it produced nulls, not zero
rates. A 0 ms query means the clock did not advance during the call.

This run also answers the open #92 thermal question. On 19 October the CIM
`MSAcpi_ThermalZoneTemperature` class returned `permission_denied` on this
laptop. The PDH `Thermal Zone Information` counter used by the collector
returned a temperature for the same interactive user.

`endpoint-agent --collect-telemetry --device-id victus-test` on the same
machine printed a v2 payload with `source = endpoint` and known CPU, memory,
disk, GPU, battery and temperature fields. Without `--device-id` it exited 1.

## Not done

- **Second physical target.** It is recorded as unavailable in the release
  scope. The acceptance item for both targets stays open.
- **Service tokens.** These readings are from the interactive user. The #85
  `service-budget.yml` LocalService and denied-account runs do not yet run
  `sensoravailability`.
- **Observed denials.** Counter reset, disk denial and interface removal are
  covered by tests, not by an observed OS event on this laptop. Only the
  down interface was observed.
- **Network rates and providers on the wire.** These need a v2 contract PR.
- **Cost.** The collector's cost under the #85 budget harness is not measured.
  CPU and network each wait 250 ms by design.
- **Durable delivery.** `--collect-telemetry` prints one payload. Scheduling,
  spooling and submission remain separate work.
