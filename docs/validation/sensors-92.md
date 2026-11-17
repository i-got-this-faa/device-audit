# Nullable battery, thermal and GPU collectors, TEL06 #92

Status on 17 November 2026: **the collector, its failure-path tests and a hosted
Windows CI availability run are recorded. Physical-target availability is not.**
The PR closing #92 was merged on the owner's instruction with the physical-target
items below still open.
Neither selected physical Windows target was available in this session, and the
second target is recorded as unavailable in the
[release scope](../roadmap/release-scope.md). No support claim follows.

## What was built

`packages/telemetry` has a `SensorCollector` with four sources. Each runs in its
own goroutine under its own deadline (default 5 s, maximum 30 s). An error,
timeout or panic is recorded on that source only.

| Source | Metric | Unit | Windows provider | Capability |
| --- | --- | --- | --- | --- |
| `battery` | `battery_charge` | percent | `kernel32!GetSystemPowerStatus` `BatteryLifePercent` | `read_battery_charge` |
| `thermal` | `acpi_zone_temperature` | celsius | PDH `\Thermal Zone Information(*)\Temperature`, Kelvin − 273.15 | `read_acpi_thermal_zone` |
| `gpu_engine` | `gpu_adapter_utilization` | percent | PDH `\GPU Engine(*)\Utilization Percentage`, two collections 250 ms apart; processes summed per engine, busiest engine per adapter, capped at 100 | `read_gpu_engine` |
| `gpu_vendor` | `nvidia_gpu_utilization`, `nvidia_gpu_temperature` | percent, celsius | `%SystemRoot%\System32\nvidia-smi.exe --query-gpu=utilization.gpu,temperature.gpu --format=csv,noheader,nounits` | `read_existing_nvidia_smi` |

No PowerShell, WMI/COM session, shell, PATH lookup, driver or tool install is
used. Vendor output is capped at 64 KiB and 16 GPUs. PDH reads are capped at
65,536 instances and 16 MiB. Instance labels are indexes (`system`, `zone-0`,
`adapter-0`, `nvidia-0`); PIDs, adapter LUIDs and ACPI zone names are dropped.

### Null reasons

Only the four telemetry v2 reasons are emitted. A fixed `detail` word says why;
provider error text is never copied.

| Case | Reason | Detail |
| --- | --- | --- |
| `BatteryFlag` has bit 128 (no system battery) | `not_applicable` | `no_system_battery` |
| `BatteryFlag` 255 / `BatteryLifePercent` 255 | `sensor_unavailable` | `battery_status_unknown` / `charge_unknown` |
| PDH thermal object or counter absent | `sensor_unavailable` | `pdh_object_absent` / `pdh_counter_absent` |
| Thermal object present, zero zones | `sensor_unavailable` | `no_thermal_zones`, or `pdh_no_instances` when PDH collection reports no data |
| Zone reports 0 K or less | `sensor_unavailable` | `non_positive_kelvin` |
| PDH access denied (`0xC0000BDB` or Win32 5) | `permission_denied` | `pdh_access_denied` |
| Zero GPU engine instances | `sensor_unavailable` | `no_engine_instances` |
| `nvidia-smi.exe` not installed | `not_applicable` | `vendor_tool_absent` |
| `nvidia-smi` exit 4, or `[Insufficient Permissions]` field | `permission_denied` | `vendor_insufficient_permissions` |
| `nvidia-smi` exit 9 / 12 / 3 or 13, or `[N/A]` field | `sensor_unavailable` | `vendor_driver_not_loaded` / `vendor_library_not_found` / `vendor_query_not_supported` / `vendor_field_unsupported` |
| Deadline expired | `collection_error` | `timeout` |
| Provider panic | `collection_error` | `provider_panic` |
| Value with a reason, out of range, NaN/Inf, unknown reason | `collection_error` | `value_with_reason` / `out_of_range` / `missing_reason_invalid` |
| Any other error | `collection_error` | `provider_error` |

Zero GPU engine instances is `sensor_unavailable` rather than `not_applicable`.
In the [#85 hosted service run](collector-budget-85.md#sensor-access) the
denied account saw zero GPU engine instances on a VM that had an adapter, so
zero instances cannot prove there is no GPU. A provider-returned zero, such as
0 % NVIDIA utilization, stays a known zero.

### Mapping to telemetry v2

`SensorSample.MetricsV2()` fills existing fields. No wire contract changed.

- `battery_percent`: the system charge.
- `temperature_c`: the highest ACPI zone. NVIDIA temperature never fills it.
- `gpu_utilization`: the highest adapter or NVIDIA utilization.
- When every reading is null, the field is null with the most actionable
  reason: `permission_denied`, then `collection_error`, then
  `sensor_unavailable`, then `not_applicable`.

These aggregations are provisional, not health inputs. v2 has no provider field;
the provider stays in the collector output and availability report.

## Tests

`packages/telemetry/sensors_test.go` runs on every OS:

- `TestSensorCollectorDistinctNullReasonsDoNotFailOtherSources`: no battery,
  absent thermal PDH object and PDH-denied GPU engine give `not_applicable`,
  `sensor_unavailable` and `permission_denied`. The NVIDIA source still
  returns 7 % and 48 °C, and the v2 temperature stays null.
- `TestSensorCollectorTimeoutPanicAndErrorStayOnTheirSource`: a provider that
  ignores its context, a panic, an opaque error with a path in its text, and
  `nvidia-smi` exit 4. Each is confined to its source; no error text leaks.
- Parser tests for power status, Kelvin conversion, GPU engine aggregation and
  anonymization, `nvidia-smi` CSV including `[N/A]`, and PDH/exit-code
  classification.
- `TestSensorMetricsV2Validate` round-trips the mapped fields through
  `contracts.TelemetryV2` JSON and `Validate`.
- `TestPlatformSensorCollectorReturnsSample` runs the real platform collector.
  On Windows CI it calls the real APIs. It asserts that every reading has
  metadata and exactly one of value or reason.

`tools/probes/sensoravailability` has its own command tests: no overwrite,
bounds, and no identifier strings in output.

## Commands run on the Linux development host

Go 1.27.1, `linux/amd64`. Python 3.14 with `models/test-requirements.txt` in
`/tmp/venv92`; the host Python lacks `rfc3339-validator` and fails four
schema-vector tests without it.

```sh
make check PYTHON=/tmp/venv92/bin/python
make cross-build
GOOS=windows GOARCH=386 go vet ./packages/telemetry
go run ./tools/probes/sensoravailability -output /tmp/sa.json -samples 1 -interval 0s
```

All passed. The last command printed `sensor_unavailable` /
`platform_not_selected` for all five metrics. That is the intended non-Windows
result, not a Linux sensor reading. `make database-check` was not run locally
because no `TEST_DATABASE_URL` was set; it runs in CI, and this change touches no
database code.

## Hosted Windows CI run

Check scaffold run [44079287075](https://github.com/i-got-this-faa/device-audit/actions/runs/44079287075)
on `windows-2025` ran `sensoravailability` at commit `972c0a5` as part of
`tools/check-windows.ps1`: 2 samples, a 2-second interval and a 5-second
per-source deadline. The committed copy is
[sensors-92-windows-ci.json](sensors-92-windows-ci.json). The runner reported Go
1.27.1, `windows/amd64`, OS 10.0.26100, `Intel(R) Xeon(R) Platinum 8370C CPU @
2.80GHz`, 4 visible cores and 17,174,360,064 bytes of physical memory. It ran
under the CI account on a hosted VM. It is not a LocalService token and not a
physical target.

| Source | Metric | Result in both samples | Max query (ms) |
| --- | --- | --- | ---: |
| `battery` | `battery_charge` | null, `not_applicable` / `no_system_battery` | 0 |
| `thermal` | `acpi_zone_temperature` | null, `sensor_unavailable` / `pdh_no_instances` | 292.259 |
| `gpu_engine` | `gpu_adapter_utilization` | known: 14.805 % then 6.037 % | 250.987 |
| `gpu_vendor` | `nvidia_gpu_utilization`, `nvidia_gpu_temperature` | null, `not_applicable` / `vendor_tool_absent` | 0 |

The real Windows calls returned three distinct null reasons and one known GPU
value, and each null left the other sources sampled. The mapped v2 fields were
`battery_percent` null `not_applicable`, `temperature_c` null
`sensor_unavailable` and `gpu_utilization` 14.805 then 6.037 percent. The GPU
engine time is mostly the fixed 250 ms gap between PDH collections. The thermal
PDH object exists on this VM but collected no zone instances, so the detail is
`pdh_no_instances`, not `pdh_object_absent`. A 0 ms query means the clock did not
advance during the call. This run does not exercise an observed
`permission_denied`.

## Not done

- **Both physical targets.** The HP Victus target was not reachable from this
  Linux session, and the second physical target is unavailable. Run this on each
  target, as the interactive user and under the #85 LocalService and denied
  service tokens:

  ```powershell
  New-Item -ItemType Directory -Force artifacts/sensors
  go run ./tools/probes/sensoravailability -output artifacts/sensors/victus-interactive.json -samples 3 -interval 15s
  ```

  The 19 October probe on that laptop read battery charge and NVIDIA values but
  got `permission_denied` on the CIM ACPI thermal class. The PDH thermal counter
  used here is a different interface. Follow-up: the #91 interactive run on the
  Victus on 17 November read battery, thermal, GPU engine and NVIDIA values; see
  [telemetry-91.md](telemetry-91.md#hp-victus-run-17-november-2026). The
  second target and the service-token runs remain open.
- **A real permission denial.** The `permission_denied` path is covered by the
  PDH status and `nvidia-smi` exit-code tests, not by an observed OS denial.
- **Service-token runs.** `service-budget.yml` does not yet run
  `sensoravailability` under its LocalService and denied accounts.
- **Wiring.** Done in #91: `endpoint-agent --collect-telemetry` calls this
  collector and prints a v2 payload. Scheduling and delivery remain open.
- **Provider metadata on the wire.** This needs a separate v2 contract PR.
- **Cost.** The PDH and `nvidia-smi` cost of this collector under the #85
  budget harness has not been measured.
