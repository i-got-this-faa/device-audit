# Typed read-only probe catalog, DIA01 #36

Status on 18 November 2026: **the catalog, its rejection and denial tests, and
real runs of both probes on the HP Victus target are recorded. Assignment
verification, signed results, an observed OS denial and LocalService runs are
not.**

## What was built

`packages/workflows/catalog.go` runs exactly the two CT06 probes. A request is
the assignment's `probe_id`, `arguments` and `budget`. It is checked by
`DiagnosticArgumentsV1.ValidateFor`, the same function that validates signed
assignments, before any provider runs. Each probe ID maps to one Go function.
There is no command, script, path or URL input, and no generic executor.

| Probe | Reads | Evidence body |
| --- | --- | --- |
| `storage_health.v1` | `IOCTL_STORAGE_QUERY_PROPERTY` on `\\.\PhysicalDrive<n>` opened with no access rights: the device descriptor, then NVMe log page 0x02 | bus type and NVMe critical-warning flags, composite temperature, spare, percentage used, media errors, unsafe shutdowns, power-on hours, error-log entries and temperature minutes |
| `system_errors.v1` | the TEL07 `wevtapi` reader for System and Application, levels 1 and 2, within `lookback_seconds`, at most `max_entries` per log | per log: outcome, records, skipped count, `more`; per record: record ID, event ID, level, creation time, message digest/size/status, provider (when publisher-shaped) and provider digest |

Every success is a `device-audit.probe-evidence.v1` document. It carries
`probe_id`, `source` (`endpoint_storage_ioctl` or `endpoint_event_log`),
`observed_at` and the typed arguments.

### Rules

- **Component IDs.** Only `storage:disk-<n>`, with `n` from 0 to 63 and no
  leading zero, names a disk. The device path is built from that integer. A
  well-formed ID in any other form, an absent disk or a removable, USB, SD/MMC
  or virtual disk returns `probe_error` / `component_not_found`. A non-NVMe disk
  returns its bus type with `nvme_health: null` and `missing_reason:
  not_applicable`.
- **No raw log content.** Event messages never appear in probe output, only the
  SHA-256 of the TEL07-bounded message, its size and status. Any process can
  write an event under an unregistered source name, so a provider name is kept
  only when it matches `^[A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$`; otherwise
  `provider` is null and only `provider_sha256` remains.
- **No side effects.** The error probe passes no saved positions, so it never
  moves `--collect-errors` state. No probe writes files, changes ACLs, elevates
  or retries with more access.
- **Failures** use the CT06 `failed` reasons:

  | Case | Reason / detail |
  | --- | --- |
  | Disk open or query denied | `permission_denied` / `storage_access_denied` |
  | Any event log denied | `permission_denied` / `event_log_access_denied`, with the other log as partial evidence |
  | Absent or failed log | `probe_error` / `event_log_<outcome>` |
  | Failure after `wall_seconds` | `budget_exhausted` / `wall_budget` |
  | Evidence larger than `max_output_bytes` | `budget_exhausted` / `output_budget`; no evidence returned |

  Partial evidence is dropped when it exceeds the output budget. A cancelled
  parent context returns the cancellation, for the runner to report.

`endpoint-agent --run-probe` reads one strict request on standard input. It
exits 0 with evidence, 1 with a `device-audit.probe-failure.v1` record, or 2
when the request was rejected and nothing ran. It is a local operator check: it
does not verify an assignment signature, target or expiry.

## Tests

`packages/workflows/catalog_test.go`, every OS:

- `TestCatalogRejectsUnknownProbesAndShellInput`: 21 wire requests fail
  `ParseRequest`. They include unknown probes, `cmd.exe /c whoami` and
  `powershell -enc` as probe IDs, `command`/`shell`/`script` keys at each level,
  Windows and device paths, `storage:disk-0 & whoami`, mixed or missing
  arguments, out-of-range values, trailing data and oversized input.
  `storage-a`, `storage:disk-64`, `storage:disk-01` and `storage:disk-99`
  return `component_not_found`. The recording fakes show that no provider was
  called for any of them.
- `TestSystemErrorsOmitsCommandLikeLogContent`: events whose messages contain
  an encoded PowerShell command, `cmd.exe /c del … && curl … | sh` and `$(rm
  -rf /)`, plus a provider named `cmd.exe /c whoami`. None of that text appears
  in the evidence; the digests match.
- `TestSystemErrorsHonoursLookbackAndMaxEntries`: lookback and the per-log cap
  apply and the cut sets `more`.
- `TestDeniedProbePermissionsFailWithoutSideEffects`: a denied System log gives
  `permission_denied` with Application as partial evidence; the call log is
  exactly `bounds:System, bounds:Application, read:Application`. A denied disk
  is read once and not retried.
- `TestStorageHealthEvidence`, `TestBudgetsBoundTheProbe` (output budget, a
  provider that blocks past a 1-second wall budget, parent cancellation),
  `TestParseNVMeHealthLog` (field offsets, null temperature, a counter above 64
  bits, a short page).

`packages/workflows/catalog_windows_test.go` runs both probes against the host.
On a host whose disk 0 is ineligible it accepts `component_not_found`.
`apps/endpoint-agent/probe_test.go` checks the CLI exit codes and failure record.

## HP Victus run, 18 November 2026

HP Victus 15-fb0xxx, Windows 11 build 26200, interactive standard user, not
elevated. Go 1.27.4.

```powershell
'{"probe_id":"storage_health.v1","arguments":{"component_id":"storage:disk-0","lookback_seconds":null,"max_entries":null},"budget":{"wall_seconds":30,"max_output_bytes":4096}}' | endpoint-agent --run-probe
'{"probe_id":"system_errors.v1","arguments":{"component_id":null,"lookback_seconds":86400,"max_entries":16},"budget":{"wall_seconds":60,"max_output_bytes":65536}}' | endpoint-agent --run-probe
```

| Request | Exit | Result |
| --- | ---: | --- |
| `storage_health.v1`, `storage:disk-0` | 0 | 617 bytes, bus `nvme`, critical warnings 0, 55 °C, spare 100 % (threshold 5 %), 18 % used, 0 media errors, 266 unsafe shutdowns, 5,241 power-on hours |
| `system_errors.v1`, 24 h, 16 per log | 0 | 6,600 bytes; System 16 records with `more: true`; Application 2 records |
| `storage_health.v1`, `storage:disk-7` | 1 | `probe_error` / `component_not_found` |
| `system_errors.v1`, `max_output_bytes` 512 | 1 | `budget_exhausted` / `output_budget` |
| probe ID `cmd.exe /c whoami` | 2 | `probe request rejected: probe is not allowlisted` |

`Get-WinEvent` for levels 1–2 over the same 24 hours, oldest first, returned
the same 16 System and 2 Application record IDs. Their providers included
Microsoft-Windows-TPM-WMI, TPM, Microsoft-Windows-DistributedCOM,
Microsoft-Windows-WindowsUpdateClient, Microsoft-Windows-Defrag and VSS.
`Get-PhysicalDisk` reported the same disk as NVMe, Healthy.

For comparison, `Get-StorageReliabilityCounter` failed for this account with
"Access to a CIM resource was not available". The probe does not use that
path. Opening the disk with `GENERIC_READ` was also denied; the probe opens it
with no access rights, which the NVMe driver allows.

## Not done

- **Assignment execution.** Verifying the controller signature, target device
  and expiry, deduplication and signed CT06 results are DIA03 #38.
- **Observed OS denial.** Both probes succeeded for the standard user, and also
  from a copy of the binary labelled Low integrity. Denial is covered by the
  fake-provider tests only.
- **LocalService.** No probe ran under the service token.
- **Non-NVMe health.** SATA/ATA SMART is reported `not_applicable`; only NVMe
  was available here. The second physical target is recorded unavailable.
- **Inventory mapping.** `storage:disk-<n>` is a local OS disk number. Binding
  it to an inventory component (#97) is not done, and a disk renumbered after
  hardware changes gets a different ID.
