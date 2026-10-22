# Windows probe implementation evidence, 21 October 2026

Issue [#21](https://github.com/i-got-this-faa/device-audit/issues/21) remains
**hardware-blocked, not acceptance-complete**. This change fills development-probe
and evidence-export gaps. It does not replace or extend the measurements in the
[19 October physical-laptop record](windows-2026-10-19.md).

## Preserved hardware evidence and exact prerequisite

The existing HP Victus Windows 11 Home Single Language 25H2 x64 laptop remains the
only documented physical Windows target. The 19 October record supplies real CPU,
memory, disk-space, network-rate, battery-charge and NVIDIA GPU readings, with
explicit denied ACPI thermal access. It contains no measurements of the new GPU
engine or selected-provider event-query probes.

This implementation ran on a Linux x64 development host. No Windows target was
reachable through a documented authorized connection. The SSH capability listed
no configured hosts; local connection configuration and environment discovery
found no Windows-specific route. The repository's current
[platform matrix](../roadmap/release-scope.md) explicitly records a second target
as unavailable. No arbitrary hosts were contacted and no CI VM was counted.

To complete #21, provide a **second distinct physical Windows target matching the
selected matrix**, plus authorized PowerShell 7 execution on both it and the
existing laptop. Run the updated probe on both machines, privately attest that
they are distinct, and review the minimized evidence and token context. If a
second machine is outside the selected class, amend the matrix through its owner
before making a support claim. No credentials or device identifiers need to be
published. New native provider/event access remains unverified on either machine.

## Implemented development workflow

- A fixed metric catalog supplies units/providers and complete null records even
  when an entire source fails or its worker times out/cannot start.
- Existing CPU, memory, fixed-volume, network, battery, ACPI and NVIDIA probes are
  retained. An additional bounded CIM GPU-engine query uses anonymous indexes;
  engine results are not adapter totals or stable component identities.
- The selected error-source candidates are System WHEA-Logger, disk and
  Kernel-Power, and Application Error and Windows Error Reporting. Provider/log
  association and log enabled state are checked before a bounded read of at most
  one critical/error event from the preceding 24 hours. Only boolean presence or
  a null reason is retained, never event contents or identifiers. An exact
  no-matching-events result is zero presence, not evidence of device health.
- Raw reports stay local. The exporter reconstructs a provider/unit/value/reason
  table using fixed names and validated numeric ranges. It rejects fixture and
  legacy reports, missing metrics, invalid units and overwrites. It does not copy
  arbitrary environment or instance strings. Two report files do not establish
  two machines, and provenance labels are not cryptographic attestation.
- Startup context no longer depends on successful hardware metadata CIM queries,
  so an inaccessible metadata provider cannot abort all source probes.

See the [probe guide](../../tools/probes/README.md) for commands and limits.

## Checks actually exercised

Portable PowerShell 7.6.7 on Linux x64 was used outside the checkout. No checks
were run mid-implementation. After the implementation was ready:

- `pwsh -NoLogo -NoProfile -File tools/probes/Test-WindowsProbe.ps1` passed
  **225 checks**. Provider fixtures are explicitly tagged. Coverage includes null
  versus zero, invalid capacities, reset rates, access denial, timeout and launch
  failures with complete missing records, GPU bounds/anonymization, partial event
  failures, disabled/unassociated logs, bounded event selection, no-match versus
  denied access, and minimized export privacy, unit validation and overwrite
  protection. Synthetic real-shaped exporter inputs are test fixtures only;
  their temporary reports are removed and are not Windows evidence.
- An actual child-process network probe returned two real .NET rate readings
  with provider/units on this Linux host. A one-millisecond deadline timed out
  the next actual worker and produced two null metrics with `timeout`; another
  real network worker then completed successfully. No interface identifiers
  were exported. This exercises worker lifecycle and .NET collection, not Windows
  qualification.
- The actual `Measure-WindowsSensors.ps1` entrypoint rejected Linux with
  `Windows is required; no fixture fallback is provided.` It exited nonzero and
  created no report.
- `git diff --check` passed.

The focused tests first exposed a Linux-only fixture-path assumption and then a
missing disabled-log guard. Both were corrected before the passing run. Review
also corrected the Windows metadata model: `EventLogLink` supplies `LogName`, not
`IsEnabled`; enabled state comes from `Get-WinEvent -ListLog`.

The 225-check suite and worker smoke results above predate the scoped review
fixes and do not verify the updated source. On 22 October, they could not be
rerun: `pwsh` is absent from `PATH`, and `/tmp/device-audit-pwsh/pwsh` is absent.

No Go or Python files, shared contracts or production telemetry call sites changed,
so the language-specific `make check`, `make cross-build` and `make model-check`
gates do not apply to this script-only change. Native Windows provider behavior,
the selected LocalService token, denied-token comparisons, resource qualification,
event ingestion/bookmarks and two-machine acceptance were not exercised. The
existing Windows CI job can run the regression script, but is not physical-target
evidence. #85, #91, #92 and #93 retain their separate implementation gates.

Independent source review found no confirmed patch defect. It flagged a native
permission test that must not be skipped: PowerShell's `FilterHashtable` path has
an [upstream report of access denial appearing as no matching events](https://github.com/PowerShell/PowerShell/issues/18965).
The preceding `ListLog` access check is intentional, but the complete sequence
must still be verified under real denied and service tokens before relying on a
zero-presence result. Explicit-denial fixtures do not establish that native
behavior. Windows cleanup of a running NVIDIA subprocess is also untested.

The worker timeout path preserves `timeout` after the deadline even when process
termination or cleanup raises an error. The regression/smoke checks do not force
a failed-kill condition; process-tree termination is not guaranteed, and waiting
for a worker that survives termination can exceed the configured deadline.

The endpoint remains fixture-driven and the lab schema is not telemetry v2. No
production collector, model, service, MDM, remote-shell executor or blockchain
capability is added. Review/merge and real two-machine evidence are still required
by #21; this PR must not auto-close it.
