# Authenticated diagnostic assignment execution, DIA03 #38

The Windows endpoint accepts one CT06 assignment on stdin with
`--run-assigned-probe`. Admission requires the pinned diagnostic authority,
the enrolled deployment and device, the CT06 probe and argument schema, and
enough time to run within the signed deadline. The worker uses the limits from
DIA04 #108. The CT06 wire schema and golden vectors from #76 apply unchanged.

## Acceptance evidence

| Test | Evidence |
| --- | --- |
| `TestEndpointDiagnosticAssignment` | The endpoint command path rejects a changed signed budget, signed wrong-device and wrong-deployment targets, expired and future-issued assignments, insufficient time, unknown probes and fields, duplicate keys, trailing JSON and oversized input before the worker runs. |
| `TestEndpointDiagnosticAssignment` | Reopening the identity store preserves assignment IDs and the controller sequence watermark. An exact duplicate, the same ID with a newer sequence, and a different ID with a stale sequence cannot run. The worker holds the identity lock, and losing device sequence state denies further execution. |
| `TestEndpointDiagnosticAssignment` | A successful result and a permission-denied result verify with the admitted device key and correlate to the original assignment. The shared sequence allocator advances from 2 to 3. Success includes a size and SHA-256 that match the local evidence bytes. The worker receives the exact signed request and a deadline. |
| `TestExecuteDiagnosticAssignmentTransitions` | Cancellation after durable admission yields a signed terminal result with a null start time. An evidence write error yields signed failure without an evidence reference. |
| `TestAssignedProbeWindowsCommand` | The native CLI test checks signed output-budget failure, replay protection across command processes, and tamper refusal. |

The endpoint fixture uses a synthetic worker to count launches and return
controlled outcomes. The Windows CLI test exercises the native worker when
run by `windows-check`.

## Scope of validation

On Linux, `make check`, `make cross-build`, `make model-check` and
`make contract-check` passed. The first `make check` run failed in
`TestScopedRelayDirectAndRelayDelivery` and
`TestSchedulerSlowProviderDoesNotStallOthers`. Both passed on the full
rerun. Contract conformance covered 367 golden vectors and 81 wire cases.

The focused endpoint and workflow race tests passed on Linux. The three
`TestDiagnosticAssignments*` controller tests also passed with PostgreSQL
18.7, covering dispatch, signed result ingestion and replay, expired leases,
revocation, cancellation, and concurrent terminal writes. The controller
tests use an in-process probe fixture and simulated admitted mesh peer.

The console browser acceptance suite passed with Playwright Chromium. It
exercises console authentication and device views. The signed assignment
command does not have a browser route. The Windows test binary was
cross-compiled. Native Windows execution, target-hardware probes and
LocalService qualification were unavailable on the local Linux host.
The boot ID records the Windows kernel boot time observed at admission.
Clock correction and boot identifier stability across real reboots were
outside the local test.

A claim survives a command restart and prevents another probe. Recovery of
an interrupted claim, automated poll and result delivery, offline
cancellation, and terminal result spooling are follow-up work in DIA06 #110.
Evidence and identifiers remain off-chain. The Go chain policy tests run as
part of repository checks.
