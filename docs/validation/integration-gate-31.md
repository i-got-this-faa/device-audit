# INT02 first real-device integration gate, 20 November 2026

Record for [issue #31](https://github.com/i-got-this-faa/device-audit/issues/31).

**Result: the gate is open.** Both Windows-machine acceptance items are unmet.
Only one physical Windows endpoint exists (the HP Victus in the
[release scope](../roadmap/release-scope.md#endpoint-platform-matrix)), so two
machines cannot enroll, and no forced-DERP run was made on Windows. This record
holds the same-host evidence that exists and lists what stays open. The first two
target-window gates stay open (see [Open gates](#open-gates)).

## Acceptance

| Acceptance item | Status | Basis |
| --- | --- | --- |
| Two Windows machines enroll and send signed telemetry over direct and forced-DERP paths into durable storage and the console | **Not met** | Second endpoint unavailable. No Windows run reached a controller over Tailcat, so direct and forced-DERP delivery from Windows are unmeasured. |
| Record foundation decisions and fixtures | Met | [Decisions](#foundation-decisions-and-fixtures) |
| Record unauthorized, replay, revocation, controller-restart and offline test evidence | Met for same-host Linux runs; **not** for Windows | [Failure-path evidence](#failure-path-evidence) |
| Missing requirements keep the first two target-window gates open | Met | [Open gates](#open-gates) |

## Foundation decisions and fixtures

| Foundation | Record |
| --- | --- |
| Release scope, Windows-first target, LocalService (#14) | [release-scope.md](../roadmap/release-scope.md) |
| Source reconciliation (#72) | [source-reconciliation](source-reconciliation-2026-10-15.md), [patent-map](../source/patent-map.md) |
| Replay fake (#81) | [replay-acknowledgements-89.md](replay-acknowledgements-89.md), `tools/fakes/endpoint-replay` |
| Model thresholds (#86) | [model-thresholds-86.md](model-thresholds-86.md) |
| Relay and fallback (#88) | [relay-fallback-88.md](relay-fallback-88.md) |
| Spool loss accounting (#95), drain (#96) | [endpoint-spool-and-probe-limits.md](endpoint-spool-and-probe-limits.md), [spool-drain-96.md](spool-drain-96.md) |
| History in the console (#100) | [console-fixtures-99.md](console-fixtures-99.md) |
| Real HP Victus telemetry, errors, sampling | [telemetry-91.md](telemetry-91.md), [error-evidence-93.md](error-evidence-93.md), [sampling-94.md](sampling-94.md) |

## Failure-path evidence

Run on 20 November 2026 from `e50d098`, Linux amd64, Go 1.27.1, PostgreSQL 17.11
(disposable cluster), Python in a venv from `models/test-requirements.txt`.

| Command | Result |
| --- | --- |
| `make check` and `make cross-build` | pass |
| `make database-check` | pass |
| `make contract-check` | pass |
| `make replay-check` | pass |
| `tools/integration-gate.sh` (13 named tests, `-race`, no skips) | pass |

`tools/integration-gate.sh` needs `TEST_DATABASE_URL` and fails on any skipped test.

| Path | Tests | Shows |
| --- | --- | --- |
| Unauthorized | `TestEnrollmentRejectsInvalidProofsAndExpiryWithoutAdmission`, `TestMeshAdmissionPersistsAndRevocationDenies` | Invalid or expired proofs create no device. A key unknown to the controller is denied at mesh admission. |
| Replay | `TestMeshConcurrentDuplicatesAcceptOnce`, `TestMeshSequencePolicySurvivesControllerRestart` | 16 concurrent copies give one row and byte-identical receipts. A different payload at a used sequence is rejected, also after a new database pool. |
| Revocation | `TestRevocationRejectsFreshAndEstablishedPeersAcrossRestart`, `TestRevocationRejectsSampleQueuedBehindIt` | Revoked peers are refused whether fresh or established, across controller restart. A queued sample gets a signed rejection. |
| Controller restart | `TestEndpointEnrollmentPostgres`, `TestEnrollmentAndProcessRestart`, `TestDeviceStateHTTPPaginationProvenanceAndRestart`, `TestConsoleHistoryPageSurvivesRestart` | Enrollment, latest state and console history come back from PostgreSQL through a new listener and repository. The first reply is lost after commit and the retry yields one row per record. |
| Offline | `TestSpoolDrainKeepsUnacknowledgedHead`, `TestSpoolDrainBackoffAndOrdering` | Lost, interrupted, 408, 429 and 5xx replies keep the spool head and order, then back off with jitter. |
| Direct and relay delivery | `TestScopedRelayDirectAndRelayDelivery` | Same-host direct delivery, then delivery through a test DERP relay. This run used the `TS_DEBUG_ALWAYS_USE_DERP=1` path, not the UDP-blocked namespace proof (`make relay-fallback-proof`, recorded in [relay-fallback-88.md](relay-fallback-88.md)). |

## Open gates

| Gate | Missing requirement |
| --- | --- |
| Second Windows endpoint | A second physical machine in the included class. It is unavailable and no CI or VM substitutes. |
| Windows direct and forced-DERP delivery | A Windows endpoint enrolled against a deployed controller, with a direct run and a run with UDP blocked. No public relay or controller host (#73) exists. |
| Installed service on the target | Signed samples from the LocalService service reaching durable storage. The service qualification ran the pipeline, not a delivery to a controller. |
| Windows power loss, WAN/NAT, deployed storage | Not tested anywhere. |
| Console view of two devices | Console tests use fixtures and one-device runs; two real devices were never shown. |

No production, patent, prediction or privacy claim follows. Same-host Linux runs
with fixture sensor readers do not qualify Windows.
