# Signed diagnostic assignment dispatch and terminal results, DIA05 #109

Issue `#109` adds controller signing, authorized creation and cancellation, bounded mesh polling/lease delivery, and idempotent single-terminal-transition result ingestion for allowlisted CT06 diagnostic probes (`storage_health.v1`, `system_errors.v1`).

## Implemented scope

- **Schema (`infra/database/migrations/012_diagnostic_assignments.sql`)**: Adds `diagnostic_controller_sequences`, `diagnostic_assignments`, `diagnostic_results`, and `diagnostic_assignment_events` with triggers enforcing monotonically advancing controller sequences, unrevoked active enrollments on dispatch, valid single-terminal-transition state changes, result binding, and append-only audit immutability.
- **Workflow boundary (`packages/workflows/assignments.go`)**: Defines `AssignmentStatus` lifecycle constants (`pending`, `leased`, `cancel_requested`, and terminal `succeeded`, `failed`, `cancelled`, `expired`, `rebooted`, `rejected`), typed sentinel errors, `AssignmentCoordinator`, and `ExecuteAssignedToResult` for signed controller verification and bounded signed result creation.
- **Controller repository, console API & mesh endpoints (`internal/controller/diagnostic_assignments.go`, `internal/controller/diagnostic_service.go`, `internal/controller/mesh.go`, `apps/controller/main.go`)**:
  - Exposes `POST /console/api/diagnostics/assignments`, `POST /console/api/diagnostics/assignments/{id}/cancel`, `GET /console/api/diagnostics/assignments/{id}`, and `GET /console/api/devices/{id}/diagnostics/assignments` behind `RequireFreshAdmin` / `RequireRole(auth.RoleViewer, ...)` with strict deployment scope, CSRF checks, and `--diagnostic-signing-key-file` configuration surfaced on `/healthz`.
  - Exposes authenticated peer mesh endpoints `POST /v1/diagnostics/poll` and `POST /v1/diagnostics/results`, consuming device sequences atomically alongside `device_sequences` telemetry ingestion.

## Evidence ledger

| Case | Evidence source | Verified behavior |
| --- | --- | --- |
| Workflow signed assignment execution | `TestExecuteAssignedToResultTransitions` | Verifies Ed25519 assignment signature and target binding, executes allowlisted probes into signed `succeeded` results, rejects wrong targets with `rejected` without invoking the runner, and records `cancelled` on canceled context. |
| Signing, dispatch, cancellation, status & restart | `TestDiagnosticAssignmentsSignDispatchCancelStatusAndRestart` | Verifies fresh-admin/viewer RBAC, CSRF origin checks, `/healthz` configuration state, single-lease poll dispatch (`delivery_count` and lease tracking), idempotent and conflicting result ingestion, cross-table telemetry sequence replay rejection, `cancel_requested` survival across controller restart, and cursor pagination. |
| Expired leases, revocation & SQL guards | `TestDiagnosticAssignmentsExpiredLeasesRevocationAndDatabaseGuards` | Verifies leased assignments finalize once to `expired` after lease expiry (blocking re-dispatch, cancellation transitions, and late results), revoking a device blocks pending polls, new creations, and post-revocation results, and SQL triggers reject mutations/deletions/bad inserts. |
| Concurrent polling & terminal races | `TestDiagnosticAssignmentsConcurrentPollAndResult` | Eight concurrent polls lease one pending assignment once; eight identical signed results produce one creation and seven idempotent hits; eight conflicting results produce one winner and seven `ErrAssignmentConflict` rejections. |

## Explicit boundaries and open items

- **Offline/reboot spool recovery**: Local diagnostic assignment execution persistence across endpoint reboots (`rebooted` synthesis after endpoint restart) belongs to downstream issue `#110` (`DIA06`).
- **Forecast-driven diagnostic triggers**: Automatic forecast-driven assignment triggers belong to downstream issue `#70` (`FED06`). Shell execution and remediation remain out of scope.

DIA06 #110 later distinguishes the dispatch lease from the result reporting
window and supersedes the lease expiry behavior described here. See
[DIA06 validation](diagnostic-recovery-110.md).
