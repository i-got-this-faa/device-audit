# Managed diagnostic recovery, DIA06 #110

| Failure path | Evidence |
| --- | --- |
| Probe finishes offline and the result response is lost | `TestEndpointEnrollmentPostgres` uses the real mesh client, loopback DERP, controller HTTP handler and PostgreSQL. The test takes the mesh down during a fixture probe, persists the signed result locally, then drops the first accepted HTTP response. An exact retry retires the job. PostgreSQL contains one terminal transition with the original signature and evidence reference. |
| Process stops during a probe or after local completion | `TestDiagnosticOutboxProcessRecovery` exits a subprocess after the durable start or terminal commit. A fresh endpoint process context loads the outbox under a different boot identifier. Successful work keeps its exact signed bytes and evidence, an unfinished start produces `rebooted` / `agent_restarted`, and recovery never invokes a worker. |
| Cancellation during an outage | `TestDiagnosticOutboxProcessRecovery` observes a cancellation from the first successful poll after restarting with unfinished work. `TestDiagnosticCancelsRunningProbeOnReconnect` injects a failed poll then a successful poll with the cancellation while the worker still runs. Both produce a signed `cancelled` / `cancel_requested` result. |
| Shared sequence and duplicate delivery | `TestDiagnosticOutboxProcessRecovery` sends telemetry, the original diagnostic result, and later telemetry in shared sequence order. It simulates a lost acknowledgement, reopens storage, retries the original bytes, and refuses to execute the assignment again after retirement. |
| Lease, reporting deadline, cancellation and authorization | `TestDiagnosticAssignmentsExpiredLeasesRevocationAndDatabaseGuards` accepts an offline result after its dispatch lease and assignment deadline, rejects a late execution start, preserves offline cancellation until reconnect, verifies the 24-hour reporting cutoff and keeps the revocation and SQL guards. `TestDiagnosticAssignmentsSignDispatchCancelStatusAndRestart` verifies one live lease per device and checks the authenticated poll and result routes. |

The subprocess tests inject boot identifiers and probe output. They exercise
process exit and persisted state on Linux. The Windows amd64 agent and its
test binary cross-compile. A physical Windows reboot or power loss, Windows
SCM execution under LocalService, and Windows hardware probe behavior remain
unverified for DIA06. The Chromium console regression suite runs separately
from endpoint recovery. The existing CT06 fixtures exercise unchanged wire
formats. No chain transaction or deployment is involved.
