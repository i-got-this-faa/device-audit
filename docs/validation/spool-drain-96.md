# TEL09 #96 authenticated spool drain

Validated on Linux amd64 with Go 1.27.4 and a disposable PostgreSQL 18.7
cluster. The acknowledgement schema and database schema are unchanged.

| Behavior | Evidence |
| --- | --- |
| Lost acceptance, controller restart and reconnect | `TestEndpointEnrollmentPostgres` drops the first HTTP reply after the real controller commits. The endpoint command has two records queued and PostgreSQL has one. A new controller repository, HTTP listener and Tailcat server use the same database and controller keys. The same drain process retries the head, retires it and submits the next record. PostgreSQL has two rows total. A subsequent submission of the first request returns the original signature. |
| Service delivery | The same integration test starts the service pipeline with fixture sensor readers. A new snapshot wakes the worker, reaches PostgreSQL and becomes the acknowledged spool record. The pipeline stops cleanly on cancellation. |
| Stable receipts and digest conflicts | `TestMeshConcurrentDuplicatesAcceptOnce` returns byte-identical receipts for 16 concurrent copies and checks that there is one row. `TestMeshSequencePolicySurvivesControllerRestart` opens a new database pool and handler, checks that a different payload signed by the same device at the same sequence is rejected, then recovers the byte-identical receipt for the original after expiry and after the mark advances. |
| Wrong device, sequence, digest or signature | `TestSpoolDrainKeepsUnacknowledgedHead` checks that a blocked reply leaves both original files byte for byte, keeps the local acknowledgement mark, and never sends the second record. The same test covers a signed replay rejection, a signed `revoked_key` response, and an unsigned HTTP 403. |
| Revocation at ingestion | PostgreSQL tests verify that revocation denies receipt recovery for already committed evidence. They also exercise a request queued behind revocation and confirm it receives a signed rejection. |
| Transient failures and ordering | `TestSpoolDrainBackoffAndOrdering` injects a lost transport response, an interrupted body, and HTTP 408, 429 and 5xx. It checks exact request bytes, sequence order, jitter bounds through the 1-minute cap, and the reset after an acceptance. `TestSpoolDrainCancelsBackoffWithoutRetiring` checks cancellation with both records retained. |
| Commit failure and PostgreSQL restart | `TestMeshInjectedCommitFailureIsNeverAcknowledged` checks that a failed transaction returns unsigned 503 and leaves the mark and row count unchanged. `TestRepositoryPostgresCrashRecovery` recovers the stored receipt time after an abrupt PostgreSQL restart. |

## Checks run

- `make check` with the Python dependencies in `models/test-requirements.txt`.
  The initial run used system Python without `rfc3339-validator` and failed
  four timestamp format assertions. The pinned environment passed.
- `make cross-build` for Windows amd64 and Darwin arm64.
- `make database-check` against PostgreSQL, including the Tailcat endpoint
  integration, controller replay checks and revocation tests.
- `make storage-crash-check` with isolated PostgreSQL server tools.
- `make contract-check` with 331 golden vectors, 79 wire cases and 29 reader versions.

## Limits

The endpoint restart path also has spool commit-boundary subprocess tests.
The controller reply-loss test closes an HTTP connection after COMMIT and
then restarts the controller listener and repository. It does not kill a
controller process in that interval.

The same-host run uses a test DERP relay and fixture sensor readers. Installed
Windows LocalService delivery, target hardware, WAN/NAT and a live direct
connection switching to DERP during a drain remain untested. A revoked peer
denied before HTTP presents a connection failure to the endpoint. A received
HTTP denial or verified revocation response stops delivery with the head
retained. Power loss, acknowledgement key rotation, deployed storage, and
recovery after the original evidence row is pruned remain unqualified.
