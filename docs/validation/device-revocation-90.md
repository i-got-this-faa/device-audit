# SEC09 #90 durable device revocation

Device revocation authority for
[issue #90](https://github.com/i-got-this-faa/device-audit/issues/90), based on
main `77e4c96`. The wire contract commit precedes the controller consumer.
Networking keys, device signing keys and chain keys are unchanged; nothing is
written on-chain.

## What runs

`POST /console/api/devices/{id}/revocation` on the administrator HTTPS
boundary requires an admin session authenticated within five minutes, a valid
CSRF token and an allowed Origin. The body is a
`device-audit.device-revocation-request.v1` with an opaque `reason_reference`.
`RevokeDevice` locks the device row that ingestion locks. It then sets
`device_enrollments.revoked_at` and appends one `device_revocation_events` row
in a single transaction.

| Outcome | HTTP | Body |
| --- | --- | --- |
| Revoked now | 201 | `device-audit.device-revocation.v1` record |
| Already revoked through this route | 200 | the original record; no second event |
| No session / viewer / stale admin / bad CSRF / foreign Origin | 401/403 | denial; no state change |
| Path/body mismatch, query, unknown or forged field, free-text reason | 400 | no state change |
| Unknown device | 404 | no state change |
| Revoked by hand without a record | 409 | no actor is invented |
| Storage failure or uncertain COMMIT | 503 | repeat the request to learn the outcome |

After revocation, the existing checks deny the device:

- Tailcat `AllowClient` and each mesh request use `NetworkPeerBinding`, which
  excludes revoked rows. A revoked peer on an open tunnel gets an unsigned 403
  on its next request, and the tunnel is disconnected.
- `AcceptEvidence` re-reads `revoked_at` under the row lock and rejects with
  signed `revoked_key`.

## Acceptance ledger

| Acceptance | Check | State | Evidence |
| --- | --- | --- | --- |
| Authorized revocation persists admission state | Fresh admin gets 201. The record's actor, reason, enrollment digest and time match the session and stored row. Tunnel admission is then refused | proved, PostgreSQL 17.11 | `TestRevocationHTTPAuthorizationAndAuditRecord` |
| Unauthorized revocation is denied | No session 401. Viewer, admin authenticated 6 minutes ago, wrong CSRF and foreign Origin each get 403. Malformed bodies get 400 and an unknown device 404. None writes an event or revokes | proved | same test |
| Fresh and established peers are rejected at the controller boundary | After revocation: tunnel admission lookup is refused, an established peer's request is 403 with disconnect, and direct ingestion returns `revoked_key`. The sample accepted before revocation remains | proved | `TestRevocationRejectsFreshAndEstablishedPeersAcrossRestart` |
| Revocation survives controller restart | The same three checks pass after closing the pool and building a new repository and handler. A repeat returns the original record, and there is one event | proved | same test |
| Revocation survives a PostgreSQL crash | Two devices revoked, then `pg_ctl -m immediate stop`. A revocation during the outage fails closed. After crash recovery the peer is refused, evidence returns `revoked_key`, and both original records are returned unchanged | proved, isolated 17.11 cluster | `TestRepositoryPostgresCrashRecovery` (`make storage-crash-check`) |
| A queued sample is never admitted after revocation | A revocation holds the row lock. A mesh sample passes peer admission (the revocation is uncommitted) and waits on the lock, as observed in `pg_stat_activity`. After the revocation commits, the sample gets a signed `revoked_key` and nothing is stored | proved | `TestRevocationRejectsSampleQueuedBehindIt` |
| A revocation waits for an in-flight sample | A sample holds the row lock and the revocation waits. The sample is accepted with `received_at` no later than `revoked_at`. The next sample is denied | proved | `TestRevocationWaitsForInFlightSample` |
| Concurrent revocations leave one audit event | Eight writers on two connection pools: exactly one creates the record, and all eight return the same record | proved | `TestRevocationConcurrentAdministratorsRecordOnce` |
| Revocation is atomic | A deferred trigger fails at COMMIT: 503-class error, device still admitted, no event. After the trigger is dropped, revocation succeeds | proved | `TestRevocationRollbackUnrecordedAndUnavailableStore` |

## The tests detect regressions

- With the `revoked_at` check removed from `AcceptEvidence`, the queued-sample
  and restart tests fail.

## Commands

Linux x86_64, Go 1.27.3, a disposable PostgreSQL 17.11 cluster on loopback,
18 November 2026:

- `make check`: passed.
- `make database-check` with `TEST_DATABASE_URL`: passed, including the real
  Tailcat endpoint round trip and migration 006 upgrade tests.
- `make storage-crash-check`: passed; the log shows crash recovery.
- `make contract-check`: passed, 301 golden vectors, 75 wire cases, 27 reader
  versions.
- `CGO_ENABLED=0 make cross-build`: passed. With cgo the darwin step fails in
  the local Nix shell, the same as on main (#24, #89 records).
- The new revocation tests passed three consecutive `-race` runs.

## Not covered

- Rejections over a real Tailcat tunnel. The tests inject the tunnel peer, as in
  #24 and #89. The real tunnel is exercised only on the accepted path.
- An open tunnel is not cut when the revocation commits; it is cut on the
  peer's next request. The relay admission file is static and is not updated.
- A real IdP. Sessions are synthetic test rows.
- Reinstatement, key rotation and re-enrollment (#130). No console page calls
  the revocation route yet.
- Windows controller hosting, a deployed PostgreSQL host and off-host backup
  restore. Restoring a backup taken before a revocation re-admits the device
  until the revocation is repeated.
