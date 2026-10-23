# DB02 #83 repository evidence

On 23 October 2026 the owner selected repository-only scope, real writer kills
before/after commit, a disposable PostgreSQL restart, and atomic challenge
consumption with enrollment. Admission authorization and HTTP handlers remain
in #18/#24/#89/#90. This records implementation evidence, not completed release
qualification or patent conformance.

## Observed locally

The checks ran from this worktree using its pinned Nix development shell and
PostgreSQL 17.11 on Linux. Test identities, RFC 8032 keys, metrics and signed
payloads are synthetic. Database operations, independent connections, writer
process termination and PostgreSQL shutdown/recovery are real.

Final validation passed with `make check`, `make cross-build`,
`make database-check`, `make contract-check` and `make storage-crash-check`.
`TEST_DATABASE_URL` selected the disposable cluster for the database checks.
Contract conformance retained 240 golden vectors, 52 wire cases and 16 reader
versions. `make check` included the race detector and 29 Python model tests.

- `make database-check` against a disposable PostgreSQL cluster verifies fresh
  migrations, upgrade preservation, console auth, repository transactions and
  the existing controller startup behavior. Version 2 candidate records and
  console bindings survive version 3 without importing trust.
- Enrollment/challenge consumption roll back together after a database-injected
  failure. Concurrent enrollment consumes a challenge once. Conflicting
  device/key bindings leave no identity or consumed-challenge residue.
- Evidence insertion followed by a failing sequence update leaves no sample
  and no sequence advance. A deferred trigger failure at COMMIT also rolls both
  back. The rolled-back sequence remains usable.
- Sixteen independent connection pools submit the same signed evidence. Exactly
  one transaction succeeds; the other requests are replay rejections. Concurrent
  distinct sequences leave the maximum accepted mark and its sample intact.
- Shared contract fixtures retain exact bytes, envelope/signature, known request
  fingerprint, null metric, unit, missing reason and collection/receipt times.
  A separately signed whitespace variant retains its original byte spelling.
  Reopening the repository retains identity, evidence and replay state. Removing
  sample bodies does not reopen consumed sequences. Gaps and the maximum
  sequence are accepted; exhaustion cannot wrap.
- Wrong deployment, invalid signatures/digests, expiry/future timestamps,
  mismatched or expired challenges, revoked bindings and unavailable storage
  reject writes without advancing state. A writer expiring while waiting for a
  device-row lock is rejected after acquiring it. Cancellation ends a blocked
  writer without partial state.
- Writer subprocesses invoke real repository methods. Test-only PostgreSQL
  triggers block the update after row insertion; the parent observes the
  advisory-lock wait, kills the writer, releases the lock and verifies rollback.
  Separate subprocesses are killed after confirmed commit and before any
  application response. Enrollment/consumption/initial mark and evidence/mark
  remain complete in both committed cases. No production fault hook exists.
- `make storage-crash-check` creates a separate temporary cluster. With
  `fsync=on` and `full_page_writes=on`, it commits enrollment/evidence even though
  the database's session default has `synchronous_commit=off`. Repository
  transactions override that default. `pg_ctl -m immediate` stops the server
  abruptly. An outage write fails; after recovery, signed provenance, challenge
  consumption and mark 2 persist. Enrollment retry is `challenge_reused`;
  evidence retry is `replay`. The PostgreSQL log confirms crash recovery.

## Limits and remaining review

The fixture HTTP endpoint is still unsigned and in memory. No live endpoint,
mesh admission, authorized bootstrap service, wire acknowledgement or receipt
lookup was exercised. Neither owner-to-owner contract review nor a reviewed,
merged PR is established by these checks.

The crash target is opt-in and is not yet run by the CI database job. Local
process/database crashes do not prove host power-loss durability, deployed
storage behavior, HA/failover, off-host backup recovery or stale-backup replay
safety. Retention, production database configuration, least-privilege roles,
revocation authority and its race tests remain follow-on work. A lost COMMIT
response remains an uncertain result requiring future authenticated recovery.
