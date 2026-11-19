# Signed device repository, DB02 #83

`NewPostgresRepository(ctx, db, RepositoryConfig{DeploymentID: ...})` binds a
migrated PostgreSQL database to one operator-configured deployment. A different
deployment cannot reuse that database. `Now` defaults to the controller clock;
test clocks must be safe for concurrent calls. Never populate either value from
request metadata. Database/session credentials and device signing keys are
separate from mesh admission, console sessions and future chain signers.

Fixed v1 sequence, lifetime and rejection values come from the named constants
in `packages/contracts/envelopes_v1.go`. Repository constants name challenge
entropy and the PostgreSQL uniqueness SQLSTATE. Migration SQL retains the
versioned schema bounds; changing a Go constant cannot redefine an applied
migration.

The [#18 TLS admission service](../../infra/enrollment/README.md) calls the
bootstrap repository operations. The existing `/v1/telemetry` fixture keeps its
memory store and normalized digest. Repository success means its transaction
committed; it does not sign an acknowledgement, authenticate a live mesh peer
or establish sensor truth. The mesh handler signs acknowledgements (#89).

## Transactions and callers

1. `IssueBootstrapToken`, `StartEnrollment` and `AdmitEnrollment` implement #18's
   operator-authorized bootstrap flow. Final admission locks the token, verifies
   the network proof and commits token/challenge consumption, signed enrollment
   and a unique network binding together. `NetworkBinding` reads public binding
   metadata without retaining the plaintext proof. Route authorization and
   transport behavior are in the linked enrollment guide.
2. Internal signing-only callers can use `CreateEnrollmentChallenge` with an
   authorized device ID, signing public key
   and opaque authorization-record reference. The repository generates 256 random
   bits, stores the binding and expires it after ten minutes. Store no bootstrap
   credential in that reference. Authorization-record issuance, revocation and
   delivery are caller responsibilities; a reference alone proves no authority.
   `Enroll` validates the enrollment v1 signature and configured deployment,
   locks the challenge, checks its binding, consumption and expiry, and inserts
   the signed identity with high-water mark 1. Challenge consumption commits in
   that same transaction. Conflicting device/key bindings never replace an
   enrollment. These internal signing-only operations grant no network admission.
   No key rotation or re-enrollment operation exists. Bootstrap uses the same
   transaction-local signing implementation rather than an independently
   committing `Enroll` call.
3. After authenticating and authorizing the peer, #24/#89 call `AcceptEvidence`.
   It locks the enrolled device row, rejects a revoked binding, verifies the
   evidence v1 envelope using the stored key, and checks the high-water mark.
   An exact retry at a consumed sequence returns the original stored receive
   time if the digest matches the row. A new request must pass the clock check
   after locking. Evidence and the new mark commit together before the
   repository returns the stored receive time.
4. `Device` and `Evidence` read deployment-scoped stored records for later
   authorized consumers. They are not an authenticated receipt lookup service.
5. `RevokeDevice` (#90) is called only by
   `POST /console/api/devices/{id}/revocation`, behind fresh-admin, CSRF and
   Origin checks. The actor comes from the session. It locks the same device row
   as `AcceptEvidence`, reads the clock after the lock, sets
   `device_enrollments.revoked_at` and appends one `device_revocation_events`
   row in one transaction. A sample that holds the lock commits first, with a
   receive time no later than `revoked_at`. A sample queued behind the
   revocation re-reads the row and is rejected with `revoked_key`. A repeat
   returns the original record and writes nothing. Revocation is permanent; no
   reinstatement or re-enrollment exists.

Writes explicitly use Read Committed and `SET LOCAL synchronous_commit=on`.
This overrides an asynchronous session default. PostgreSQL must still use
appropriate durable storage, `fsync=on` and `full_page_writes=on`; this code
does not qualify a host or storage device. See PostgreSQL's
[row locking](https://www.postgresql.org/docs/17/explicit-locking.html#LOCKING-ROWS)
and [WAL settings](https://www.postgresql.org/docs/17/runtime-config-wal.html).

Evidence preserves exact decoded payload bytes, the complete signed envelope,
the canonical signed-request fingerprint, collection time and receipt time.
JSONB stores envelope metadata; it never replaces `payload_bytes` for hashing.
Nullable telemetry metrics, missing reasons and explicit units remain in those
bytes. Payload digests and request fingerprints are different values; neither
is a chain commitment. All records remain off-chain.

The high-water mark is independent of sample retention. It belongs to the
deployment/device across restarts, keys and request types. Future diagnostics
and federated consumers must lock and advance this same row atomically with
their records. Never reconstruct the mark from telemetry history, expose an
advance-only operation, or reset it after pruning or restoring data.

## Failure and integration boundaries

`RepositoryRejection` carries a contract/storage reason and, for replay
rejections, a known mark. These are internal outcomes. Admission handlers own
authorization precedence, safe disclosure, transport status and signed
acknowledgements. Missing reads return `ErrRepositoryNotFound`; database errors
wrap `ErrRepositoryUnavailable`. Context cancellation reaches database calls.
Do not return underlying database errors to clients or log their private data.

Any commit error is unavailable/uncertain, never success. A connection lost
during COMMIT can leave either a committed transaction or a rolled-back one.
An authenticated retry of the exact stored request can recover its receipt.
A `replay` rejection provides no proof of receipt. Restoring a stale backup
requires sequence/revocation reconciliation before ingestion.

Migration 003 leaves candidate `devices`/`telemetry_samples` untouched. They
lack the provenance needed to establish signed enrollment trust. The trusted
tables have no mandatory mesh credential.

`revoked_at` stays the single admission flag. Tunnel admission and each mesh
request read it through `NetworkPeerBinding`; ingestion re-reads it under the
row lock. A row revoked by hand, for example before migration 006, has no audit
record. `RevokeDevice` then returns `ErrRevocationUnrecorded` (HTTP 409) rather
than invent an actor. The static relay admission file is not updated.

Run `make database-check` with `TEST_DATABASE_URL` for database integration and
writer-kill tests. Run `make storage-crash-check` with local PostgreSQL server
tools for a fresh isolated cluster's abrupt shutdown/recovery test. See the
[PR validation evidence](https://github.com/i-got-this-faa/device-audit/pull/186#issuecomment-6359146745).
