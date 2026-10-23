# Signed device repository, DB02 #83

`NewPostgresRepository(ctx, db, RepositoryConfig{DeploymentID: ...})` binds a
migrated PostgreSQL database to one operator-configured deployment. A different
deployment cannot reuse that database. `Now` defaults to the controller clock;
test clocks must be safe for concurrent calls. Never populate either value from
request metadata. Database/session credentials and device signing keys are
separate from mesh admission, console sessions and future chain signers.

This is an internal repository. No production HTTP route calls it yet. The
existing `/v1/telemetry` fixture keeps its memory store and normalized digest.
Repository success means its transaction committed; it does not issue a signed
acknowledgement, authorize a peer or establish sensor truth.

## Transactions and callers

1. After authorizing bootstrap access, #18's admission service calls
   `CreateEnrollmentChallenge` with an authorized device ID, signing public key
   and opaque authorization-record reference. The repository generates 256 random
   bits, stores the binding and expires it after ten minutes. Store no bootstrap
   credential in that reference. Authorization-record issuance, revocation and
   delivery are caller responsibilities; a reference alone proves no authority.
2. `Enroll` validates the enrollment v1 signature and configured deployment,
   locks the challenge, checks its binding, consumption and expiry, and inserts
   the signed identity with high-water mark 1. Challenge consumption commits in
   that same transaction. Conflicting device/key bindings never replace an
   enrollment. No key rotation or re-enrollment operation exists.
3. After authenticating and authorizing the peer, #24/#89 call `AcceptEvidence`.
   It locks the enrolled device row, rejects a revoked binding, verifies the
   evidence v1 envelope using the stored key, and checks the server clock and
   high-water mark. Evidence and the new mark commit together. The clock is read
   after locking, so waiting cannot bypass expiry. No Go mutex serializes writers.
4. `Device` and `Evidence` read deployment-scoped stored records for later
   authorized consumers. They are not an authenticated receipt lookup service.

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

`RepositoryRejection` carries a contract/storage reason and, for freshness
rejections, a known mark. These are internal outcomes. Admission handlers own
authorization precedence, safe disclosure, transport status and signed
acknowledgements. Missing reads return `ErrRepositoryNotFound`; database errors
wrap `ErrRepositoryUnavailable`. Context cancellation reaches database calls.
Do not return underlying database errors to clients or log their private data.

Any commit error is unavailable/uncertain, never success. A connection lost
during COMMIT can leave either a committed transaction or a rolled-back one.
Do not turn a retry's `replay` into idempotent success or proof of receipt.
Authenticated reconciliation and receipt lookup remain future work. Restoring
a stale backup requires sequence/revocation reconciliation before ingestion.

Migration 003 leaves candidate `devices`/`telemetry_samples` untouched. They
lack the provenance needed to establish signed enrollment trust. The trusted
tables have no mandatory mesh credential. #90 must add revocation authority and
qualify its serialization against this device-row lock; the nullable column
and rejection check alone are not that capability.

Run `make database-check` with `TEST_DATABASE_URL` for database integration and
writer-kill tests. Run `make storage-crash-check` with local PostgreSQL server
tools for a fresh isolated cluster's abrupt shutdown/recovery test. See the
[recorded evidence](../../docs/evidence/83-device-repository.md).
