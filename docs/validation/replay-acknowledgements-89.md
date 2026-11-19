# SEC08 #89 replay rejection and signed acknowledgements

TEL09 #96 changes exact retries on the existing mesh POST. After peer and
device authorization, the controller compares the signed request digest to the
stored row. A match returns the original signed `accepted` acknowledgement,
including the stored receive time. A mismatch or missing row at a consumed
sequence still receives a rejection. Receipt recovery checks revocation before
looking up the row. The wire format and acknowledgement key pin are unchanged.
See the [TEL09 evidence](spool-drain-96.md) for the current tests.

## Original SEC08 validation

The sections below record the mesh evidence replies first shipped for
[issue #89](https://github.com/i-got-this-faa/device-audit/issues/89). Based on
main `32a14f3`. No wire schema changed. The controller acknowledgement key is
separate from the mesh, TLS, device and chain keys.

## What runs

`POST /v1/evidence` on the mesh listener still verifies the peer and envelope
before ingestion (#24). `AcceptEvidence` locks the device row, checks the
high-water mark and commits the sample with the new mark. It returns the stored
receive time only after COMMIT succeeds. The handler then signs a
`device-audit.acknowledgement.v1` with the key from `--ack-key-file`:

| Outcome | HTTP | Body |
| --- | --- | --- |
| Committed | 200 | signed `accepted`, `last_sequence` = request sequence |
| Replay or other envelope rejection for the peer's own device | 400/403/409 | signed `rejected`; `last_sequence` only when read under the lock |
| Unadmitted or misbound peer, or uncorrelatable request | 400/403 | plain text, unsigned |
| Storage failure or uncertain COMMIT | 503 | plain text, never signed |

The endpoint (`--controller-ack-key-file`) and the tests use
`AcknowledgementV1.VerifyForEvidence`. It checks the pinned key, deployment,
device, request version, key ID, sequence and `request_sha256`.

## Acceptance ledger

| Acceptance | Check | State | Evidence |
| --- | --- | --- | --- |
| Concurrent copies of one signed envelope produce one accepted evidence record | 16 goroutines send one envelope through the mesh handler into PostgreSQL. Exactly one `accepted`. The device has one sample and mark 7 | proved, PostgreSQL 17.11 | `TestMeshConcurrentDuplicatesAcceptOnce` |
| Duplicates get a contract-valid acknowledgement without advancing state twice | Each of the other 15 responses is HTTP 409 with a signed `replay`, `last_sequence` 7, that passes `Validate` and `VerifyForEvidence`. The accepted `received_at` equals the stored row | proved | same test |
| Out-of-order and replay across controller restart preserve the sequence policy | Accept 5, then reject 3. Close the pool and build a new repository and handler. Reject 5, 4 and 2 at mark 5, accept 7, reject 6 at mark 7. Stored samples are exactly {5, 7} | proved | `TestMeshSequencePolicySurvivesControllerRestart` |
| Replay across a real tunnel and process restart | A fresh endpoint process over Tailcat gets `accepted` for 2. After the server and client restart, it gets a signed `replay` for 2 and `accepted` for 3 | proved | `TestEndpointEnrollmentPostgres` (`make database-check`) |
| An injected transaction failure cannot acknowledge an uncommitted sample | A deferred constraint trigger fails at COMMIT. The reply is 503 with no acknowledgement, and there is no sample and no mark change. After the trigger is dropped, the same envelope is accepted | proved | `TestMeshInjectedCommitFailureIsNeverAcknowledged` |
| Signed rejections never name another device | Misbound-peer, unknown-peer and wrong-deployment requests get no signed body. Forged, altered, wrong-key, expired and future requests get a signed rejection with a null mark | proved | `TestEvidenceVerificationRejectsBeforeIngestion` |

## The tests detect regressions

- Without `FOR UPDATE` on the device row, the concurrency test fails. Duplicates
  return 503 from the unique key instead of a signed replay.
- If a `storage_unavailable` acknowledgement is signed, the injected-commit test
  fails.

## Commands

Linux x86_64, Go 1.27.3, a disposable PostgreSQL 17.11 cluster:

- `make check`: the first run printed `FAIL`, and its output was cut off
  before the test name. Two later `make check` runs and three `make test` runs
  passed. The new mesh tests passed 15 consecutive `-race` runs. The cause is
  not identified.
- `make database-check`: passed, including the real Tailcat endpoint round trip.
- `make contract-check`: passed, 289 golden vectors.
- `CGO_ENABLED=0 make cross-build`: passed. With cgo the darwin step fails in
  the local Nix shell, the same as on main (#24 record).
- `openssl genpkey -algorithm ed25519` and `openssl pkey -pubout` output load
  through the controller and endpoint key loaders.

## Not covered

- Rejections over a real Tailcat tunnel. They are tested with an injected peer.
- A killed controller process between COMMIT and reply. `TestRepositoryWriterKillBeforeAndAfterCommit`
  covers the repository side. The reply is lost and a retry gets `replay`.
- Acknowledgement key rotation, receipt retention and authenticated receipt
  lookup. A `replay` is not proof that a pending payload was stored.
- Windows controller hosting and a deployed PostgreSQL host.
