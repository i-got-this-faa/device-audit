# SEC03 #24 evidence verification

Controller-side verification of signed evidence before durable ingestion, for
[issue #24](https://github.com/i-got-this-faa/device-audit/issues/24). Based on
main `7495d6f`. No wire contract changed. Network identity, signing identity and
chain evidence remain separate.

## What runs

`POST /v1/evidence` on the mesh listener resolves the tunnel key to a committed,
unrevoked binding. It then calls `verifyEvidence` in `internal/controller/mesh.go`.
That pure function returns a contract rejection reason and checks, in order:

1. `Validate()`: schema version, structure, payload bound and payload digest.
2. Deployment, then device, then signing key ID against the binding.
3. The Ed25519 signature against the admitted signing public key. The key comes
   from `device_enrollments.public_key`, never from the request.
4. `TimestampRejection(now)`: expiry and the five-minute future skew.

`AcceptEvidence` runs only after all four checks pass. It keeps its own
signature, timestamp, sequence and revocation checks under the row lock.

## Acceptance ledger

| Acceptance | Check | State | Evidence |
| --- | --- | --- | --- |
| Version, signature, admitted signing identity, peer binding and timestamp policy are verified before durable ingestion | A counting fake repository receives no `AcceptEvidence` call for cross-device, tampered or denied requests | proved | `TestMeshHTTPAdmissionAndBoundary` |
| Forged, altered, wrong-key and misbound-peer requests are rejected | Two devices enrolled through the TLS handlers into PostgreSQL. Each case asserts the HTTP status and reason | proved against PostgreSQL 17 | `TestEvidenceVerificationRejectsBeforeIngestion` |
| Rejections leave no persisted sample | Each case compares the `device_evidence` count and both devices' `last_sequence` before and after | proved against PostgreSQL 17 | same test |
| Rejections emit attributable security events | Each case asserts exactly one JSON log record with `event`, `reason`, tunnel `peer`, bound `device_id` and `claimed_device_id`. The record contains no payload or signature | proved | same test |
| Valid evidence is still accepted | Final request returns 204, stores one sample and advances only device A to sequence 2. No security event | proved | same test |
| Timestamp helper matches the shared freshness policy | `TimestampRejection` agrees with every golden vector, apart from replay | proved | `TestEnvelopeV1GoldenVectors`, `make contract-check` |

Rejection cases in the PostgreSQL test:

| Case | Reason | Status |
| --- | --- | --- |
| Forged: admitted key ID, unrelated signer | `invalid_signature` | 409 |
| Altered payload, digest recomputed, old signature | `invalid_signature` | 409 |
| Altered payload, stale digest | `invalid_payload` | 400 |
| Wrong key: device A envelope signed by device B's key and key ID | `key_mismatch` | 403 |
| Misbound peer: device B's tunnel sends device A's valid envelope | `unauthorized_peer` | 403 |
| Unknown tunnel key (client disconnected) | `unauthorized_peer` | 403 |
| Clock at `expires_at` | `expired` | 409 |
| `issued_at` five minutes and one second ahead | `future_timestamp` | 409 |
| Schema version `device-audit.evidence.v2` | `invalid_payload` | 400 |
| Other deployment, correctly signed | `deployment_mismatch` | 403 |

With `verifyEvidence` disabled, the misbound-peer case returned 204 and stored
device A's sample through device B's tunnel. The test fails in that state.

## Validation

Passed on 17 November 2026, Linux x86_64, Go 1.27.3 from the repository Nix
shell, PostgreSQL 17.11 on loopback:

- `make check`: vet, race suite, Python tests, fixture scenarios and formatting.
- `make database-check` with `TEST_DATABASE_URL`, which includes the real
  Tailcat endpoint round trip in `apps/endpoint-agent`.
- `make contract-check`: 289 golden vectors, 71 wire cases, 25 reader versions.
- `make cross-build` passes with `CGO_ENABLED=0`. Without it, the darwin step
  fails in `runtime/cgo` (`gcc: error: unrecognized command-line option
  '-arch'`). Clean main `7495d6f` fails the same way in this shell.

## Not tested

- The rejection cases inject the tunnel key into the request context. The real
  Tailcat tunnel is exercised only on the accepted path, by the endpoint-agent
  integration test.
- Security events are structured process logs. They are not a durable audit
  table. The durable revocation audit event belongs to #90.
- Replay, out-of-order sequences and signed CT04 acknowledgements remain #89.
- Windows controller hosting was not run for this change.
