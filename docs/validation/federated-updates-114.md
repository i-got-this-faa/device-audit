# Validating signed federated updates, FED09 #114

Issue `#114` implements durable validation, replay protection, and persistence for signed `FederatedUpdateV1` participant submissions before downstream aggregation (`FED03 #43`) or promotion (`FED10 #115`).

## Implemented scope

- **Schema (`infra/database/migrations/010_federated_updates.sql`)**: Adds append-only `federated_updates` keyed by `(deployment_id, round_id, device_id)` with `UNIQUE (deployment_id, device_id, sequence)` and foreign keys to `federated_rounds`, `federated_round_participants`, `device_enrollments`, and `model_artifacts`. Constraints and triggers require verified `sha256(weights_bytes) = update_sha256`, open-round window compliance, matching candidate/base/feature/parameter counts, eligible admitted unrevoked device keys, finite binary64 weights, and row immutability.
- **Federated domain interface (`packages/federated/federated.go`)**: Adds `AcceptedUpdate`, update sentinel errors (`ErrUpdateInvalid`, `ErrUpdateIncompatible`, `ErrUpdateConflict`, `ErrUpdateExpired`, `ErrUpdateReplay`, `ErrUpdateUnauthorized`, `ErrUpdateCorrupt`), and `AcceptUpdate` / `AcceptedUpdates` on `Coordinator`.
- **Repository enforcement (`internal/controller/federated_updates.go`)**:
  - Locks in `federated_rounds -> federated_round_participants -> device_enrollments` order to prevent deadlocks with `AcceptParticipant`, `AcceptEvidence`, and `RevokeDevice`.
  - Authenticates deployment scope, enrolled key, unrevoked state, and Ed25519 signature before inspecting retries, returning identical retries with `created=false` and differing submissions with `ErrUpdateConflict`.
  - Enforces compatibility, round/controller clock windows (re-reading the clock after lock acquisition), and monotonic `device_enrollments.last_sequence` shared across telemetry and updates.
  - Verifies stored digests, weights, and envelopes on `AcceptedUpdates`, failing closed with `ErrUpdateCorrupt` on at-rest tampering.
- **Mesh HTTP endpoint (`internal/controller/mesh.go`)**: Exposes `POST /v1/federated/updates` on `MeshHTTPServer` with `Cache-Control: no-store`, mesh peer binding verification, query-string rejection, 64 KiB body cap (`413`), and clean rejection status codes.

## Evidence ledger

| Case | Evidence source | Verified behavior |
| --- | --- | --- |
| Mesh HTTP boundary & sizing | `TestMeshHTTPFederatedUpdateBoundary` | Verifies `201 Created`, `200 OK` on retry, `400` on query parameters, `413` over 64 KiB, `403` on wrong peer, `409` on conflict, and `503` when unsupported; invalid/unauthenticated requests stop before repository calls. |
| Valid updates, restart, sequence monotonicity | `TestFederatedUpdatesValidRestartAndSequenceProtection` | Accepts updates via `AcceptUpdate` and `POST /v1/federated/updates` (auto-admitting eligible snapshot participants on first update), retains updates identically across repository restart and round deadline close, rejects conflicting updates (`ErrUpdateConflict` / `409`), and enforces one shared `device_enrollments.last_sequence` mark across `AcceptEvidence` and `AcceptUpdate`. |
| Incompatibility, revocation, deadline, expiry, nonfinite/oversized | `TestFederatedUpdatesRejectsWrongBaseIneligibleRevokedBadSigExpiredAndNonfinite` | Rejects mismatched base/digest/candidate/feature/parameter_count, unknown/ineligible/unlisted/revoked devices (including revocation after admission and deadline crossed while blocked on `device_enrollments`), wrong key/signature/deployment, `NaN`/`+Inf` weights, >4096 parameters, and bad `update_sha256` without mutating `federated_updates` or `last_sequence`. |
| Concurrent duplicates & conflicts | `TestFederatedUpdatesConcurrentDuplicateAndConflicting` | 8 concurrent identical submissions yield 1 creation and 7 clean repeats; 8 concurrent distinct submissions yield 1 creation and 7 `ErrUpdateConflict` errors. |
| DB triggers & at-rest corruption | `TestFederatedUpdatesDatabaseGuardsAndAtRestCorruption` | Triggers block `UPDATE`, `DELETE`, tampered digests, wrong parameter count, unadmitted/ineligible inserts; `AcceptedUpdates` fails closed with `ErrUpdateCorrupt` on at-rest envelope tampering. |

## Explicit boundaries and open items

- **No aggregation or promotion**: Averaging accepted updates (`FED03 #43`) and evaluating/promoting candidate models (`FED10 #115`) remain separate downstream work.
- **No console UI or endpoint mesh sender changes**: Console participant/metric views belong to `#49` (`WEB04`); endpoint-agent training (`--train-federated-update`) stages signed `FederatedUpdateV1` JSON files on disk (`#42`) and mesh upload scheduling/retries are separate.
