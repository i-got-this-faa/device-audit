# Reproducible federated candidate aggregation, FED03 #43

Issue `#43` aggregates persisted compatible updates (`FED09 #114`) under the declared `sample-count-weighted.v1` policy into reproducible unapproved candidate artifacts (`FED07 #112`) without touching `model_references.active`.

## Implemented scope

- **Schema (`infra/database/migrations/011_federated_aggregation.sql`)**: Adds append-only `federated_aggregations` recording participant inputs (`participants` JSON, sample total, canonical `input_sha256`), `weights_bytes` / `weights_sha256`, candidate artifact identity (`model_artifacts` FK), or terminal failure reason (`no_updates`, `insufficient_participants`, `aggregation_failed`, `cancelled`) via `BEFORE INSERT` guards verifying `federated_updates` membership and immutability triggers.
- **Aggregation primitives (`packages/federated/aggregation.go`, `models/src/device_audit_models/federated.py`)**: Implements `sample-count-weighted.v1` using matching CPython `math.fsum` / `exactFloat64Sum` summation (including negative-zero normalization), canonical length-prefixed `input_sha256`, and deterministic UTF-8 / float-normalized `logistic-baseline.v1` and `device-audit.federated-candidate.v1` serialization producing bit-for-bit identical bytes and SHA-256 digests between Go and Python.
- **Controller repository (`internal/controller/federated_aggregation.go`, `federated_updates.go`, `packages/federated/federated.go`)**: Adds `AggregateRound` and `Aggregation` on `Coordinator`. Binds decoded round records to the queried deployment/round identity, reads only persisted `federated_updates` rows after round closure, verifies existing unapproved candidate artifact bytes before reuse (refusing pre-approved collisions), leaves `model_references.active` unchanged on both success and failure, and recomputes participant commitments on read.

## Evidence ledger

| Case | Evidence source | Verified behavior |
| --- | --- | --- |
| Go/Python bit-for-bit reproducibility | `TestWeightedAverageAndReproducibleLogisticCandidate`, `models/tests/test_federated.py` | Both Go and Python compute identical `input_sha256` (`bca4312ae...`), baseline `logistic-baseline.v1` candidate SHA-256 (`e30038982...`), and UTF-8 / scientific-float / negative-zero candidate SHA-256 (`d0644649a...`) regardless of participant input order; full `make model-check` (100 tests including `test_held_out.py`) passes. |
| Candidate build, model loading & active slot preservation | `TestFederatedAggregationReproducibleLogisticCandidateAndRetry` | Aggregates `device:a` (10 samples) and `device:b` (30 samples) over `logistic-baseline.backblaze-2013.v1`, writes an unapproved loadable candidate (`health.LoadControllerModel` passes with ML05 report), leaves `model_references.active` untouched, rejects open rounds before deadline, and preserves candidate identity across controller restarts and actor changes. |
| No-update, insufficient-participant, cancelled & failure safety | `TestFederatedAggregationFailuresLeaveActiveUnchangedAndRetrySafely` | Closed 0-update round (`ErrNoUpdates`), closed 1-of-2 round (`ErrInsufficientParticipants`), cancelled round (`ErrRoundNotOpen`), and corrupt stored update (`ErrUpdateCorrupt`) record terminal failures, preserve failure state on retry, store zero candidate artifacts, and leave `active`/`candidate` references untouched. |
| Concurrency, DB triggers & at-rest tampering | `TestFederatedAggregationConcurrencyDatabaseGuardsAndSyntheticCandidate` | 8 concurrent `AggregateRound` calls create once and return identical records; triggers block updates, deletes, open-round inserts, and forged `succeeded` inserts lacking matching `federated_updates` rows; tampered participant `sample_count` fails closed with `ErrAggregationCorrupt` while preserving cancellation/unavailability errors; pre-approved or corrupt candidate collisions refuse reuse; mismatched stored round records are rejected. |

## Explicit boundaries and open items

- **Held-out evaluation & promotion**: Evaluating candidate artifacts against ML05 gates and promoting candidates to `active` belong to downstream issue `#115` (`FED10`).
- **Console views & trigger endpoints**: Console participant/metric views (`WEB04 #49`) and held-out forecast exposure (`#118`) remain separate.
