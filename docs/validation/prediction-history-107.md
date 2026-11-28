# Controller prediction history and queries validation, ML11 #107

Issue `#107` implements durable append-only prediction and health persistence in PostgreSQL (`device_predictions`) and bounded viewer/administrator query endpoints on `DeviceStateService`.

## Implemented scope

- **Schema (`infra/database/migrations/009_prediction_history.sql`)**: Adds `device_predictions` with provenance columns for rules (`rules_version`, `rule_reason`), nullable health verdict (`health_status`, `probability`, `probability_unit`, `horizon_hours`, `unknown_reason`), model (`model_status`, `model_error`, `model_version`, `model_sha256`, `policy_version`, `policy_sha256`, `evaluation_sha256`), `device_evidence` reference (`sequence`, timestamps, payload/request digests, source, schema), CT03 feature summary and vector, and ML10 7-day/21-day fault baseline metadata alongside embedded `PredictionV2`. Foreign keys and database triggers enforce append-only immutability and valid evidence/approval references on insert.
- **Health feature/window provenance (`packages/health/rules.go`)**: Extends `Assessment` with `Features`, `CurrentFaultWindow`, and `BaselineFaultWindow` metadata populated by `AssessHealth`.
- **Wire contracts (`packages/contracts/prediction_history_v1.go`, `prediction-history-v1.md`)**: Defines `PredictionHistoryV1`, `LatestPredictionV1`, and `PredictionHistoryRecordV1` with `Validate(deviceID)` rejecting inconsistent provenance, forged risk without complete features/model/evidence, or `stale_evidence` without an evidence reference.
- **Controller repository & HTTP endpoints (`internal/controller/prediction_history.go`, `device_state.go`)**:
  - `EvaluateAndRecordDeviceHealth` and `RecordDeviceHealth` evaluate and persist inside repeatable-read synchronous-commit transactions, verifying `device_evidence` byte digests and `model_approvals`.
  - `GET /console/api/devices/{id}/predictions` validates `deployment_id`, `[from, to)` <= 31 days, `limit` 1..100, and `(as_of, id)` keyset cursors, failing closed (`500` `ErrPredictionEvidenceBroken`) on missing or altered underlying evidence/approvals.
  - `GET /console/api/devices/{id}/predictions/latest` derives `current_health` from `expires_at` against the controller clock, failing closed to `unknown` (`stale_evidence`) with null probability and horizon once expired.

## Evidence ledger

| Case | Evidence source | Verified behavior |
| --- | --- | --- |
| Schema migration & triggers | `infra/database` tests + `TestPredictionHistoryRejectsWrongScopeAndBrokenEvidenceReferences` | Schema version 9 migrates cleanly on PostgreSQL 17; triggers block `UPDATE`, `DELETE`, and tampered `evidence_payload_sha256` inserts. |
| Contract invariants | `TestPredictionHistoryRecordValidation` | Validates known/unknown/no-evidence records and rejects cross-device, invalid `model_status`, `stale_evidence` without evidence, and mismatched digests. |
| End-to-end persistence, pagination, restart, staleness | `TestPredictionHistoryPersistencePaginationRestartAndStaleness` | Records no-model (`model_unavailable`), no-evidence (`insufficient_evidence`), real telemetry v2 (incomplete features), fixture SMART (`healthy`), and stale assessments; verifies stable `(as_of, id)` tie-breaking across pages, controller restart retention, `/latest` expiry transition to `stale_evidence`, revoked device readability, and 400/401/403/404 handling. |
| Broken reference fail-closed | `TestPredictionHistoryRejectsWrongScopeAndBrokenEvidenceReferences` | Rejects wrong deployment scope, missing/tampered evidence or mismatched evaluation digests on write (`ErrPredictionEvidenceBroken`) and returns HTTP `500` without disclosing a risk value when persisted `device_evidence.payload_bytes` is corrupted at rest. |

## Explicit boundaries and open items

- **Web console view**: Rendering prediction history and alerts in `apps/web-console` belongs to open downstream issue `#39` (`WEB03`).
- **Telemetry/model scope**: Real `device-audit.telemetry.v2` samples omit SMART counters and the ML06 baseline model failed `ml05.v1` gates, so production evaluations continue to persist `unknown` (`model_unavailable` or `insufficient_evidence`) with null risk/horizon.
