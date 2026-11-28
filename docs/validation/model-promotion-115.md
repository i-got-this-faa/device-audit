# Evaluation-gated candidate promotion, FED10 #115, 28 November 2026

Issue `#115` makes a stored held-out evaluation the only route to an active
model. Migration `013_model_promotion.sql`, the
[promotion contract](../../packages/contracts/model-registry-v1.md) and the
[console routes](../../internal/controller/model-registry.md#evaluation-and-promotion-fed10-115)
evaluate each candidate against the frozen ML05 thresholds and the active model,
and record one promotion or rejection.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Evaluate each candidate against the active baseline and frozen held-out thresholds | `TestModelPromotionGatesCandidateOnHeldOutEvaluation` submits publisher-signed reports. The controller rereads every metric through `health.AssessEvaluationReport` and applies the 14 ML05 gates, then the six `fed10.v1` regression gates against the model active at decision time. `TestDecideMatchesSharedVectors` and `models/tests/test_promotion.py` run the same nine vectors in Go and Python. |
| Persist metrics and the authorized decision | `model_evaluations` keeps the report bytes, verdict and reasons; `GET .../evaluation` returns the metric intervals. `model_promotions` keeps the outcome, reasons, baseline, each regression check, time and actor. Both need a fresh administrator to write and a viewer to read. A restart in the test reads the same decision. |
| Poor calibration leaves the active model unchanged | A report with a negative Brier skill and slope 0.4 is `fail`; the promotion is `rejected` with `gate_failed:brier_skill` and `gate_failed:calibration_slope_low`, nothing becomes active, the candidate slot is cleared and `PUT active` is `not_approved`. The recorded ML06 report fails exactly four gates (`TestAssessEvaluationReportFailsTheRecordedML06Candidate`). |
| Regression leaves the active model unchanged | A candidate that passes ML05 with average precision 0.19 against the active 0.20 is `rejected` with `regression:active_average_precision`; `synthetic.3` stays active. A candidate at 0.25 is promoted with the active model recorded as its baseline. |
| Missing evaluation data and interrupted evaluation leave the active model unchanged | Too few test devices, a missing count, a missing metric, `evaluation_error`, a reused held-out set, another model and a different bootstrap are each `blocked` (`TestAssessEvaluationReportSeparatesFailedFromBlocked`). A blocked candidate is `rejected` with `evaluation_blocked`. No evaluation at all is 404 and nothing changes. An active model with no stored evaluation gives `baseline_not_comparable`. |
| Promotion cannot be forced by a successful aggregation alone | An aggregated candidate is unapproved. The approval route is removed, a promotion needs a signed evaluation, and a trigger refuses an approval without a stored passing evaluation. The test tries a direct approval of a failed model and `UPDATE`/`DELETE` on evaluations and promotions; the database refuses each. |

## Other checks

- Eight concurrent identical promotions create one decision and one active model
  (`TestModelPromotionConcurrentRequestsDecideOnce`, run with `-race`).
- A forged signature, a stranger key, a modified report, a viewer and a stale
  administrator cannot submit evidence. A report for another model stores nothing.
- `make lint test fake-check contract-check database-check`,
  `CGO_ENABLED=0 make cross-build`, `go fmt` and `git diff --check` passed
  against PostgreSQL 17.11. `go test -race ./...` passed. `models/tests` passed
  except `test_held_out`, which needs numpy 2.5.5; numpy was not available in
  this shell, and the change does not touch that module.

## Not tested

- No federated candidate has a real held-out report. `device_audit_models.held_out`
  scores a train-only logistic fit and has no input for aggregation provenance, so
  reports in the tests are synthetic ML05 reports with passing or failing metrics.
  On current evidence no model can pass: the recorded ML06 report fails four gates.
- No publisher signing tool or key issuance exists; tests sign with a test key.
- The `fed10.v1` tolerances are a conservative first policy declared before any
  candidate, not tuned or validated against model output.
- The health path can read reports through `PostgresRepository.EvaluationReport`,
  but the controller binary does not yet wire a `HealthConfig`.
- Console views for evaluations and decisions (`WEB04 #49`) and endpoint download of
  the active model over the mesh are separate work.
- The registry still has no revocation or rollback history for approved models.
