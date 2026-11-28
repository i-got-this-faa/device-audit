# Forecast provenance v1, FED13 #118

`DeviceForecastV1` and `ForecastSourceV1` tell a workflow whether a forecast may
be acted on, and what it rests on. Both are derived at read time from stored,
append-only records (prediction history, model evaluations, promotions,
approvals and federated aggregations). Nothing is cached, so a controller
restart changes no answer.

## Device forecast

`GET /console/api/devices/{id}/forecast?deployment_id=…` (viewer) returns the
newest persisted prediction judged at the controller clock.

| `status` | `reason` | Meaning |
| --- | --- | --- |
| `available` | none | Fresh prediction from an evaluated, promoted, still active model. `forecasts` is filled. |
| `stale` | `prediction_expired` | The prediction passed `expires_at`. |
| `stale` | `stale_evidence` | The assessment itself was made on stale telemetry. |
| `stale` | `model_superseded` | Another model is active now. |
| `unavailable` | `no_prediction` | No assessment was recorded for the device. |
| `unavailable` | `model_unavailable`, `insufficient_evidence` | The recorded assessment is unknown. Probability and horizon stay null. |
| `unavailable` | a model source reason below | The recorded model is not an eligible source. |

`forecasts` is empty unless `status` is `available`. A null probability or
horizon is never converted to zero. An available forecast also carries
`model` (version, artifact and evaluation digests, feature version, promotion
policy and time, whether it is active, and the originating federated round
when there is one), `observation_window` (the feature version, window and
completeness) and `evidence` (the telemetry sample it rests on).

## Model and round source

`GET /console/api/models/{version}/forecast-source` (viewer), and
`PostgresRepository.ForecastSourceForRound` for Go workflow code, return
`available` or `unavailable`:

| `reason` | Cause |
| --- | --- |
| `round_not_aggregated` | The round exists and has produced no aggregate. |
| `round_failed` | Aggregation failed; `round_failure_reason` has the cause. No model. |
| `candidate_unevaluated` | No stored held-out evaluation. An approval written around the database gate does not count. |
| `evaluation_not_passing` | The stored verdict is not `pass`. |
| `candidate_rejected` | A promotion decision rejected it. |
| `not_promoted` | Evaluated and passing, but not promoted or approved. |

A model is a source only with a passing evaluation that its approval cites. An
aggregate that has not been evaluated is never an approved forecast source.
