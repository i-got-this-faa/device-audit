# Console prediction view validation, WEB03 #39

Adds `GET /console/devices/{id}/predictions`, rendering the durable prediction history and latest assessment from #107.

## Evidence

| Case | Check | Result |
| --- | --- | --- |
| Model, horizon, explanation, evidence, forecasts, evidence-sample link | `TestDevicePredictionsShowModelHorizonExplanationEvidence`, browser | Pass |
| Null risk never drawn as zero; measured zero kept | `TestDevicePredictionsNeverDrawNullRiskAsZero`, browser | Pass |
| Stale and expired predictions; stale latest never shows current risk | `TestDevicePredictionsMarkStaleAndExpiredWithoutCurrentRisk`, browser | Pass |
| Denied/broken evidence, outage, unknown device, bad cursor fail closed | `TestDevicePredictionsFailClosed`, browser (502/503/404) | Pass |
| No assessment, not configured, query validation, login-return allowlist | `TestDevicePredictionsWithoutAssessmentOrConfiguration`, `...QueryValidationAndPaging` | Pass |
| 320px layout | browser | Pass |

## Not tested

The browser suite uses a synthetic reader, not PostgreSQL; the controller adapter maps `ErrPredictionEvidenceBroken` to the denied state without a database test. No real model risk is shown because none passes its gates.
