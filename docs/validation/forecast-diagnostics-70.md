# Forecast-driven local diagnostics, FED06 #70

Issue `#70` launches bounded local diagnostic jobs from evaluated, fresh forecast
data. Contract: [forecast-diagnostics-v1](../../packages/contracts/forecast-diagnostics-v1.md).

## Evidence

| Case | Evidence |
| --- | --- |
| Policy | `TestPlanForecastDiagnosticsMapsOnlyEvaluatedStorageRiskAndAllowlistedProbes` maps degraded and critical storage risk to the storage probe, ignores healthy, unknown, incomplete and non-drive models, keeps the strongest forecast per category and selects only allowlisted probes with valid arguments. |
| Fresh evaluated forecast to job to local insight on two endpoints | `TestForecastDrivenDiagnosticsAreEvaluatedFreshDeduplicatedAndTraceable` (PostgreSQL) promotes a model through its stored evaluation, records degraded assessments for two enrolled devices, launches a signed `storage_health.v1` assignment on each, polls and executes them with the workflow runner under each device key, accepts the signed results, and reads the trace: forecast time, evidence sequence, model and evaluation digests, assignment status, result state and the result's evidence reference. |
| Healthy and absent forecasts | The same test shows no assessment returns `unavailable/no_prediction` and a healthy assessment returns an available forecast with no decisions. No assignment or link row exists either way. |
| Repeated delivery | Three repeats, one after a repository restart, return `deduplicated` with the same job and leave one assignment and one link per device. |
| One unfinished job | A newer assessment while the job is unfinished returns `skipped/job_in_flight`; after the result is accepted the next fresh forecast launches a new job. |
| Stale or superseded forecasts | Activating another model gives `stale/model_superseded`. Advancing the clock past expiry, on a restarted repository, gives a stale forecast. Neither launches work. |
| Immutability | `UPDATE` and `DELETE` of `forecast_diagnostic_triggers` are refused. |
| Authorization and input | `TestForecastDiagnosticRoutesAuthorizeAndServeTheTrace` covers 401, 403 for a viewer, 400 for a query or non-empty body, 404 for an unknown device, deployment scope 400/403 and the served trace. A refused request queues nothing. |

## Limits

- Real telemetry v2 carries no SMART counters, so real deployments report
  `insufficient_evidence` or `model_unavailable` and launch nothing. The
  degraded forecast was produced with the SMART fixture reader used by the
  health tests, as in FED13.
- The result is a device-signed record posted through the controller store, as
  in DIA05. The endpoint agent over the mesh was not run for this issue, and
  its result was produced by the workflow runner with a stub probe, not
  Windows hardware. DIA06 evidence covers the endpoint path.
- The forecast does not name a disk, so storage probes `storage:disk-0` only.
- No scheduler calls the route; a caller posts. Two concurrent posts for
  different assessment times can each launch a job before either is linked.
- No remediation, shell, Jev, MDM or configuration management is added. The
  claim 1/8 workflow evidence here is the controller and runner path, not a
  production, patent or privacy claim.
