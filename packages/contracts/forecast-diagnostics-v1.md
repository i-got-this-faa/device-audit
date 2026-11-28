# Forecast-driven diagnostics v1

`ForecastDiagnosticsV1`, `ForecastDiagnosticTraceV1` and the policy in
`packages/workflows/forecast_policy.go` (`FED06 #70`) connect an evaluated, fresh
forecast to a bounded, read-only local diagnostic. Schema versions are
`device-audit.forecast-diagnostics.v1` and
`device-audit.forecast-diagnostic-trace.v1`; the policy is
`device-audit.forecast-diagnostic-policy.v1`.

## Routes

| Route | Role | Meaning |
| --- | --- | --- |
| `POST /console/api/devices/{id}/forecast-diagnostics` | fresh admin, CSRF | Evaluates the device's newest forecast now. Takes no query and an empty body or `{}`. |
| `GET /console/api/devices/{id}/forecast-diagnostics?deployment_id=…[&limit=1..100]` | viewer | Lists the jobs forecasts launched, newest forecast first. |

There is no background scheduler. A launch happens when an authorized caller
posts, so a timer or an unrelated job never starts diagnostics.

## What launches work

The controller reads the device forecast through `DeviceForecast` (FED13). Only
`status: available` can launch work: fresh, from a promoted and evaluated model
that is still active. `unavailable` and `stale` forecasts (`no_prediction`,
`model_unavailable`, `insufficient_evidence`, `stale_evidence`,
`prediction_expired`, `model_superseded`, `not_promoted`, and the other stable
reasons) return the reason and no decisions.

For an available forecast the policy plans at most one probe per category:

- A **degraded or critical** health assessment from a hard-drive SMART model
  (`hdd_smart_7d.v1` features) with a known probability and horizon calls for
  `storage_health.v1` on `storage:disk-0`. The forecast does not name a disk, so
  other disks are not probed. Healthy and unknown assessments launch nothing.
- A per-category fault forecast at or above `0.5` calls for `storage_health.v1`
  (storage) or `system_errors.v1` (cpu, gpu, memory, battery, thermal,
  network, lookback 3600 s, 64 entries). Current models emit none; the path
  exists so the data contract is honoured when they do.

Only the two allowlisted CT06 probes are ever selected. Each assignment is
controller-signed, targets one device, is bounded to 30 s and 64 KiB or 256 KiB
of output, and expires after 1 hour. No shell, remediation, package or
configuration action exists.

## Deduplication

- The job ID is derived from deployment, device, assessment time and category,
  so repeated delivery of one forecast names the same job. Outcome
  `deduplicated` returns it with its current status.
- A category whose probe still has an unfinished forecast-triggered job for the
  device is `skipped` with `job_in_flight`, even for a newer assessment.
- `forecast_diagnostic_triggers` is immutable and unique per
  (device, assessment time, category), so a repeat or restart never adds a job.
  A crash between queuing the job and linking it is repaired by the next call.

## Trace

Each link names the forecast (assessment time, category, probability, horizon,
evidence sequence), the evaluated model (version, artifact and evaluation
SHA-256), the policy, who triggered it, the assignment and its status. Once the
device-signed result is accepted, `result_state`, `result_reason` and the
result's evidence references (`reference_id`, `sha256`, `size_bytes`) are
included. Result bytes are not copied; they stay on the endpoint and in the
immutable result record.
