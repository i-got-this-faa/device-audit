# Forecast provenance validation, FED13 #118

Adds `DeviceForecastV1` / `ForecastSourceV1` ([contract](../../packages/contracts/forecast-provenance-v1.md)), `PostgresRepository.DeviceForecast`, `ForecastSourceForModel` and `ForecastSourceForRound`, and the viewer routes `GET /console/api/devices/{id}/forecast` and `GET /console/api/models/{version}/forecast-source`. No migration: provenance is read from existing append-only tables.

| Case | Check | Result |
| --- | --- | --- |
| Forecast tied to promoted model, feature version, evaluation digest, observation window, evidence sample and originating round | `TestForecastSourceRefusesFailedRoundsRejectedAndUnevaluatedCandidates`, `TestDeviceForecastFreshnessAndModelEligibility` (PostgreSQL) | Pass |
| Failed round (`round_failed`), open round, unknown round | same | Pass |
| Rejected candidate, failing evaluation, evaluated but not promoted | same | Pass |
| Unevaluated aggregate stays unavailable, including after restart and with an approval inserted around the DB gate | same | Pass |
| Expired prediction, superseded model, unknown health, no prediction return no forecasts | `TestDeviceForecastFreshnessAndModelEligibility` | Pass |
| Route auth, deployment scope, unknown device | same | Pass |

## Not tested

The model route is covered through the repository, not over HTTP. Real telemetry v2 carries no SMART counters, so real deployments report `insufficient_evidence` or `model_unavailable`; available forecasts were exercised with the SMART fixture reader. Forecast-driven triggering of diagnostics is #70.
