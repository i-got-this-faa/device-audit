# Prediction history v1

Read-only, bounded view of one enrolled device's durable prediction and health
assessments with model, feature, horizon, telemetry-evidence, and historical
fault-baseline provenance. Go types: `packages/contracts/prediction_history_v1.go`;
there is no JSON schema yet.

- History request: `GET /console/api/devices/{id}/predictions` with required
  `deployment_id`, `from` and `to` (RFC 3339). The window is
  `from <= as_of < to`, at most 31 days. Optional `limit` (1 to 100, default 50)
  and `after` (the previous `next_after`).
- Latest request: `GET /console/api/devices/{id}/predictions/latest` with
  required `deployment_id`. Returns `current_health` evaluated against the
  controller clock alongside the latest stored record. Once `expires_at` passes,
  `stale` is `true` and `current_health` fails closed to `unknown`
  (`stale_evidence`) with null probability and horizon.
- Records are ordered by `(as_of, id)` with microsecond precision.
- Unknown records preserve null `probability` and `horizon_hours` with an
  explicit `unknown_reason`. When no telemetry sample existed at or before
  `as_of`, `evidence`, `expires_at`, and `prediction` are `null`.
- Broken evidence or model references (missing or altered `device_evidence`
  payload, mismatched digests, or mismatched model approvals) fail closed with
  HTTP 500 rather than returning a risk value.
- Errors: 400 invalid or unknown parameter, oversized window or limit (never
  clamped); 401 no session; 403 another deployment; 404 unknown device (or no
  recorded prediction on `/latest`); 500 broken evidence or corrupt record;
  503 store failure.
