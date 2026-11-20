# Telemetry history v1

Read-only, bounded view of one enrolled device's durable signed samples.
Go types: `packages/contracts/telemetry_history_v1.go`; there is no JSON schema yet.

- Request: `GET /console/api/devices/{id}/history` with required `deployment_id`,
  `from` and `to` (RFC 3339). The window is `from <= collected_at < to`, at most
  31 days. Optional `limit` (1 to 100, default 50) and `after` (the previous
  `next_after`).
- Samples are ordered by `(collected_at, sequence)`. Samples that share a
  timestamp are never skipped or repeated across pages. Times have microsecond precision.
- Each sample carries `sequence`, `source` (`fixture` or `endpoint`), `collected_at`,
  controller `received_at`, the signed request SHA-256, telemetry v2 `metrics`
  (explicit units, nullable values) and `log_references`: the digests, sizes and
  windows of error evidence. No log bodies are stored or returned.
- `next_after` is an opaque cursor, null on the last page. An empty window returns
  an empty `samples` array.
- Errors: 400 invalid or unknown parameter, oversized window or limit (never
  clamped); 401 no session; 403 another deployment; 404 unknown device; 503 store failure.
