# Inventory metadata API, API03 #97

Configure the database, OIDC authentication, deployment ID and TLS as described
in [the enrollment guide](../../infra/enrollment/README.md). The controller then
registers these session-protected routes. It does not import fixture/candidate
devices into the trusted inventory.

- `PUT /console/api/devices/{id}/inventory` appends a complete
  [inventory update v1](../../packages/contracts/inventory-v1.md) for an enrolled,
  non-revoked device. Administrator scope, authentication within five minutes,
  exact configured Origin and `X-CSRF-Token` are required. The body device ID
  must match the path. Send `Content-Type: application/json`; the body is bounded
  to 64 KiB. Query parameters, ambiguous JSON and caller-supplied actor fields
  are rejected.
- `GET /console/api/devices/{id}/inventory` reads the latest record. Optional
  `?revision=N` reads an exact positive revision. Viewer or administrator scope
  is required. Other, repeated, malformed or out-of-range parameters fail with
  400. An unknown device or missing revision returns 404 with no metadata.

Successful writes return 201 with server-controlled enrollment/actor provenance.
Start with `expected_revision: 0`, then use the last observed revision. A stale
revision returns 409; reload before updating. A revoked device returns 409.
Invalid updates return 400. Store and commit failures return 503 without
database diagnostics or a success record. An uncertain commit can be reconciled
by reading the latest or expected historical revision and comparing its full
contents. Do not interpret a conflict as proof that your update committed.

The repository serializes writers on the enrolled-device row. It checks the
current revision, verifies the device is not revoked and appends the complete
snapshot in one synchronous-commit transaction. Earlier revisions remain
queryable when components or memberships change or become unknown. Device
signing keys, mesh bindings and telemetry sequence marks are unchanged.
PostgreSQL stores times to microsecond precision; stored observation and record
times are truncated to that precision. Observation time cannot exceed the
receiver clock, checked after lock acquisition. Source and component IDs are
operator assertions; no model, cohort or identity is inferred from a missing ID.

These are off-chain metadata records, not signed observations, a tamper-resistant
audit log, a network access policy or an asset integration. A privileged database
operator can modify them. Membership supports the existing one-group/one-segment
shape. Historical cohort analytics, hierarchy queries, fleet listing, retention,
external observation verification and backup recovery remain later work.

Run `TEST_DATABASE_URL=... make database-check` for real PostgreSQL coverage.
Inventory tests verify immutable application history, unknown/missing/revoked
devices, exact source/enrollment/actor provenance, clearing to unknown metadata,
reopening connections, independent concurrent writers, deferred commit failure,
storage outages, denied updates and protected queries. Shared fixture review and
a reviewed merge remain release gates.

## Device list and latest state, API01 #28

`GET /console/api/devices` and `GET /console/api/devices/{id}` return enrolled
devices with their latest durable sample (see
[device state v1](../../packages/contracts/device-state-v1.md)). Viewer or
administrator scope is required.

- `deployment_id` is required and must equal the controller's configured
  deployment. A different value returns 403; a missing one returns 400.
- The list takes `limit` (1 to 100, canonical decimal, default 50) and `after`
  (the previous page's `next_after`). A larger limit, a repeated or unknown
  parameter, or a malformed cursor returns 400; the page is never silently
  clamped.
- An unknown device returns 404. Store failures return 503 without diagnostics.
- The latest sample is joined at the device's committed `last_sequence`, so the
  list and detail agree and survive controller restarts. Revoked devices stay
  listed with `revoked_at`.

The list does not include inventory metadata revisions; read them with the
inventory route. Fixture/candidate devices from `/v1/devices` are never listed.

The console's `/console/devices` pages (WEB02 #30) read the same repository
methods and add observed-time freshness; see the
[console guide](../../apps/web-console/README.md#enrolled-devices-and-freshness).
This JSON API is unchanged and does not classify freshness.


## Telemetry and evidence history, API02 #98

`GET /console/api/devices/{id}/history` pages through a device's persisted samples
(see [telemetry history v1](../../packages/contracts/telemetry-history-v1.md)).
Viewer or administrator scope is required, and `deployment_id` follows the same
rules as the device list. `from` and `to` are required and the window is capped at
31 days; `limit` is capped at 100 and an excess is rejected, so one request cannot
read an unbounded range. Ordering is `(collected_at, sequence)` with a keyset
cursor, so equal timestamps are stable. Reads come from `device_evidence`, so a
controller restart changes nothing. Revoked devices stay readable; an unknown
device returns 404. Not covered: retention, aggregation, filtering by source or
metric, and export.
