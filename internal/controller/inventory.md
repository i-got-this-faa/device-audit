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
