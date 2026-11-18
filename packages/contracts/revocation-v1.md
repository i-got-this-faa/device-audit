# Device revocation v1

SEC09 #90 adds a separately versioned administrator request that stops a
device from being admitted, and the durable record of that revocation. These
records do not delete evidence, rotate keys, update a relay admission file or
create an on-chain payload.

A request contains `schema_version: device-audit.device-revocation-request.v1`,
`device_id` and `reason_reference`. The reason is an opaque off-chain reference
to an incident or ticket. It uses the opaque ID grammar, so free text, raw logs
and hardware serial numbers cannot be stored through it. Revocation is
permanent for that enrollment. No reinstatement contract exists; a device that
must return needs a new enrollment.

A stored record uses `device-audit.device-revocation.v1` and adds
server-controlled `deployment_id`, `revoked_at`, `enrollment_sha256`,
`actor_issuer` and `actor_subject`. The digest references the device's original
signed enrollment request. The actor comes from the authenticated console
session, never from request fields. `revoked_at` is an RFC 3339 receiver time
read after the controller locked the device's admission row.

Requests require administrator authorization, authentication within five minutes
and CSRF/Origin checks. Storage must set the admission state and append this
record in one transaction under the same row lock that evidence ingestion uses.
Repeating a request for a revoked device returns the original record and does
not create a second one. An unavailable store fails closed. A lost commit
response is uncertain; repeat the request or read the device before assuming
either outcome.

Shared fixtures are registered in `conformance-v1.json`. JSON Schema checks
shape; Go additionally rejects a zero revocation time. Neither reader verifies
administrator authorization or that ingestion honours the revocation.
