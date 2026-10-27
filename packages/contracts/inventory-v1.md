# Inventory revisions v1

API03 #97 adds separately versioned administrator inventory assertions. The
update and record schemas reuse the unchanged telemetry v2 inventory shape.
These records do not establish endpoint truth or grant networking admission.

An update contains `schema_version: device-audit.inventory-update.v1`,
`device_id`, `expected_revision`, `observed_at`, `source_reference` and
`inventory`. The complete snapshot replaces previous membership. Revision zero
means no prior record; each accepted update increments the revision. Revisions
are integers bounded by 9007199254740991. A stale expected revision conflicts
rather than overwriting another administrator's work.

`inventory.components` is required, with at most 64 entries. Each identified
component has an opaque `id`, `type` and optional `model`. Component IDs must
be distinct within a snapshot. Preserve an actual source identity across
observations; do not derive one from a list position, device ID or model label.
If no component identity is known, use an empty list. This means no identified
components were recorded, not that the device has no hardware. Missing group or
network-segment IDs remain omitted and unknown. A snapshot supports one group
and one segment, as in telemetry v2. It defines no hierarchy, cohort, network
authorization or external asset-system adapter.

A stored record uses `device-audit.inventory-record.v1`, replacing
`expected_revision` with `revision` and adding server-controlled `deployment_id`,
`recorded_at`, `enrollment_sha256`, `actor_issuer` and `actor_subject`. The digest
references the device's original signed enrollment request. The actor comes from
the authenticated console session, never from request fields. `source_reference`
is an opaque off-chain observation reference, not a credential or raw log.
Observation time must not be in the future relative to record time; older
observations may be explicitly recorded and remain distinguishable from order
of recording. Timestamps use RFC 3339. No on-chain payload is created.

Updates require administrator authorization, authentication within five minutes
and CSRF/Origin checks; reads require viewer authorization. Unknown or revoked devices cannot receive metadata.
Storage must retain prior revisions and atomically check the expected revision
before appending. An unavailable store must fail closed. A lost commit response
is uncertain; query before retrying, never infer acceptance.

Shared fixtures are registered in `conformance-v1.json`. JSON Schema checks
shape; Go additionally checks duplicate identities and time ordering. Neither
reader verifies administrator authorization or durable storage.
