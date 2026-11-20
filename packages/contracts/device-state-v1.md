# Device state v1

Read-only view of enrolled devices and their latest durable signed sample.
Go types: `packages/contracts/device_state_v1.go`. There is no JSON schema yet;
the Go types are the source of truth.

- `DeviceStateV1` holds deployment, device, signing key ID, enrollment time,
  `revoked_at` (null unless revoked) and `last_sequence`, the committed replay
  mark.
- `latest` is the sample stored at `last_sequence`: sequence, payload `source`
  (`fixture` or `endpoint`), `collected_at`, controller `received_at`, the
  signed request SHA-256, the telemetry v2 metrics with explicit units and
  nullable values, and `sensors`.
- `latest` is `null` when the device has not sent a sample, or when the body
  for its newest sequence is no longer retained. `last_sequence` is unaffected.
- `sensors` lists all seven metrics in a fixed order. `available` has a value.
  `missing` is reported null with a `missing_reason`. `not_reported` was absent
  from the sample. Absence never means a zero reading.
- `DeviceStatePageV1` is a keyset page ordered by `device_id` with `next_after`
  (null on the last page). Page size is 1 to 100; default 50.

Enrollment and sample data come from signed envelopes. The device
signature, not this view, vouches for them; the view is not a health verdict.
