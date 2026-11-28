# Off-chain audit evidence store v1, AUD01 #119

The controller keeps bounded, immutable snapshots of the signed records an
[audit manifest](audit-v1.md) references, so a manifest digest can be checked
against the exact stored bytes after a restart. Migration
[014](../../infra/database/migrations/014_audit_evidence.sql) adds the table.
The store does not build manifests (#45), verify them (#120), enforce retention
(#132) or anchor anything.

## What is stored

A store request names one durable record; the controller reads the bytes itself
and never accepts them from the caller.

| `kind` | Selector | Stored bytes | `evidence_schema_version` |
| --- | --- | --- | --- |
| `telemetry` | `sequence` | The device-signed evidence envelope, re-checked against its accepted request digest | `device-audit.evidence-envelope.v1` |
| `prediction` | `prediction_id` | The prediction v2 payload of a persisted assessment, after its evidence and model references are re-verified | `device-audit.prediction.v2` |
| `diagnostic` | `assignment_id` | The device-signed diagnostic result, re-checked against its accepted request digest | `device-audit.diagnostic-result.v1` |

`device_id` is the owner and must match the source. Each object is at most 2 MiB
(`AuditEvidenceMaxBytesV1`, below an audit manifest's 10 MiB reference limit).
`retention_expires_at` must be in the future and within 10 years (a provisional
sanity bound; the retention policy is #132's). A manifest reference's `sha256`
and `size_bytes` are the stored `sha256` and `size_bytes`. Diagnostic results are
not yet a supported manifest reference schema; #45 must extend that set.

## Routes

| Route | Role | Result |
| --- | --- | --- |
| `POST /console/api/audit-evidence` | fresh admin | `201` stored, `200` identical repeat |
| `GET /console/api/audit-evidence/{id}` | viewer | Metadata only, no bytes |
| `GET /console/api/audit-evidence/{id}/content[?device_id=…]` | admin | Exact stored bytes with `Repr-Digest`; `device_id` asserts the owner |

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `invalid_request` | Bad shape, unknown kind, retention not in range, unknown parameter |
| 403 | `evidence_wrong_scope` | The evidence belongs to another device than asserted |
| 404 | `evidence_not_found`, `evidence_source_not_found` | No such evidence, or no such source record for this device |
| 409 | `evidence_conflict` | The ID or the source is already stored differently |
| 410 | `evidence_expired` | Retention ended; metadata stays, bytes are no longer served |
| 413 | `evidence_too_large` | Over the limit; nothing is stored |
| 500 | `evidence_unavailable` | The source or the stored bytes failed their integrity check; they are not served |
| 503 | | Database unavailable or commit uncertain; repeat the request |

Error bodies carry only the code, never evidence bytes or the owning device.
