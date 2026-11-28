# Off-chain signed audit evidence validation, AUD01 #119

Adds `audit_evidence` (migration 014), `StoreAuditEvidence`, `AuditEvidenceMetadata`, `AuditEvidenceContent` and the routes in the [contract](../../packages/contracts/audit-evidence-v1.md).

| Case | Check | Result |
| --- | --- | --- |
| Telemetry, prediction and diagnostic evidence stored with owner, size, digest, retention and actor | `TestAuditEvidenceStoresExactSignedBytesWithScopeLimitsAndRetention` (PostgreSQL) | Pass |
| Served bytes are the original signed objects: the device key verifies the stored envelope and diagnostic result | same | Pass |
| Bytes identical after a controller restart; `Repr-Digest` matches | same | Pass |
| Wrong device scope, unknown evidence, unknown parameter: explicit codes, no bytes or owner in the body | same | Pass |
| Oversized write refused with nothing stored | same | Pass |
| Unknown or foreign source, assessment without a payload, ID or source reused differently, bad retention or kind refused with nothing stored | same | Pass |
| Viewer and anonymous cannot store or read bytes; viewer reads metadata only | same | Pass |
| Database refuses UPDATE, DELETE and a digest that does not match the content | same | Pass |
| Bytes changed at rest are refused (500, `evidence_unavailable`) | same | Pass |
| Bytes refused after retention, metadata kept (410) | same | Pass |

## Not tested

The corruption case removes the database guards in an isolated test database to simulate damage below the controller. Retention enforcement and tombstones are #132; access policy across jobs, reports and artifacts is #55; manifests are #45. Real endpoint telemetry carries no SMART counters, so predictions stored here are unknown assessments unless a model is active.
