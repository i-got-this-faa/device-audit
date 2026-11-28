# Audit manifest signing v1, AUD02 #45

The controller signs the [audit manifests](audit-v1.md) of CT09 over evidence it
already stores ([AUD01](audit-evidence-v1.md)). Migration
[016](../../infra/database/migrations/016_audit_manifests.sql) stores them.
Verification (#120), retention (#132), anchoring and reports are separate.

## Routes

`--audit-signing-key-file` (PKCS#8 PEM Ed25519) enables them and `/healthz`
reports `audit_manifests`. The key must differ from the diagnostic signing key.

| Route | Role | Result |
| --- | --- | --- |
| `POST /console/api/audit-manifests` | fresh admin | `201` created, `200` identical repeat |
| `GET /console/api/audit-manifests/{id}` | admin | The record, including the private blinding nonce |
| `GET /console/api/audit-manifests/{id}/commitment` | viewer | Only `schema_version`, `commitment_id`, `commitment_sha256` |

The request (`device-audit.audit-manifest-request.v1`) holds `manifest_id`,
`policy_version` (`device-audit.audit-manifest-policy.v1`), `expires_at` (whole
second, future, within 365 days) and 1 to 64 `evidence_ids`. It cannot carry a
digest, size, nonce, creation time or evidence bytes.

## What is signed

For each evidence ID the controller reads the stored bytes, re-checks the
SHA-256 and size, refuses expired evidence and evidence of an unsupported schema,
and makes one reference: `reference_id` is the evidence ID, `schema_version`,
`sha256` and `size_bytes` are the stored record's, and `expires_at` is its
retention rounded down to the second. The manifest may not expire after any
reference. References are sorted by ID. `creation time`, the commitment ID and
the nonce are chosen by the controller (the last two are independent 256-bit
random values, once per manifest). The manifest is signed with CT09's signing
bytes, so the digest is reproducible from the stored manifest.

Each record also carries a `basis` entry per reference: owner device, kind and
the versions behind it, read from the stored bytes and durable source, not from
the request.

| Evidence | `model_version`, `model_sha256` | `methodology_version` |
| --- | --- | --- |
| Telemetry envelope | null | the payload schema version |
| Prediction v2 | the model reference in the payload | the health rules version of the assessment |
| Diagnostic result | null | the probe ID of the assignment |

Those bytes are bound by the reference digest, so the basis cannot disagree with
what is signed.

## Identity and refusals

A manifest ID names one manifest. The request digest (policy, expiry and the
sorted evidence IDs) is stored, so the same request in any order is a repeat and
returns the stored manifest unchanged, even after its evidence expired. A
different reference, evidence set or expiry for that ID is `409
manifest_conflict` and nothing is changed. The same evidence under another ID
gets another nonce and an unrelated commitment.

| Status | Code | Meaning |
| --- | --- | --- |
| 400 | `manifest_invalid_request` | Bad shape, other policy, no or duplicate evidence, bad expiry, unknown field |
| 400 | `manifest_outlives_evidence` | The expiry is after some evidence's retention |
| 404 | `evidence_not_found`, `manifest_not_found` | No such evidence or manifest |
| 409 | `manifest_conflict`, `manifest_incompatible_evidence` | The ID names another manifest, or an evidence schema is not supported |
| 410 | `evidence_expired` | An evidence record's retention ended |
| 500 | `evidence_unavailable`, `manifest_unavailable` | Stored bytes or a stored manifest failed their integrity check; nothing is served |

Diagnostic result v1 (`device-audit.diagnostic-result.v1`) is a supported
reference schema, in the Go validator and the JSON schema.
