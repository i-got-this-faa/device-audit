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

## Verification, AUD03 #120

`GET /console/api/audit-manifests/{id}/verification` (administrator, no query)
recomputes a verification and returns `AuditManifestVerificationV1`
(`device-audit.audit-manifest-verification.v1`). It writes nothing, caches
nothing and reads no stored result: it loads the raw manifest and evidence rows
and recomputes `packages/audit.VerifyManifest`.

1. The manifest signature under the controller audit key, then its commitment
   from the manifest bytes against the stored commitment, then manifest expiry.
   A failure here is the overall `evidence_status` and no reference is examined
   (`invalid_signature`, `digest_mismatch`, `evidence_expired`), as in CT09.
2. For each reference: whether the record exists, whether its retention ended,
   whether its stored schema is the one named, whether its SHA-256 and size are
   the signed ones, whether the bytes parse as that schema, whether the recorded
   model and methodology still match, and whether the device signature verifies
   under the key enrolled for it. Diagnostic results are also correlated with the
   controller-signed assignment they answer.

| Reference `status` | Meaning |
| --- | --- |
| `verified` | Digest, size, schema, bound versions and any device signature check out |
| `edited` | The stored bytes differ from the signed digest or size |
| `missing` | No evidence record exists for the reference |
| `expired` | Retention ended; the bytes are not examined |
| `wrong_version` | The record is of another schema, model or methodology than was signed |
| `invalid_signature` | The device signature does not verify under its enrolled key |
| `unknown_signer` | No enrolled key has the signing key ID |
| `malformed` | The bytes match their digest but are not a valid record of the schema, or not bound to their assignment |

The overall `evidence_status` takes `evidence_expired`, then `evidence_missing`,
then `digest_mismatch` (edited, wrong version, malformed), then
`invalid_signature` (invalid signature, unknown signer), else `verified`.

`scope` is always `integrity_only` and `endpoint_truthfulness` is always
`not_established`. A valid signature shows that an enrolled device key signed
those bytes. It says nothing about whether the endpoint measured, probed or
reported truthfully, and prediction records are controller-made and carry no
device signature, so only their digest and shape are checked. `anchor_state` is
always `unverified`: no chain state is consulted.

A tombstone (an evidence record deleted but remembered) belongs to #132; until
it exists, only an ended retention (`expired`) and an absent record (`missing`)
can be reported, and tombstoned evidence will need its own reference status.
