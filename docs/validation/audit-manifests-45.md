# Canonical signed audit manifests, AUD02 #45

Issue `#45` signs canonical off-chain manifests over the evidence AUD01 stores.
Contract: [audit-manifests-v1](../../packages/contracts/audit-manifests-v1.md).

## Evidence

| Case | Evidence |
| --- | --- |
| Equivalent inputs, identical bytes | `TestBuildManifestIsCanonicalAndAnyChangeIsADifferentManifest` builds one spec with references in two orders and gets identical signing bytes, signature and commitment. `TestAuditManifestsAreCanonicalSignedAndBoundToStoredEvidence` (PostgreSQL) repeats the request in another order, on the same and a restarted repository, and gets the stored manifest byte for byte. |
| Altered references cannot reuse an identity | The unit test changes each signed field (deployment, ID, commitment ID, nonce, times, digest, size, reference ID, schema, reference expiry, reference count) and each gives a different commitment and a signature that does not verify the other manifest. The PostgreSQL test sends fewer references, another reference and a later expiry under the first manifest ID and receives `manifest_conflict`, and the stored manifest is unchanged. |
| Telemetry, prediction and diagnostic evidence with versions | The PostgreSQL test links a real signed telemetry envelope, a prediction from a promoted evaluated model and a device-signed diagnostic result a forecast launched (#70). The basis records the model version and artifact digest, the rules version and the probe ID. |
| Incompatible or unusable evidence | Unsupported schemas are refused by the builder (`unknown schema`), unknown evidence is `evidence_not_found`, retention that ends before the manifest is `manifest_outlives_evidence`, ended retention is `evidence_expired`, and another policy, no evidence, duplicates and past or sub-second expiry are `manifest_invalid_request`. None stores a manifest. |
| Reproducible verification | `contracts.CheckAuditEvidenceV1` returns `verified` for the retained bytes, `digest_mismatch` for one flipped byte and `invalid_signature` under another key. |
| Immutability and integrity | Updates and deletes of both tables are refused. A manifest whose stored digest was changed below the controller returns `manifest_unavailable` and is not served. |
| Routes | `TestAuditManifestRoutesAuthorizeAndKeepTheNonceOutOfThePublicCommitment` covers 401, viewer 403, unknown fields and queries 400, 404, 201 then 200, 409, the administrator-only manifest and a viewer commitment of exactly three fields without the nonce or device ID. |

## Limits

- Lifecycle v2 is a supported reference schema, but no store keeps lifecycle records yet, so the controller cannot make a lifecycle reference.
- The manifest verifies byte integrity and signer possession only. Nested signatures, enrollment, forecast freshness and lifecycle methodology are #120.
- The audit key is a file key. Rotation, an authorized-key registry and revocation of the audit key are not implemented. The key is checked only against the diagnostic key, not the acknowledgement or chain keys.
- Retention enforcement and tombstones are #132. No chain transaction or receipt is involved.
- The model and methodology are the versions the controller read when signing. They describe the evidence; they do not prove the measurements.
