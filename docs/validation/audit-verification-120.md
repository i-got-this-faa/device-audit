# Off-chain evidence verification, AUD03 #120

Issue `#120` verifies a stored manifest and its evidence independently and
reports edited, missing, expired and wrong-version evidence as distinct results.
Contract: [audit-manifests-v1](../../packages/contracts/audit-manifests-v1.md).

## Evidence

| Case | Evidence |
| --- | --- |
| Unit outcomes | `TestVerifyManifestReportsDistinctOutcomesAndIntegrityOnly` covers intact, edited, missing, not found, retention ended, wrong stored schema, wrong model version, malformed, another audit key, a wrong commitment, an expired and an absent manifest, a future manifest and a missing clock. Every result carries `integrity_only`, `not_established` and `unverified`. |
| Real records, nothing trusted | `TestAuditManifestVerificationRecomputesEverythingAndDistinguishesFailures` (PostgreSQL) verifies a real telemetry envelope, a promoted-model prediction and a forecast-launched device-signed diagnostic result: digests and both device signatures recomputed, the diagnostic result correlated with its signed assignment. |
| Stored flags are not trusted | A prediction row is rewritten together with its own `sha256` column, so the store serves it as intact. Verification still reports `edited` because it compares with the digest in the signed manifest. |
| Distinct failures | The same test reports `missing` (record renamed away), `expired` (retention ended, bytes not examined), `wrong_version` (stored schema changed, and the recorded model changed), a damaged commitment (`digest_mismatch`, no reference examined), and, for a manifest signed over records that were already damaged, `invalid_signature` and `unknown_signer`. Each damage is undone and the result returns to `verified`. |
| Authorization and side effects | The route is administrator-only (401, 403), refuses queries, returns 404 for an unknown manifest and writes no rows. |

## Limits

- A valid signature is integrity only. It never shows that an endpoint told the truth, and predictions carry no device signature.
- No tombstone store exists (#132). Tombstoned evidence cannot be reported separately yet; only `expired` and `missing` exist.
- Damage was simulated by disabling the table guards in an isolated test database, not by real disk faults or a restore.
- Device keys are looked up by signing key ID among enrollments, including revoked ones, and revocation time is not reported. The audit key is the controller's single configured key, with no rotation or registry.
- Model existence in the registry and forecast freshness are not re-checked; only the recorded model and methodology versions are compared.
- No chain state is consulted (`anchor_state` is always `unverified`).
