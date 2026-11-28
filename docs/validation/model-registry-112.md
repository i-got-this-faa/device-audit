# Model artifact registry, FED07 #112, 24 November 2026

Migration 007, the [registry contract](../../packages/contracts/model-registry-v1.md)
and the [console routes](../../internal/controller/model-registry.md) store
signed model artifacts with explicit `active` and `candidate` references.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Immutable digests, provenance and feature/runtime compatibility | The stored entry returns the signed manifest (feature version and order, runtime name and version, architecture, purposes, digest), the source reference, upload time and uploader subject. A trigger refuses `UPDATE` and `DELETE` on artifacts and approvals; the test tries both. |
| Authorized upload and download | No session is 401; a viewer and an admin authenticated an hour earlier are 403 for upload. Download needs an admin; a viewer is 403. The bytes come back exactly, with `Repr-Digest`. |
| Explicit active/candidate references | The empty registry has two null slots. Setting the candidate, approving and activating are separate fresh-admin requests; activation clears the candidate. |
| Tampered, conflicting-version and unauthorized artifacts are rejected | Changed bytes are `digest_mismatch`; a signed field changed after signing is `invalid_signature`; a manifest signed by another key is `key_mismatch`; an empty artifact is `invalid_request`; over 16 MiB is `artifact_too_large` (contract test). The same version with other bytes, or the same bytes as another version, is `version_conflict`. Refused uploads store nothing. Bytes changed at rest (trigger disabled in the test) are refused on download with 500. |
| Restart preserves references and never activates an unapproved candidate | Activation without approval is `not_approved` and leaves both slots unchanged. A direct SQL insert of an unapproved active row fails its foreign key. A training-only approved artifact is `purpose_unsupported`. After a new repository and server start over the same database, both slots are unchanged and the unapproved candidate is still refused. |

The tests are `TestModelRegistryRejectsUnauthorizedAndTamperedArtifacts`,
`TestModelRegistryNeverActivatesAnUnapprovedCandidate`,
`TestModelArtifactUploadVerify` and `TestModelRegistryRequestsRejectUnknownAndNullFields`.

## Fault checks

Each mutation was applied and reverted. The tests failed each time.

- The download served bytes that failed the digest check.
- Any upload to a stored version was treated as an identical repeat.

## Commands and results

Same run as [fault-history-106.md](fault-history-106.md): `make check` with
`TEST_DATABASE_URL` set, `CGO_ENABLED=0 make cross-build` and
`make contract-check` passed against PostgreSQL 17.11.

## Not tested

- The restart is a new repository and HTTP server over the same database in one
  process, not a killed controller process.
- No real model was uploaded. The artifacts are synthetic bytes, and the ML02
  baseline has no signed manifest; the publisher key has no issuer.
- The approval cited an evaluation digest that nothing checked. FED10 #115
  ([validation](model-promotion-115.md)) removed that approval route: a
  promotion now creates the approval from a stored passing evaluation.
- Endpoints cannot download the active model over the mesh yet, and #55 has
  not reviewed these routes in its access matrix.
- A 16 MiB upload against the 10 s server read timeout was not measured.
