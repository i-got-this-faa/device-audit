# Audit manifests, commitments and receipts v1, CT09 #79

`audit_v1.go` and `audit-v1.schema.json` define four separate namespaces. The
manifest, receipt, verification result and evidence stay off-chain. Only the
public commitment's opaque fields are eligible for a future chain adapter.
No chain, account, contract deployment, finality threshold, resolver or retention
service is selected or implemented. `packages/audit.Anchorer` is unchanged.

## Signed off-chain manifest

`device-audit.audit-manifest.v1` binds deployment/manifest/commitment IDs, a private
blinding nonce, policy version, controller audit-key fingerprint, creation/expiry
and 1..64 evidence references. Manifest lifetime is positive and at most 365 days.
Every reference has an opaque local reference ID, exact schema version, SHA-256,
positive size up to 10 MiB in explicit bytes, and expiry after manifest creation.
References must be strictly sorted by ASCII reference ID, without duplicates.
Supported references are signed evidence v1, prediction v2 and lifecycle v2.
The reference digest covers exact stored bytes; JSON reserialization changes it.
The existing envelope and lifecycle fixtures provide the synthetic example bytes.

Use #75's Ed25519, lowercase fingerprints, whole-second UTC timestamps and
`device-audit/signature/v1` plus NUL. Each signing field is a big-endian uint32
byte length followed by its UTF-8 value. Ordered fields are `schema_version`,
`deployment_id`, `manifest_id`, `commitment_id`, `blinding_nonce`, `policy_version`,
`controller_key_id`, `created_at`, `expires_at`, decimal evidence count, then
each reference's `reference_id`, `schema_version`, `sha256`, decimal `size_bytes`,
`expires_at`. The schema version supplies signature namespace separation.
`SigningBytes` permits an absent signature for construction. `Validate` checks a
completed signature's shape; `VerifySignature(trustedAuditKey)` authenticates it.
A key fingerprint supplied in a manifest grants no trust or deployment access.

The operator must bind an authorized, non-revoked controller audit application
key to the deployment. Device signing keys, mesh credentials, administrator
sessions and chain signers cannot substitute for that authority. Verify nested
evidence signatures, device enrollment, payload schemas, forecast freshness,
lifecycle methodology and provenance separately. Manifest verification checks
byte integrity and signer possession, not measurement truth or report quality.

## Blinded public commitment

`device-audit.audit-commitment.v1` has exactly `schema_version`, `commitment_id`
and `commitment_sha256`. The latter two are lowercase hex of 32 bytes each.
Generate commitment ID and private nonce independently with a cryptographic
random generator, at least 256 random bits each, per manifest. Never derive the
ID from a hostname, serial, device/deployment ID, evidence ID or report contents.
The manifest stores both values under normal evidence access control. Do not
publish its nonce, IDs, references, policy version, signing key, report or logs.

Let `M = SHA256(manifest signing bytes || raw 64-byte signature)`, using #75's
`EnvelopeRequestSHA256V1`. The public digest is:

```text
SHA256(ASCII("device-audit/audit-commitment/v1") || 0x00
       || raw 32-byte commitment ID || raw 32-byte nonce || raw 32-byte M)
```

Fixed-width decoded bytes have no ambiguity or JSON number dependencies.
`AuditManifestV1.Commitment()` constructs this value after structural validation;
it does not authenticate the manifest or authorize publication. The signed
manifest already binds the nonce, deployment and policy. Different nonce/ID
values produce independent commitments to otherwise matching evidence. Keep the
nonce private; deterministic hashes alone can expose correlations and permit
guessing low-entropy reports. This is an integrity format, not a formal privacy
or anonymity guarantee. Anyone given the manifest can link its commitment.

The strict public type/schema reject extra device IDs, hostnames, serials,
raw logs and private manifest fields. Non-hex raw identifiers/logs are also
rejected in ID/digest fields. Shape checks cannot prove random generation or
prevent a malicious producer encoding sensitive data as hex; the producer must
enforce this policy. The deterministic fixture ID/nonce are public test material.
A future chain adapter may encode the version and two opaque 32-byte fields,
never the manifest or its private metadata. Writer authorization, immutable
ID-to-digest binding, replay rejection and signer rotation still need chain tests.

## Receipt states and finality

`device-audit.audit-receipt.v1` is an off-chain observation bound to exact
commitment ID/digest, configured adapter ID and opaque local transaction/block
references. Those references resolve within an adapter's configured chain and
contract, not via caller-provided RPC URLs. They deliberately do not select a
chain-native hash encoding. `CheckCommitment` rejects another ID or digest.

- `pending` has null finality time/reason; a block reference may be known.
- `finalized` requires a block reference and finality time no later than the
  observation, with null reason.
- `reverted` has null current finality and a reason of `transaction_failed`,
  `reorganized` or `commitment_absent`; a prior block may remain as provenance.

`pending` may become `finalized` or `reverted`. A formerly finalized observation
may become `reverted` after a reorganization. Preserve receipt history, including
old finality; never retain the old finality timestamp as a current guarantee.
A resubmission has a new transaction reference and pending observation, with the
same immutable commitment binding. Duplicate ID with a different digest is a
conflict, never an overwrite. Monotonic observation handling and durable history
remain consumer work. Parsing a receipt cannot prove any chain fact. The future
adapter must verify writer/contract/network, inclusion and the selected finality
policy against authoritative chain state on every verification or refresh.

## Evidence verification and failure meanings

`device-audit.audit-verification.v1` keeps `evidence_status` independent from
`anchor_state`. Anchor state is `unverified`, `pending`, `finalized` or `reverted`.
Use `unverified` until a trusted adapter establishes the current state. It is
possible to have intact evidence with a reverted anchor, or a finalized anchor
whose off-chain evidence is missing. Neither is complete audit verification.
No combined success boolean hides these differences.

`CheckAuditEvidenceV1` accepts already fetched bytes, a nullable manifest, an
expected public commitment, an externally trusted audit key and explicit clock.
It returns one evidence status and never infers chain state:

1. Reject malformed input or a missing clock as an error. Missing manifest is
   `evidence_missing`.
2. Authenticate the structurally valid manifest. A wrong key or cryptographic
   signature failure is `invalid_signature`.
3. Recompute its commitment. An ID or digest difference is `digest_mismatch`.
   Reject a manifest created after the receiver clock as an error.
4. At or after manifest or any reference expiry, return `evidence_expired`.
5. If any referenced artifact is absent, return `evidence_missing`.
6. If any supplied artifact has a different byte length or SHA-256, return
   `digest_mismatch`. Otherwise return `verified`, meaning supplied-byte integrity.

This precedence is deliberate. Expired/unavailable bytes do not masquerade as
an integrity failure, and an invalid signature cannot become an expiry result.
The helper neither parses referenced JSON nor proves its schema, nested signatures
or real-world meaning. The consumer must verify the configured deployment before
using a manifest, enforce resolver authorization and size/depth limits, and store
the complete manifest/nonce/evidence for the required retention period. Backups,
expiry/deletion, durable receipt lookup and recovery remain implementation work.
Do not label expired or deleted evidence verified just because a chain hash exists.

## Shared test evidence

Go tests authenticate manifest signatures, compare exact referenced bytes,
correlate receipts and exercise missing, expired, altered and bad-signature
paths. Fixtures include rejected public data fields, noncanonical reference
order, duplicate references and false finality. Python independently reconstructs
canonical signing bytes, reference digests and blinded commitments, and checks
Draft 2020-12 shape/date-time expectations. Schema alone cannot check signatures,
digests, field correlation, sorted IDs, time ordering or actual chain state.

```sh
go run packages/contracts/fixtures/audit/generate.go
make check cross-build
```

Another owner's review of verification/finality semantics remains required before
consumers. No real chain, finality/reorganization test, durable resolver, retention
or key rotation is exercised here. Contracts and synthetic fixtures establish no
production anchoring, patent coverage or truth of endpoint measurements.
