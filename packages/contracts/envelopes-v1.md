# Provisional enrollment, evidence and acknowledgement v1, #75

This specifies contracts, not controller enrollment or ingestion behavior. The
hosting/tenancy plan in `docs/decisions.md`, #73, selects one organization per
deployment provisionally. `deployment_id` is an opaque operator-provisioned
deployment identifier. A request cannot select its authorization boundary.
Consumers must compare it with their configured deployment. SRC05 #72 records the supplied PDF reconciliation. That source mapping
establishes neither implementation nor patent coverage; no production key storage
is claimed.

## Signature and canonical bytes

Use pure Ed25519 from Go's `crypto/ed25519`, compatible with
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html), through
[`ed25519.Sign` and `ed25519.Verify`](https://pkg.go.dev/crypto/ed25519).
Do not use Ed25519ph, Ed25519ctx, or sign a prehash. Public keys are 32 bytes;
signatures are 64 bytes, both encoded as lowercase hex. A signing key ID is
`ed25519:` followed by lowercase hex SHA-256 of the raw public key. Check both
the fingerprint and the signature. Enrollment proves possession only; it needs
separate bootstrap authorization. Evidence uses the enrolled, non-revoked device
public key, never a key supplied by the evidence sender. Acknowledgements use a
separately pinned controller signing key. A key ID is a lookup hint, not trust.

These algorithm, fingerprint, framing and bounds choices are provisional for
interoperability. RFC 8032 supports the algorithm, not a patent requirement,
hardware keystore choice, organizational approval, or deployment threat model.
Changes require new contract versions. No dependency or custom crypto is needed.

Canonical signing bytes are the ASCII bytes `device-audit/signature/v1` followed
by one zero byte, then the fields below in order. Encode **each** field as a
four-byte unsigned big-endian byte length followed by its UTF-8 bytes. Integers
are unsigned base-10 ASCII without leading zeroes, including `0`. Null is the
empty string, which is disjoint from the allowed non-null field values. There
are no field names, separators, BOM, trailing bytes, or signature field. All
text fields in this version are ASCII. JSON property order, whitespace and JSON
escape spelling have no effect after strict decoding. Unknown/missing/null
required fields, case aliases, duplicate keys at any nesting level, and trailing
JSON are errors. The Go decoder and Python reader enforce this independently
of JSON Schema, which cannot detect duplicate object keys.

- Enrollment: `schema_version`, `deployment_id`, `device_id`, `signing_key_id`,
  `sequence`, `issued_at`, `expires_at`, `public_key`, `challenge_id`.
- Evidence: `schema_version`, `deployment_id`, `device_id`, `signing_key_id`,
  `sequence`, `issued_at`, `expires_at`, `payload_schema_version`, `payload_sha256`.
- Acknowledgement: `schema_version`, `deployment_id`, `device_id`,
  `controller_key_id`, `request_schema_version`, `request_key_id`,
  `request_sequence`, `request_sha256`, `received_at`, `status`,
  `rejection_reason`, `last_sequence`.

Evidence signs the SHA-256 of the exact decoded `payload_base64` bytes. Use
canonical padded RFC 4648 standard base64 without whitespace; decoded bytes
must be nonempty UTF-8 JSON of at most 262144 bytes. Do not parse/re-marshal
before hashing. This avoids claiming a cross-language canonical JSON or float
encoding. Different serialized payloads have different commitments. Initially
only `device-audit.telemetry.v2` is allowed; validate that payload, including
nullable metrics, explicit units and ordered log windows, and require its
`device_id` to match the envelope. The digest must match even before signature
verification; hashing alone supplies no authentication. Signed timestamps refer
to submission, not telemetry collection, so offline data retains `collected_at`.

For acknowledgement correlation, `request_sha256` is lowercase hex SHA-256 of
the request's canonical signing bytes concatenated with its raw 64-byte
signature. This is an off-chain request fingerprint, not the demo's v1 digest
or a chain commitment. Verify acknowledgement signature, pinned controller key,
deployment, device and **all** request correlation fields before using it.
`SigningBytes()` checks the signed fields, allowing unsigned construction and
rejection correlation even when the enrollment key fingerprint or evidence body
fails semantic validation. Senders must validate the completed envelope before
transmission. `VerifySignature()` requires full semantic validation as well.

## Enrollment and identities

`device-audit.enrollment.v1` carries a device's proposed signing public key,
fingerprint, sequence 1 and an opaque `challenge_id`. A future controller issues
a challenge only following valid, unexpired operator bootstrap authorization
over HTTPS for its configured deployment. Its durable challenge record must
bind the deployment, proposed device ID and signing key ID, expiry and bootstrap
authorization. Generate challenges with at least 256 random bits, expire them
within ten minutes, and consume them once atomically with enrollment. A device
signs the envelope to prove possession. Challenge/credential issuance and routes
are intentionally outside this contract. Bootstrap secrets never enter signed
envelopes, telemetry, acknowledgements or fixtures.

The controller assigns or authorizes the opaque device ID. The sender cannot
claim another device by changing it. Provisionally classify an attempt to replace
an existing enrollment binding as `enrollment_conflict`; this version has no key
rotation/re-enrollment operation. Reserve an explicit, authorized future contract
for recovery/rotation that preserves sequence state.
The same public key must not be registered for multiple device identities in a
deployment. Network admission remains a separate authorized binding.

WireGuard/Tailcat keys, PSKs, mesh peer identities, TLS keys and bootstrap
credentials are neither signing keys nor replacements for signature checks.
Do not derive one from another or reuse them for controller acknowledgements or
chain signing. No mesh credential is present in these schemas. A future mesh
adapter must independently bind the authenticated peer to the enrolled device.
No raw logs or device identifiers belong on-chain. Signatures establish integrity
and key possession, not the truth of sensor readings or endpoint honesty.

## Sequence, clock and restart policy

Sequence numbers are JSON integers from 1 through 9007199254740991, exactly
representable by common JSON readers and PostgreSQL bigint. Enrollment uses 1;
evidence starts at 2. The durable high-water mark is scoped to
`(deployment_id, device_id)` across signing keys, schema versions, reconnects
and restarts. Gaps are allowed: accept only a sequence strictly greater than
the stored mark. Requests reaching the freshness check with a consumed sequence,
including reordered older messages and identical retries, are `replay`.
Rejected requests do not advance it. Do not wrap at exhaustion. New key IDs,
lost local state and controller restarts must never silently reset it.

Admission remains outside these validators. `enrollment_conflict` describes a
proposed binding conflict; `replay` describes a consumed sequence at the freshness
stage. A consumed challenge can instead yield `challenge_reused` at authorization.
The pure Go/Python freshness checks cannot determine binding conflicts or
challenge state. The acknowledgement enum carries these provisional outcomes;
it does not infer them. Precedence among authorization failures and transport
status mappings remains for consumer review. The time/sequence precedence below
is fixed. No controller admission or durable state is implemented here.

Endpoints durably reserve a sequence and immutable signed request before first
send; restart resumes the same pending request or reserves a higher sequence.
Spool/retry/recovery implementation is deferred. A controller must atomically
commit enrollment/challenge consumption or evidence together with the high-water
mark before returning `accepted`. Parallel requests use that same atomic
comparison, not a read/check/write race. A lost accepted response can yield a
signed replay rejection on retry. Replay alone does not prove the pending
payload was stored; retain it for reconciliation through a future authenticated
receipt lookup. No idempotent success or lookup endpoint is invented here.
Missing/unavailable durable state must fail closed with `storage_unavailable`.
Restore must preserve or reconcile high-water marks and revocations before
ingestion resumes. Backup rollback must not reopen old sequence numbers.

Timestamps are exactly `YYYY-MM-DDTHH:MM:SSZ`, UTC whole seconds, years
0002 through 9999, with real calendar dates and no leap seconds or offsets.
`expires_at` must be after `issued_at`; maximum lifetime is 600 seconds for
enrollment and 86400 seconds for evidence. The receiver supplies its own trusted
clock. Reject at `now >= expires_at` as `expired` and when
`issued_at > now + 300 seconds` as `future_timestamp`; equality at that skew
boundary is allowed. Time never replaces the sequence check. Evaluate expiry,
then future skew, then replay after structural, payload, signature and
authorization checks. These bounded clock policies are provisional, not
measured release-machine drift or finalized collection cadence.

## Acknowledgements and explicit failures

`device-audit.acknowledgement.v1` is controller-signed, carries `received_at`
from the controller clock, echoes the request version, key ID and sequence,
and binds `request_sha256`. It has no independent acknowledgement sequence.
Correlation prevents a valid old acknowledgement from accepting another
request. Retention and authenticated receipt lookup remain open.

- `accepted`: `rejection_reason` is explicitly null and `last_sequence` equals
  `request_sequence`. This means durable commit, not buffering, queueing,
  prediction success, sensor truth, or chain finality.
- `rejected`: `rejection_reason` is a required enum and `last_sequence` is the
  current durable mark, or explicitly null when unknown/unavailable or unsafe
  to disclose. Zero means known never enrolled, not unknown. Replay requires a
  known mark at least as large as the request sequence. Rejecting never commits
  the request. A rejection may be schema-valid and cryptographically valid.

Reasons: `invalid_signature`, `key_mismatch`, `payload_digest_mismatch`,
`replay`, `expired`, `future_timestamp`, `unknown_device`, `revoked_key`,
`deployment_mismatch`, `bootstrap_invalid`, `challenge_expired`,
`challenge_reused`, `enrollment_conflict`, `unauthorized_peer`,
`storage_unavailable`, `invalid_payload`.
Do not echo secrets, raw logs or diagnostic exception text. Only emit a signed
acknowledgement when a structurally decodable request can be correlated; malformed
or unsupported envelopes require a future transport-level error contract.
Authentication/authorization failures must not disclose another device's mark.

## Evidence and outstanding dependencies

`fixtures/envelopes/v1-vectors.json` pins signing bytes, key IDs, signatures,
request fingerprints and contract/crypto/freshness outcomes. Go verifies real
Ed25519 signatures; Python's test reader uses the existing test-only schema
dependency plus stdlib parsing, hashing and framing to check wire/semantic
validity and canonical bytes, not signatures. It cannot authenticate ingestion.
Private fixture seeds are public RFC 8032 test seeds only, never production keys.
Vectors are contract tests, not server/restart/concurrency integration evidence.

Another owner must review sequence/restart, lost-acknowledgement and restore
semantics before consumer work. #17 controller/fake-server implementation and
#80's conformance harness are untouched. Durable transactions, challenge and
bootstrap issuance, peer authorization, revocation/recovery, controller trust
distribution, protected endpoint key storage, actual clock behavior, and
restart/restore integration remain unimplemented. #14 still bounds deployment choices; source reconciliation under #72 does not
establish implementation or patent coverage.
