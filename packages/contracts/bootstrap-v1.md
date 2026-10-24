# Bootstrap admission v1, SEC01 #18

This contract adds authorized bootstrap admission without changing signed
enrollment v1. One configured deployment owns the authorization boundary.
All requests and responses below require TLS, including behind a proxy. Never
trust forwarded scheme or identity headers. Bootstrap credentials are bearer
secrets delivered separately by an authorized operator.

1. `POST /admin/bootstrap-tokens` takes `bootstrap-token-request.v1` with an
   operator-authorized opaque `device_id`. A current admin session, CSRF/Origin
   validation and authentication within five minutes are required. The
   `bootstrap-token.v1` response returns a 256-bit random lowercase-hex `token`
   exactly once, deployment/device scope and whole-second `expires_at`. Lifetime
   is ten minutes. Store only SHA-256 of the token, issuer/subject provenance,
   creation/expiry and consumption state. Responses use `Cache-Control: no-store`.
2. `POST /v1/enrollment/challenges` requires `Authorization: Bearer <token>` and
   `enrollment-start.v1` with deployment/device scope, Ed25519 `public_key` and
   separate X25519 `network_public_key`, both 32-byte lowercase hex. Network keys
   must be canonical field elements below 2^255-19 with no high-bit aliases or
   low-order points. Equal signing/network public bytes are rejected. The
   controller binds one challenge to this token and these keys. A repeated start
   for the same tuple returns that challenge; another tuple is denied. Starting
   does not consume the token or create an admitted identity.
3. `enrollment-challenge.v1` returns the configured deployment/device, signing
   key fingerprint, network public key, random `challenge_id`, `expires_at` and
   `network_challenge`. Expiry cannot exceed the token's expiry or ten minutes.
   The latter is canonical standard padded base64 of an 80-byte NaCl anonymous
   sealed box containing a fresh random 32-byte proof. Use
   `golang.org/x/crypto/nacl/box.SealAnonymous` and `OpenAnonymous`, compatible
   with libsodium sealed boxes. The endpoint decrypts with its X25519 network
   private key. The controller stores only SHA-256 of the plaintext proof.
4. `POST /v1/enrollment` requires the same bearer token and
   `enrollment-admission.v1`. Its `enrollment` is the unchanged signed
   enrollment v1 with sequence 1, authorized scope, signing key and challenge.
   `network_public_key` must match the challenge; `network_proof` is the decrypted
   32-byte proof as lowercase hex. The outer Ed25519 `signature` uses the same
   signing key as the inner enrollment and binds all network-proof fields.

Outer signing bytes use the existing `device-audit/signature/v1` zero-terminated
domain and four-byte big-endian length-prefixed ASCII fields, in order:
`schema_version`, inner enrollment request SHA-256 fingerprint as defined in
envelopes-v1.md, `network_public_key`, `network_proof`. The version separates
this signature from every existing request. Returning an arbitrary network
public key with a valid Ed25519 signature alone cannot prove network possession.
TLS authenticates the challenge issuer; anonymous boxes do not authenticate it.
An endpoint must never decrypt challenges from an untrusted TLS origin.

Admission verifies both signatures, deployment/device/key/challenge binding,
network proof, receiver-clock expiry and one-use state. One PostgreSQL
transaction consumes the token and challenge and inserts the signing identity,
initial sequence and unique network binding. Any failure rolls back all of them.
Token rows are locked before challenge/device rows. A token or either key cannot
admit multiple devices. Existing signed-only repository rows are never silently
promoted to network admission. No external mesh operation occurs in this transaction.

Only after commit, HTTP 201 returns `enrollment-accepted.v1` with deployment,
device, signing key ID, network public key and `last_sequence: 1`. This TLS
response is not an acknowledgement-v1 signed receipt. A lost commit response is
uncertain; a retry must not fabricate success. Receipt reconciliation remains
separate work.

Errors use `enrollment-error.v1` with `reason`. Malformed requests are 400,
authorization/proof/expiry failures 403, consumed challenges or conflicting
bindings 409, and unavailable/uncertain storage 503. Plaintext requests return
403 `tls_required` before reading credentials. The configured TLS listener does
not parse plaintext HTTP requests. TLS rejection does not revoke a token already
disclosed by a client. Do not use such a token; wait for its expiry before
issuing a replacement. Early token revocation is separate work.
Invalid, unknown, expired or
consumed bootstrap tokens share `bootstrap_invalid`. Rejections disclose no
device sequence, database error, token or proof. Body size is bounded to 16 KiB;
queries are forbidden. Strict readers reject missing/null/unknown/duplicate
fields, case aliases and trailing JSON.

Contracts and synthetic fixtures do not qualify a deployed IdP, TLS proxy,
endpoint keystore, production mesh, device sensor truth or patent coverage.
Production transport (#25), evidence authorization (#24), signed evidence
acknowledgements (#89), device revocation (#90) and rotation/recovery remain
separate. All records remain off-chain.
