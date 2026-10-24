# Enroll an endpoint

SEC01 [#18](https://github.com/i-got-this-faa/device-audit/issues/18) implements
controller bootstrap admission over TLS. One transaction binds an authorized
opaque device ID to separate Ed25519 signing and X25519 network public keys.
Endpoint key storage and an installed endpoint enrollment client remain #23.
The existing endpoint executable still sends fixture telemetry.

## Enable the controller routes

1. Configure PostgreSQL and the [administrator OIDC settings](../../apps/web-console/README.md#configure-authentication).
   Preprovision the first administrator subject. Register the exact HTTPS
   callback origin with the identity provider.
2. Provision a TLS certificate and private-key file readable by the controller.
   Set `DEVICE_AUDIT_TLS_CERT_FILE` and `DEVICE_AUDIT_TLS_KEY_FILE`, or use
   `--tls-cert-file` and `--tls-key-file`. The listener requires TLS 1.3.
3. Set `DEVICE_AUDIT_DEPLOYMENT_ID`, or `--deployment-id`, to the operator-owned
   opaque deployment ID. Set `DEVICE_AUDIT_PUBLIC_ORIGIN` to the HTTPS origin.
   A database already bound to another deployment cannot be reused.
4. Start the controller on its literal loopback listener. Missing database,
   administrator configuration, TLS files or HTTPS origin prevents enrollment
   startup. Omitting the deployment ID leaves enrollment routes absent.
5. Configure the public proxy to verify TLS on the upstream connection. Allow
   the authentication, console and intended administrator routes plus
   `POST /v1/enrollment/challenges` and `POST /v1/enrollment`. Keep the fixture
   telemetry and device routes private. Forwarded scheme or identity headers
   grant no authority and cannot enable enrollment over plaintext.

The proxy and real identity provider remain deployment qualification work.
The database, relay and bootstrap service have separate credentials. A network
binding does not start a mesh connection or grant a telemetry submission.

## Issue and redeem one credential

1. Sign in as an administrator. Obtain the CSRF value from `GET /auth/session`.
   Authentication must be no older than five minutes when issuing a token.
   Reauthenticate if the server rejects stale authentication.
2. Send `POST /admin/bootstrap-tokens` with the session cookie, exact configured
   `Origin`, `X-CSRF-Token` and JSON
   `{"schema_version":"device-audit.bootstrap-token-request.v1","device_id":"AUTHORIZED_OPAQUE_ID"}`.
   HTTP 201 returns the bootstrap token, deployment scope and ten-minute expiry.
   Deliver the token privately to its intended endpoint. Do not place it in
   URLs, logs, shell arguments or committed files. The server cannot retrieve it.
   If a token is disclosed, stop its use and wait for its expiry before issuing
   a replacement. TLS rejection does not invalidate a disclosed token.
3. Use an endpoint client that implements the [bootstrap contract](../../packages/contracts/bootstrap-v1.md).
   Send the bearer token only to the trusted HTTPS origin. Propose the signing
   and network public keys through the challenge route. Verify returned scope,
   fingerprints, network key and expiry before signing anything.
4. Decrypt the sealed challenge using the separate network private key. Sign
   enrollment v1 and the admission wrapper using the signing private key.
   Submit both proofs and the same bearer token to `POST /v1/enrollment`.
5. Treat HTTP 201 `enrollment-accepted.v1` as a committed admission. Verify its
   device, deployment, signing key and network key against the pending request.
   A lost response is uncertain. Retrying a consumed token is rejection and
   cannot establish that the earlier request committed. Authenticated receipt
   lookup and recovery remain separate work.

Starting the same token/key tuple again returns its existing challenge.
Another key tuple cannot replace it. Neither a challenge nor an isolated
signing enrollment creates a network binding. A failed final admission leaves
the token, challenge and both identity records unchanged.

## Inspect retained state

Migration 004 adds `bootstrap_tokens`, `enrollment_network_challenges` and
`device_network_bindings`. Tokens retain issuer/subject provenance and SHA-256
of their lowercase-hex ASCII encoding. Network challenges retain a sealed box
and SHA-256 of the decrypted random bytes. Plaintext tokens and decrypted
proofs are never stored. The network binding retains the public key and full
signed-admission request fingerprint; signed enrollment provenance stays in
the existing repository. There is no public binding lookup route.

Rows are deployment-scoped. Duplicate signing keys, network keys and device
bindings cannot replace existing identities. Old signing-only rows remain
signing-only after migration. Storage errors, cancellation and uncertain commits
fail closed. Only a committed `AdmitEnrollment` creates network admission state.
Future mesh/evidence consumers must retrieve the binding, authenticate the
actual network peer and apply the device revocation policy independently.

Expiry does not delete rows. Cleanup, early bootstrap-token revocation,
rate limits, endpoint key protection, key rotation/recovery, device revocation,
authenticated receipt reconciliation and off-host backup restore remain open.
Keep storage and proxy access restricted. All records remain off-chain.

## Reproduce the evidence

Use an isolated PostgreSQL 17 database with permission to create disposable
test databases, then run:

```sh
nix develop --command make contract-check check cross-build
TEST_DATABASE_URL='postgres://TEST_USER@127.0.0.1:TEST_PORT/postgres?sslmode=disable' \
  nix develop --command make database-check
nix develop --command make storage-crash-check
```

The database target covers real TLS HTTP handlers, PostgreSQL sessions and
token/proof persistence, denied authorization, strict parsing, expiry,
concurrent start/redemption, key conflicts, cancellation and rollback at every
admission write plus a deferred COMMIT failure. Session fixtures bypass the
external IdP; these tests do not qualify a real provider or browser login.

The crash target creates its own disposable cluster and abruptly restarts it.
It verifies that token/challenge consumption and both identity bindings survive
recovery, with `fsync` and `full_page_writes` enabled. It never restarts the
database named by `TEST_DATABASE_URL`. This target remains opt-in outside CI.
Passing these checks does not qualify a production deployment or physical endpoint.

The sealed-box implementation is pinned `golang.org/x/crypto/nacl/box` v0.58.0,
under the BSD-3-Clause license. Its [documented NaCl and libsodium interoperability](https://pkg.go.dev/golang.org/x/crypto/nacl/box)
avoids a custom encryption construction. Go's `crypto/ecdh` rejects low-order
X25519 inputs; the contract also rejects noncanonical key aliases. The dependency
adds `x/sys` and updates the versions of `x/sync` and `x/text` required by that
module. Review these dependencies through the existing Go module workflow.
