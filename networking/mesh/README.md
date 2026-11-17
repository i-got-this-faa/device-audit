# Admitted application mesh, #25

The root module imports Tailcat at
`v0.7.1-0.20261007201807-52fbad323e9d`, the same API exercised by the
independent lab. Preserve the [third-party notices](../tailcat-lab/README.md#immutable-dependency-and-license)
when distributing binaries. This is local implementation and test evidence,
not deployed service or Windows qualification.

## Configuration and provisioning

1. Provision the controller with
   `controller --mesh-init --mesh-state-dir /private/controller-mesh`.
   This exclusively creates node/PSK state and prints only the public X25519
   key. On Unix the directory is mode 0700, owned by the current user, and the
   state file is mode 0600. On Windows the same JSON state is stored under a
   protected DACL for the current user, or for an enabled per-service SID when
   the process token is LocalService. LocalService without that SID fails
   closed. Startup does not generate replacement keys or repair an existing
   ACL. Pin the printed public key on endpoints through trusted configuration.
2. Configure an operator-owned local DERP region JSON file. It uses Tailcat's
   `tailcfg.DERPRegion` format with at least one node, explicit `DERPPort`,
   `STUNPort: -1`, matching positive region/node IDs, and a self-hosted TLS
   hostname. No remote map is fetched. `InsecureForTests` is accepted only
   with literal loopback hostname/IPv4 and `IPv6: "none"`. Public relay
   defaults and `TS_DEBUG_ADDR` are rejected. No proxy or forwarding is enabled.
   Generate this file with `relay --print-region` from the
   [scoped relay](../../infra/networking/README.md#deploy-the-scoped-relay-net05-88)
   rather than writing it by hand. Production nodes may pin `IPv4` and
   `CertName` but never use `InsecureForTests`.
3. Start the controller with its existing PostgreSQL, deployment, TLS and OIDC
   configuration plus `--transport mesh --mesh-state-dir /private/controller-mesh
   --derp-region-file /config/private-region.json --ack-key-file
   /private/controller-ack.pem`. The acknowledgement key is a PKCS#8 PEM Ed25519
   key, for example from `openssl genpkey -algorithm ed25519`. It signs CT04
   receipts only. Never reuse the mesh, TLS, device or chain key. Protect it like
   the TLS private key. Export its public half with `openssl pkey -pubout` and pin
   that file on endpoints. All enrollment prerequisites remain required. The server writes `mesh-address` inside its private state
   directory. This address contains a PSK: never print it or pass it on a command
   line. Deliver it to each admitted endpoint using protected operator IPC/files.
   The endpoint file must be named `mesh-address` inside its existing identity
   directory and satisfy that directory's existing private ACL/file checks.
4. Enroll endpoints through the separate trusted HTTPS origin as documented in
   [endpoint enrollment](../../apps/endpoint-agent/README.md). Application startup
   requires the matching saved admission receipt and reuses the protected X25519
   key. It never provisions another transport identity.
5. Submit an already signed CT04 envelope from stdin using
   `endpoint-agent --transport mesh --state-dir /private/endpoint
   --mesh-server-key PUBLIC_HEX --controller-ack-key-file /config/controller-ack.pub.pem
   --derp-region-file /config/private-region.json`. The agent prints the verified
   acknowledgement JSON and exits non-zero for a rejection or an unverified reply.
   The URL is fixed to `http://controller.mesh:8080/v1/evidence` inside WireGuard.
   HTTP redirects, environment proxies and other destination hosts/ports are
   disabled. HTTP here is inside the authenticated encrypted tunnel.

Controller identity/PSK and endpoint identities survive process restart. Disco
keys and the bootstrap address are derived by the pinned API. An existing
address file must match; an operator must explicitly remove a stale address
when changing relay configuration. Keep private state and its permissions in
backups; missing, damaged or concurrently owned state fails closed. Controller
state is protected by Unix permissions or the Windows DACL above, not by
encrypting the node key or PSK. Windows flushes the state file and has no
directory fsync; power-loss recovery is unclaimed on either platform. Endpoint
Windows DPAPI/ACL rules for the device identity are unchanged. Do not copy an
endpoint directory to two active installations.

## Authorization and HTTP boundary

Tailcat's admission hook resolves the actual peer key against PostgreSQL's
committed network/signing admission join. Unknown peers, revoked devices and
lookup outages cannot establish a new application session. The server
limits concurrent admission lookups to four, leaving capacity for evidence and
administrator operations in the configured ten-connection database pool. A
saturated admission hook denies immediately; clients may retry later. The handler
rechecks that binding on each evidence request and disconnects denied peers. No
request header supplies peer identity. Before it calls the repository, the
handler verifies the envelope version, deployment, device and signing key ID
against the binding, the Ed25519 signature against the admitted signing public
key, and the declared expiry and future-skew policy. The repository repeats its
own signature, expiry, sequence and revocation checks inside the evidence
transaction. This is not a device-revocation API or a key-rotation implementation.

Every rejected request writes one structured `evidence rejected` log record with
`event=evidence_rejected` and the contract `reason`. The record names the tunnel
key (`peer`) as the attributable principal. It adds the bound `device_id` and
`deployment_id` after admission, the envelope's `claimed_device_id` when it
matches the opaque ID grammar, and `request_sha256` when the signed fields are
well formed. It never contains the payload or the signature. Storage failures
log at error level and security rejections at warning level.

Only `POST /v1/evidence` is exposed on mesh TCP port 8080. The request is the
existing strict `device-audit.evidence.v1` contract, bounded to 400 KiB, without
queries. HTTP 200 carries a signed `device-audit.acknowledgement.v1` with status
`accepted`, sent only after COMMIT returned. Its `received_at` is the stored
receive time. Malformed input and queries are 400 (`invalid_payload`). Peer,
deployment and signing-key scope denials are 403. Signature, timestamp, replay
and other envelope rejections are 409. Storage and uncertain commit failures
are 503.

A rejection also carries a signed acknowledgement (status `rejected`) when the
request is correlatable and names the admitted peer's own deployment and device.
`last_sequence` is the mark read under the device row lock (replay, and expiry
found under the lock), otherwise null. Other rejections, including unadmitted or
misbound peers, get a plain-text error. A 503 is never signed: a failed COMMIT may
still have committed, so the controller cannot truthfully reject it.

Concurrent copies of one envelope serialize on the device row lock. One gets
`accepted`; every other copy gets a signed `replay` with the committed mark.
The endpoint verifies the pinned key and every correlation field before it
trusts a reply. Lost replies remain uncertain. Preserve the signed envelope;
never fabricate a receipt or allocate a new sequence for an automatic retry.
A `replay` after a lost reply does not prove that this payload was stored.
Authenticated receipt lookup remains open.

Bootstrap, inventory, OIDC and administrator routes use the separate HTTPS
listener, with existing authorization. In mesh mode that listener excludes the
unsigned fixture ingestion/read routes and evidence route. Mesh contains none of
those administrator/bootstrap handlers. Loopback fixture mode remains explicitly
ephemeral and unauthenticated.

## Verification

`go test -race -count=1 -v ./networking/mesh` starts separate real Tailcat engines,
proves a direct UDP path plus peer-bound HTTP, restarts both processes with the
same server state and endpoint network key, and rejects an unknown key before
and after restart. It also checks corrupt/missing state and duplicate provisioning.
Controller HTTP tests exercise scope denial, tampering, unavailable storage and
administrator separation, and prove that rejected envelopes never reach the
repository. With `TEST_DATABASE_URL`, durable admission tests use the actual TLS
enrollment handlers and an independent PostgreSQL repository, then deny a revoked
binding. `TestEvidenceVerificationRejectsBeforeIngestion` sends forged, altered,
wrong-key, misbound-peer, unknown-peer, expired, future, wrong-version and
wrong-deployment evidence through two enrolled devices. It checks the status, the
security event and that no sample or sequence mark changed. Run `make check` and `make cross-build` too.

`go test -race -count=1 ./networking/mesh` also reloads the persisted public key,
rejects a second owner, a changed address and corrupt state. On Windows that
package test additionally rejects a pre-existing unprotected directory and a
broadened or unreadable DACL. Those Windows checks run under the account that
executes the test. They do not qualify LocalService or the selected physical
laptop.

`CheckRelay` and `CheckServerRelay` connect to the configured relay with the
admitted key before a session starts. Tailcat finds the controller through the
relay, so a cold session cannot start without it. The endpoint refuses to send
when the check fails. The controller logs the error and keeps HTTPS running.
`TestScopedRelayDirectAndRelayDelivery` and
`TestScopedRelayUntrustedCertificateFailsVisibly` (Linux) run separate processes
through `networking/relay` with a verified test-CA certificate. They cover
direct and relay delivery and relay and controller admission. They also cover
a closed relay and an impostor relay. `make relay-fallback-proof` repeats them
with all UDP dropped. See
[relay fallback evidence](../../docs/validation/relay-fallback-88.md).

Same-host direct transport is not a NAT/WAN result. The direct UDP restart
test is built for Linux and Darwin. The independent relay lab remains separate
evidence. Real service-token execution, installed packages, deployed
DERP/proxy/IdP, client-only/server-only restarts, power-loss storage recovery
and full production rollout are unqualified. See
[mesh adapter evidence](../../docs/validation/mesh-adapters-25.md).
