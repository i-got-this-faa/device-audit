# Relay and bootstrap deployment surface

This directory contains a [reproducible self-hosted DERP lab](derp-lab.md), the
[scoped relay deployment steps](#deploy-the-scoped-relay-net05-88) and the
deployment boundary for DERP maps, TLS/bootstrap configuration, persisted
network identity and firewall rules. Both the lab and `apps/relay` run the
pinned upstream server, not Shepherd's placeholder relay executable. Neither
is a qualified production deployment yet.

DERP relays encrypted WireGuard traffic; it does not authenticate application
requests or validate device reports. Verify authentication/rate-limit options
against the exact upstream revision. Direct UDP, relay-only and offline modes
need separate integration evidence. Production bootstrap requires HTTPS and
authenticated enrollment; do not expose the development controller publicly.

## Provisional hosting and access boundary, #73

[Decision #73](../../docs/decisions.md#provisional-hosting-persistence-and-tenancy-73)
uses a private controller/database host and a separate public self-hosted DERP
host per organization. These are reversible planning choices pending #14, not deployed services or
a release-platform selection. SRC05 #72 separately records source reconciliation.

Expose bootstrap enrollment, administrator access and DERP map publication over
HTTPS through a proxy. Enrollment requires a single-use, expiring bootstrap
credential authorized by the operator. Administrator access requires
authentication and authorization for this deployment. The [#18 enrollment service](../enrollment/README.md) implements credential
issuance and proof-bound admission. Administrator OIDC/session policy is selected in
[decision #74](../../docs/decisions.md#console-and-administrator-identity-src04-74)
and a minimal local implementation is recorded under #82. Real provider
registration, browser qualification and deployed proxy qualification remain
open. Enrollment requires TLS on the upstream connection too. HTTPS alone grants no access. Restrict the public
proxy to those intended surfaces; device telemetry uses the authenticated mesh,
and the database has no public listener. The relay receives no database access
or application secrets. Pin and verify its admission/rate-limit behavior before
public exposure. Relay access alone grants no controller access.

The deployment operator owns TLS private keys, bootstrap credentials, controller
mesh state and PSK, database credentials and backup keys. Endpoints keep their
own mesh and device-signing private keys in protected persistent local state.
Persist server and endpoint network identities across restarts. Rotation and
revocation require implementation evidence. Network admission, device-report
signature verification and any future chain signer use separate credentials
and checks. No raw logs or device identifiers go on-chain.

## Request cases for future implementation tests

Bootstrap request cases below now have #18 TLS/PostgreSQL integration tests.
The remaining cases are requirements for later consumers. Each
deployment belongs to one organization. A caller's tenant header or device ID
does not establish identity.

- Allow enrollment over HTTPS with a valid, unexpired operator-authorized
  bootstrap credential for this deployment. Deny missing, expired, reused or
  other-deployment credentials; plaintext enrollment must not process secrets.
- Allow `POST /v1/telemetry` over the mesh from an enrolled, non-revoked peer
  bound to device A, with a valid device-A signature and fresh sequence.
  Deny a payload naming device B, an invalid signature or replay. Mesh admission
  alone is insufficient. Deny telemetry through the public bootstrap proxy.
- Allow an authorized administrator of organization A to read A's device through
  authenticated HTTPS access. Deny anonymous callers, organization B's
  credentials and an endpoint attempting to read another device. Changing a
  header to name A must not bypass those checks.
- Deny unknown or revoked mesh peers, including on reconnect. A connection via
  DERP must satisfy the same identity and application checks as direct UDP.
- Deny database connections from endpoints, the relay and the public internet.

Validate these cases, secret rotation and restart identity persistence before
exposing any service. The [isolated NET04 lab](derp-lab.md) measures blocked-UDP
DERP traffic and relay restart on one Linux host. Direct UDP, DERP-only and offline
failure behavior still need evidence on #14's selected machines. The current
unauthenticated loopback fixture API, minimal local console/auth surface and
admitted mesh adapter do not establish deployed production access guarantees.

## Deploy the scoped relay, NET05 #88

`apps/relay` wraps the pinned `derpserver` for one organization. Run it on the
public relay host, not on the controller host. The relay needs no database
access and no application secrets.

1. Create the relay key once, on protected storage:
   `relay --init-key --key-file /var/lib/device-audit-relay/relay.key`.
   The file is created exclusively with mode 0600 and is never replaced.
2. Get a certificate for the relay's DNS name from a CA the endpoints trust.
   The relay checks that the certificate covers `--hostname` and is currently
   valid. It does not issue or renew certificates; restart it after renewal.
3. Write the admission file. It lists the controller's public node key
   (`controller --mesh-init` prints it) and each enrolled endpoint's network
   public key:

   ```json
   {"version":"device-audit.relay-admission.v1","network_public_keys":["<64 lowercase hex>"]}
   ```

   Unknown fields, malformed keys and an empty list are rejected. The file is
   re-read on every connection. Replace it atomically to add or remove keys.
   A damaged file denies everyone.
4. Start the relay:
   `relay --listen :443 --hostname relay.example.org --tls-cert chain.pem
   --tls-key key.pem --key-file relay.key --admission-file admission.json`.
   Allow inbound TCP on that port only. No UDP 3478 (STUN) or TCP 80
   listener is opened. Do not put an HTTP proxy in front, because DERP switches
   protocols inside TLS.
5. Generate the region file for the controller and endpoints:
   `relay --print-region --hostname relay.example.org --port 443 --region-id 900`.
   Add `--ipv4` to pin the dial address. Add `--cert-name sha256-raw:<hex>` to
   pin one certificate, but that pin must be changed on every renewal.
   Distribute the file through trusted configuration and pass it as
   `--derp-region-file`.

When the mesh starts, the controller and the endpoint agent connect to the
relay with their admitted key. They check TLS and admission and require a DERP
ping reply. A failure reports `self-hosted DERP relay unavailable` with the
region, host and port. The endpoint then refuses to send and keeps the signed
envelope. The controller logs the error and keeps its HTTPS boundary running.
Neither falls back to public relays or weaker TLS.

`make relay-fallback-proof` runs the application mesh through this relay in a
private namespace with all UDP dropped. Results and remaining gaps are in
[relay-fallback-88.md](../../docs/validation/relay-fallback-88.md). Public DNS,
a public CA certificate, real host firewalls, NAT/WAN, the selected Windows
laptop and automatic export of revocations to the admission file are still open.

`make recovery-proof` (NET03 #54, needs `TEST_DATABASE_URL`) restarts this
relay and a mesh controller, and partitions both, while the endpoint service
delivers. It runs on one host with direct and forced-DERP paths. Limits and
timings are in [recovery-54.md](../../docs/validation/recovery-54.md). That
same-host Linux run checked two limits. After a restored path, the backlog was
stored within 90 s. When the configured relay became unavailable during the
partition, the loss was logged as `self-hosted DERP relay unavailable` within
40 s. These are checks from the fixture run, not guarantees for deployed LAN,
WAN or Windows service recovery.
