# Relay and bootstrap deployment surface

This directory contains a [reproducible self-hosted DERP lab](derp-lab.md) and
records the future deployment boundary for DERP maps, TLS/bootstrap
configuration, persisted network identity, and firewall rules. The lab runs the
pinned upstream server, not Shepherd's placeholder relay executable. It is not
a production deployment.

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
authentication and authorization for this deployment. Credential issuance,
administrator OIDC/session policy is selected in
[decision #74](../../docs/decisions.md#console-and-administrator-identity-src04-74);
provider registration and route implementation remain absent. HTTPS
alone grants no access. Restrict the public
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

These are expected outcomes, not passing tests or new route contracts. Each
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
unauthenticated controller fixture and unavailable mesh adapter establish none
of these production access guarantees.
