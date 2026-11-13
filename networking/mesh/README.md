# Admitted application mesh, #25

The root module imports Tailcat at
`v0.7.1-0.20261007201807-52fbad323e9d`, the same API exercised by the
independent lab. Preserve the [third-party notices](../tailcat-lab/README.md#immutable-dependency-and-license)
when distributing binaries. This is local implementation and test evidence,
not deployed service or Windows qualification.

## Configuration and provisioning

1. Provision the controller on a Unix host using
   `controller --mesh-init --mesh-state-dir /private/controller-mesh`.
   This exclusively creates mode-0600 node/PSK state in a current-owner
   mode-0700 directory and prints only the public X25519 key. Pin that public
   key on endpoints through trusted configuration. Startup does not generate
   replacement keys. Windows controller persistence is explicitly unsupported.
2. Configure an operator-owned local DERP region JSON file. It uses Tailcat's
   `tailcfg.DERPRegion` format with at least one node, explicit `DERPPort`,
   `STUNPort: -1`, matching positive region/node IDs, and a self-hosted TLS
   hostname. No remote map is fetched. `InsecureForTests` is accepted only
   with literal loopback hostname/IPv4 and `IPv6: "none"`. Public relay
   defaults and `TS_DEBUG_ADDR` are rejected. No proxy or forwarding is enabled.
3. Start the controller with its existing PostgreSQL, deployment, TLS and OIDC
   configuration plus `--transport mesh --mesh-state-dir /private/controller-mesh
   --derp-region-file /config/private-region.json`. All enrollment prerequisites
   remain required. The server writes `mesh-address` inside its private state
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
   --mesh-server-key PUBLIC_HEX --derp-region-file /config/private-region.json`.
   The URL is fixed to `http://controller.mesh:8080/v1/evidence` inside WireGuard.
   HTTP redirects, environment proxies and other destination hosts/ports are
   disabled. HTTP here is inside the authenticated encrypted tunnel.

Controller identity/PSK and endpoint identities survive restart. Disco keys and
the bootstrap address are derived by the pinned API. An existing address file
must match; an operator must explicitly remove a stale address when changing
relay configuration. Keep private state and its permissions in backups; missing,
damaged or concurrently owned state fails closed. Controller state is protected
by Unix permissions, not encrypted storage. Endpoint Windows DPAPI/ACL rules are
unchanged. Do not copy an endpoint directory to two active installations.

## Authorization and HTTP boundary

Tailcat's admission hook resolves the actual peer key against PostgreSQL's
committed network/signing admission join. Unknown peers, revoked devices and
lookup outages cannot establish a new application session. The request handler
rechecks that binding on each evidence request, checks device/deployment/signing
scope, and disconnects denied peers. No request header supplies peer identity.
Repository signature, expiry, sequence and revocation checks remain independent
and run inside the evidence transaction. This is not a device-revocation API or
a key-rotation implementation.

Only `POST /v1/evidence` is exposed on mesh TCP port 8080. The request is the
existing strict `device-audit.evidence.v1` contract, bounded to 400 KiB, without
queries. HTTP 204 means the repository returned after commit; it has no response
body and is **not** a CT04 signed acknowledgement. Storage/uncertain commit
failures are 503; envelope conflicts are 409; malformed input is 400 and peer
scope denial is 403. Lost replies remain uncertain. Preserve the signed envelope;
never fabricate a receipt or allocate a new sequence for an automatic retry.
Signed acknowledgement/reconciliation policy remains #89.

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
administrator separation. With `TEST_DATABASE_URL`, durable admission tests use
the actual TLS enrollment handlers and an independent PostgreSQL repository,
then deny a revoked binding. Run `make check` and `make cross-build` too.

Same-host direct transport is not a NAT/WAN or physical Windows result. The
independent relay lab remains separate evidence. Real service-token execution,
installed packages, deployed DERP/proxy/IdP, client-only/server-only restarts,
power-loss storage recovery and full production rollout are unqualified.
