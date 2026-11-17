# Shepherd network design carried forward

Inspected source: `i-got-this-faa/shepherd`, commit
`03c20ced6e995961eefac841188e1ab90b4f4f59` on 2026-10-13.
Primary engineering references:

- [Networking specification](https://github.com/i-got-this-faa/shepherd/blob/03c20ced6e995961eefac841188e1ab90b4f4f59/docs/specs/14-networking.md)
- [Network package status](https://github.com/i-got-this-faa/shepherd/blob/03c20ced6e995961eefac841188e1ab90b4f4f59/networking/README.md)
- [Shepherd V1 project](https://github.com/orgs/i-got-this-faa/projects/5)
- [Tailcat upstream](https://github.com/tailscale/tailcat)

Shepherd's network tree contains scaffolding, not an implemented transport.
Its relay executable prints a placeholder message. The public project marks
the mesh spike/library/relay/integration/connectivity tasks as open: #50, #51,
#97, #98, #173, #174 and feature #248. No functional networking source was
copied from Shepherd. The separately versioned Tailcat lab imports pinned upstream modules; it does not vendor their
source. The application adapter lives in `mesh/` and is not that lab.

Reuse is architectural: preserve a server listener and client HTTP transport
over userspace WireGuard, persist node identity/server keys and PSK, admit only
enrolled node keys, bind requests to peer identity, disconnect revoked nodes,
and use self-hosted DERP when direct connectivity fails. Go 1.27.1 aligns with
the inspected Tailcat module. The isolated
[NET01 direct lab](tailcat-lab/README.md) pins and exercises the upstream API on one Linux host. The application adapter is separate from that lab. NAT/WAN, deployed relay hosts and physical-device qualification remain open.

[`mesh/`](mesh/README.md) implements the pinned admitted adapter. It imports the
protected endpoint network identity, persists controller identity on Unix and
with a Windows ACL store, and requires explicit self-hosted relay configuration.
It never falls back to public HTTP. Loopback fixtures have an explicitly separate listener.

No node-to-node artifact distribution is required yet: Shepherd used it for
package/configuration delivery. Add authenticated model distribution if the
patent implementation needs it, without importing the entire fleet manager.

## Evidence required before a deployment claim

- Same-host direct UDP and peer-bound HTTP, including restart, are covered by
  the Linux/Darwin mesh transport test. NAT/WAN is not.
- Controller node/PSK state reloads on Unix and Windows. Endpoint network
  identity reloads from its existing protected store. Power-loss recovery is not
  covered.
- Unknown peers are rejected. Admitted peers are checked against PostgreSQL
  device admission, and a revoked binding is denied on the next request.
- Explicit self-hosted DERP configuration is required, and public relay defaults
  are rejected. The separate NET04 lab measures blocked-UDP relay behavior.
  NET05 #88 adds the deployable `apps/relay` and a relay preflight. It also runs
  this adapter through that relay with all UDP dropped on one host, as recorded
  in [relay-fallback-88.md](../docs/validation/relay-fallback-88.md). A
  deployed public relay is not qualified.
- Windows ACL checks cover the controller state directory when the mesh package
  tests run on Windows. The selected physical laptop, LocalService token and
  installed service remain unqualified.

## NET01 lab evidence

[The pinned direct-UDP lab](tailcat-lab/README.md) proves a bounded application
exchange before and after restarting both peer processes. It closes its private
bootstrap relay before the measured application exchange and verifies persisted
network keys, configured admission, and peer identity.
[Recorded evidence](tailcat-lab/evidence/2026-10-16.md) also names failed experiments and unqualified recovery paths. Run
`make tailcat-lab-check` and `make tailcat-lab-proof` to reproduce it.

The [NET04 self-hosted DERP lab](../infra/networking/derp-lab.md) adds a separate
namespace-isolated blocked-UDP and relay-restart experiment. Run
`make derp-lab-proof`; its [measured evidence](tailcat-lab/evidence/2026-10-21-derp.md)
records relay forwarding and recovery without a direct path.

These labs are independent of the application adapter. The adapter's tested
restart, admission and HTTPS separation behavior is recorded in
[mesh adapter evidence](../docs/validation/mesh-adapters-25.md). NAT/WAN,
deployed DERP, physical devices and external IdP qualification remain open.
Neither lab implements #73/#75's bootstrap authorization or device-evidence
signature consumers.
