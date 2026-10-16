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
source or enable the production adapter.

Reuse is architectural: preserve a server listener and client HTTP transport
over userspace WireGuard, persist node identity/server keys and PSK, admit only
enrolled node keys, bind requests to peer identity, disconnect revoked nodes,
and use self-hosted DERP when direct connectivity fails. Go 1.27.1 aligns with
the inspected Tailcat module. The isolated
[NET01 direct lab](tailcat-lab/README.md) now pins and exercises the upstream API on one Linux host. Cross-platform runtime and production
acceptance remain open.

`mesh/` is the Go seam. Its constructors currently return `ErrNotImplemented`.
It must never silently fall back from mesh to unauthenticated public HTTP.
Loopback fixtures have an explicitly separate listener.

No node-to-node artifact distribution is required yet: Shepherd used it for
package/configuration delivery. Add authenticated model distribution if the
patent implementation needs it, without importing the entire fleet manager.

## Required evidence before enabling the adapter

- Direct LAN, NAT/WAN and blocked-UDP DERP-only round trips.
- Stable identity/address across controller and endpoint restarts.
- Unknown peer rejected; admitted peer bound to the right device ID.
- Revoked peer actively disconnected and rejected on reconnect.
- Explicit self-hosted DERP map; no public relay defaults in production.
- Relay configuration, dependency revision/license and measured transport mode.

## NET01 lab evidence

[The pinned direct-UDP lab](tailcat-lab/README.md) proves a bounded application
exchange before and after restarting both peer processes. It closes its private
bootstrap relay before the measured application exchange and verifies persisted
network keys, configured admission, and peer identity.
[Recorded evidence](tailcat-lab/evidence/2026-10-16.md) also names failed experiments and unqualified recovery paths. Run
`make tailcat-lab-check` and `make tailcat-lab-proof` to reproduce it.

This lab is independent of the production seam and its unavailable constructors.
The production requirements above, including real-device binding and revocation,
remain acceptance gates for #25. The local bootstrap is not #84's deployed DERP
qualification, and it does not implement #73/#75's bootstrap authorization or
device-evidence signature consumers.
