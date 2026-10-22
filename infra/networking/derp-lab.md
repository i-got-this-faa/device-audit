# Prove self-hosted DERP fallback

This is the Linux development lab for [NET04 #84](https://github.com/i-got-this-faa/device-audit/issues/84).
It extends the merged [NET01 #20 transport seam](../../networking/tailcat-lab/README.md),
not the unavailable production `networking/mesh` adapter. It starts a real
self-hosted upstream DERP server and two separate Tailcat peer processes in a
fresh private network namespace. No hosted relay or mocked transport is used.

## Run the experiment

Install Go 1.27.1, util-linux `unshare`, iproute2 `ip`, and nftables `nft` on Linux.
The kernel must allow unprivileged user and network namespaces and nftables in
that namespace. The runner does not use `sudo`, Docker, the host Tailscale daemon,
TUN, a bridge, host routes, or host firewall rules. Do not run it in an existing
shared network namespace as a workaround for missing permissions.

From the repository root, run:

```sh
make derp-lab-proof
```

The runner compiles the pinned nested module before removing network access.
It then creates a new user/network namespace, verifies it differs from the
parent, enables its loopback interface, and installs this namespace-only rule:

```nft
table inet device_audit_derp {
    chain output {
        type filter hook output priority 0; policy accept;
        meta l4proto udp counter drop
    }
}
```

All output UDP, including peer discovery and WireGuard transport, is blocked
before the peers cold-start. TCP loopback remains available to the single
configured relay. There is no non-loopback interface, route to a public relay,
or public DERP map fallback. The runner removes its temporary executable on
exit. Namespace destruction removes its interfaces and firewall rules; it does
not flush host rules or stop other processes or containers.

The experiment fails rather than substitutes direct UDP or silently skips when
run through this target. Ordinary module checks skip only the explicit
namespace experiment; they still run the existing direct-UDP and admission
checks. Run those checks separately after implementation:

```sh
make tailcat-lab-check
make check
make cross-build
```

The lab report includes bootstrap-address digests, not bootstrap addresses.
The private Tailcat address is passed only through anonymous peer pipes. Do not
publish raw peer pipes or enable upstream credential-bearing debug logs.

## Read the evidence

The [measured run](../../networking/tailcat-lab/evidence/2026-10-21-derp.md)
records the actual packet counters, application deliveries, outage, and restart
timing. An nftables drop counter proves attempted UDP was blocked. DERP path
observations and relay forwarding counters distinguish encrypted application
traffic from a TLS connection that only performed bootstrap discovery.

The application exchanges fresh challenges with checked SHA-256 replies through
Tailcat's WireGuard TCP stream. Server admission allows one network public key;
the application listener also binds accepted connections to that key. The client
pins the server key and uses the separately provisioned WireGuard PSK. These are
network authentication checks, not device measurement verification.

The relay listener and its active DERP sockets are closed during the experiment.
Both peer processes remain running. The relay returns on the same TCP port.
Measurements distinguish the configured outage from observed time to resumed
validated delivery. A short interruption is not a failover availability SLO.

## Ports and certificates

| Surface | This lab | Production adapter work still required |
| --- | --- | --- |
| DERP TLS | One ephemeral TCP port on `127.0.0.1`, reused on restart | Publish a stable reachable DNS name and TCP port, conventionally 443. Pinned upstream advises against an HTTP proxy because DERP switches to a custom bidirectional protocol inside TLS. Validate long-lived connection timeouts and egress policy. |
| TLS certificate | Ephemeral Go test certificate with `InsecureForTests` in the explicit loopback-only map | Use a certificate valid for the advertised hostname, trusted by endpoints. Protect its private key and test renewal and invalid certificates. Pinned `derper` automatically rotates Let's Encrypt certificates; manual certificate updates require restart. Never copy `InsecureForTests` into production. |
| STUN | Disabled with `STUNPort: -1`; UDP is dropped | UDP 3478 is the conventional optional STUN service. Provision and test it if selected for NAT discovery; it is not needed for this relay-only experiment. |
| Peer transport | Ephemeral UDP ports, all output dropped | Allow peer UDP when policy permits for direct paths; qualify NAT traversal and blocked-UDP transitions on actual release machines. |
| Application | TCP 8087 inside the userspace WireGuard tunnel only | Bind controller API listeners to the authenticated adapter. Do not expose the lab challenge service or unauthenticated telemetry on the public relay host. |
| Enrollment and map publication | Private local provisioning and an explicit map in memory | Authenticated HTTPS enrollment and trusted map delivery remain separate work. HTTPS transport alone does not grant admission. |
| HTTP/ACME | No port 80 listener | Pinned `derper` defaults to an HTTP listener on TCP 80, also used for HTTP-01. Account for that listener explicitly or disable it when choosing external certificate provisioning. No production issuance method is selected here. |

The real DERP implementation is `tailscale.com/derp/derpserver` at
`v1.103.0-pre.0.20260929142145-a0e471a35b8f`, commit `a0e471a35b8f`.
Tailcat remains pinned at `v0.7.1-0.20261007201807-52fbad323e9d`.
The existing nested `go.mod`, `go.sum`, and license notes remain the source of
truth. No replacement library or dependency upgrade is introduced.

Port, proxy, and certificate guidance is checked against the
[pinned `derper` operational notes](https://github.com/tailscale/tailscale/blob/a0e471a35b8f/cmd/derper/README.md#guide-to-running-cmdderper).
These are configuration requirements, not exercised production evidence.

## Limits before production

- This same-host, namespace-isolated lab is not a public relay deployment, a
  two-machine WAN/NAT qualification, or runtime evidence on the selected Windows
  endpoint. It uses the real upstream server handler, not the `derper` CLI or a
  production service manager.
- Blocking UDP from cold start proves relay-only fallback when direct transport
  is unavailable. It does not measure migration from an already established
  direct path to DERP or back to direct transport.
- Test TLS verification is disabled only within the loopback lab. Public DNS,
  trusted certificates, certificate renewal, reverse proxies, firewalls on real
  hosts, and cross-platform runtime remain unqualified.
- The relay has no production access policy, organization isolation, abuse
  controls, capacity benchmark, health alerting, HA, rolling upgrade, or long
  outage qualification. Do not expose this test handler publicly.
- The production adapter still returns explicit `ErrNotImplemented`. No wire
  contracts, controller/endpoint routes, or device-ID binding change here.
- Network keys, bootstrap admission, device evidence Ed25519 keys, and future
  chain signer keys remain distinct. No device signatures, telemetry truth,
  chain commitments, raw on-chain logs, or patent conformance are demonstrated.
