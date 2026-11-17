# NET05 #88 scoped relay and fallback evidence, 17 November 2026

Acceptance evidence for [issue #88](https://github.com/i-got-this-faa/device-audit/issues/88).
This records what was implemented and run in a Linux amd64 workspace. It is
software evidence. No public relay host, DNS name, public certificate or
second machine was available, so nothing here is a deployed-service claim.

## What was added

- `networking/relay` and `apps/relay`: a deployable relay built on the pinned
  upstream `tailscale.com/derp/derpserver` (`a0e471a35b8f`). The operator selects
  the hostname, certificate chain/key, listen port, persisted relay key and an
  admission file. Startup rejects an IP hostname, a certificate that does not
  cover the hostname, an expired or not-yet-valid certificate, a mismatched key,
  a group/world-readable relay key, and a missing, empty, malformed or
  unknown-field admission file. Only `/derp`, `/derp/probe`,
  `/derp/latency-check` and `/generate_204` are served over TLS with HTTP/1.1.
  There is no STUN listener, HTTP/ACME port 80 listener, debug page, mesh key or
  application route.
- Relay admission: pinned `derpserver` admits clients only through a URL, so
  the relay serves its allowlist on a loopback listener with a random path and
  disables fail-open. The admission file (`device-audit.relay-admission.v1`)
  lists the controller node key and enrolled endpoint network keys. It is
  re-read on every client connection, so removing a key affects the next
  connection without restarting. A damaged file denies everyone.
- `relay --print-region` emits the `tailcfg.DERPRegion` JSON that
  `networking/mesh` accepts (`STUNPort: -1`, no `InsecureForTests`, optional
  IPv4 dial pin and optional `CertName` such as `sha256-raw:<hex>`). It refuses
  to print a region the adapter would reject.
- `mesh.CheckRelay` / `mesh.CheckServerRelay`: a preflight using the admitted
  network key, the pinned `derphttp` client and the same TLS verification as
  Tailcat. It completes a DERP handshake and requires a ping reply. Failures
  wrap `mesh.ErrRelayUnavailable` and name the region, host and port.
  The endpoint agent refuses to send evidence when it fails, keeping the signed
  envelope. The controller logs an error at startup and keeps HTTPS enrollment
  and administration running. Tailcat finds the controller through the relay,
  so a cold mesh session cannot start without it.

## Acceptance criteria

| Criterion | Result | Evidence |
| --- | --- | --- |
| Deploy pinned DERP with the selected certificate, port and admission configuration | Implemented and run on loopback; **not deployed to a public host** | `TestRelayConfigurationFailsClosed`, `TestRelayServesOnlyDERPRoutesWithSelectedCertificate`, `TestRelayKeyPersistsAcrossRestart`, `apps/relay` tests. The mesh tests run the same package with a test CA certificate for `relay.device-audit.test`. |
| Connect admitted adapters to the configured relay map | Run | `TestScopedRelayDirectAndRelayDelivery` starts separate controller and endpoint Tailcat processes on the generated region. Both preflights pass with normal certificate verification (the test CA is supplied via `SSL_CERT_FILE`, not `InsecureForTests`). |
| Real direct delivery passes | Run (same host) | Same test: direct UDP path observed with `DiscoPing`, peer-bound HTTP 204. |
| UDP-blocked relay delivery passes | Run (same host, real blocked UDP) | `make relay-fallback-proof` runs the test in a new user/network namespace where nftables drops all output UDP. The admitted peer got HTTP 204 over the DERP path, and the relay's non-Disco packet counter rose. CI job `relay-fallback` runs the same target. In ordinary `go test` the relay phase uses upstream `TS_DEBUG_ALWAYS_USE_DERP=1` instead. |
| Invalid relay endpoint fails visibly | Run | A closed relay, an impostor relay whose certificate chains to an untrusted issuer, and an endpoint key missing from relay admission each produce `ErrRelayUnavailable` from the preflight. No application request was delivered in any of these cases. |
| Without downgrading peer authentication | Run | No failure case falls back to a public relay, plaintext or skipped TLS. `InsecureForTests` cannot be set for a non-loopback relay name. A key admitted at the relay but unknown to the controller is still denied by controller admission. Relay access does not grant controller access. |

## Runs

Go 1.27.1, Linux amd64 (CachyOS kernel 7.3), 17 November 2026.

`make relay-fallback-proof` (UDP blocked by namespace nftables):

```text
private_network_namespace=true all_output_udp=drop tcp_loopback=allowed
relay: admitted peer delivered over the configured DERP region (Tailcat local ID 1) with HTTP 204; relay non-disco packets 0 -> 23
relay: relay-only key denied by controller; relay-unadmitted key reported relay failure and was not delivered
invalid endpoint: closed relay reported by preflight; no delivery
udp-blocked: namespace nftables dropped 14 output UDP packets
--- PASS: TestScopedRelayDirectAndRelayDelivery (18.23s)
--- PASS: TestScopedRelayUntrustedCertificateFailsVisibly (5.06s)
meta l4proto udp counter packets 14 bytes 2268 drop
```

`go test -race -count=1 -v -run ScopedRelay ./networking/mesh` (direct, then forced DERP):

```text
direct: trusted relay preflight passed; admitted peer delivered over direct UDP with HTTP 204
relay: admitted peer delivered over the configured DERP region (Tailcat local ID 1) with HTTP 204; relay non-disco packets 6 -> 26
relay: relay-only key denied by controller; relay-unadmitted key reported relay failure and was not delivered
invalid endpoint: closed relay reported by preflight; no delivery
--- PASS: TestScopedRelayDirectAndRelayDelivery (29.31s)
--- PASS: TestScopedRelayUntrustedCertificateFailsVisibly (7.32s)
```

Tailcat encodes the single configured region with local ID 1. The relay path
check is therefore "a DERP region and no direct endpoint", not a match on the
operator's region ID.

`make PYTHON=/tmp/device-audit-venv/bin/python check cross-build` passed:
`go vet`, `go test -race ./...` (including `networking/relay`, `apps/relay`
and `networking/mesh`), 34 model tests, fake-controller scenarios, formatting,
and the Windows amd64 and Darwin arm64 endpoint builds. The virtualenv used
`models/test-requirements.txt`.

`make database-check` was not run locally because no PostgreSQL server or
running Docker daemon was available. The pull request `database` job runs it,
including the endpoint mesh integration, which now runs the relay preflight.

## Observed limitation

With `TS_DEBUG_ALWAYS_USE_DERP=1`, upstream wireguard-go can block in
`Device.Close` after delivery. Test children in that mode exit after a passing
run without closing. With real blocked UDP, children closed normally.

## Not done here

- No public relay host, DNS record, public CA certificate, port 443 firewall
  rule or service manager unit was deployed. Certificate renewal requires a
  relay restart. ACME is not built in.
- Same-host loopback only. NAT/WAN, two machines, the selected Windows laptop
  and migration from an existing direct path to DERP and back are not measured.
- Relay admission is a static operator file. The controller does not export
  admitted keys yet, so revoking a device does not update the relay
  automatically. Controller admission still denies revoked peers.
- No relay rate limiting, abuse controls, capacity benchmark, health alerting,
  HA or long-outage measurement.

No production, patent, prediction or privacy claim follows from this record.
