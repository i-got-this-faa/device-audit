# Pinned Tailcat direct-UDP lab

This nested Go module implements the bounded lab for [NET01 #20](https://github.com/i-got-this-faa/device-audit/issues/20).
Two real peer processes exchange a fresh challenge and its SHA-256 response through
Tailcat's userspace WireGuard tunnel. The application protocol is TCP inside the
UDP tunnel. No public HTTP transport or replacement UDP encryption is used.

The production `networking/mesh.NewServer` and `NewClient` still return
`ErrNotImplemented`. This lab does not implement enrollment or the controller
transport. Production mesh #25 remains open. The separate
[NET04 DERP lab](../../infra/networking/derp-lab.md) exercises the same pinned
seam with UDP blocked and measures relay restart; it is not a public deployment.

## Reproduce the proof

Run from the repository root with Go 1.27.1 and Linux network access:

```sh
make tailcat-lab-check
make tailcat-lab-proof
# Optional Linux socket syscall evidence. Requires strace.
networking/tailcat-lab/run-proof.sh --trace
```

`tailcat-lab-check` runs vet, race tests, module verification, and formatting in
this module. The test cannot skip a failed direct connection or substitute a
relay success. A fresh run uses random keys, temporary private files, ephemeral
UDP ports, and one loopback relay port. It takes about 12 seconds without race
instrumentation on the measured host. The overall test timeout is 150 seconds.
The `tailcat-lab` Ubuntu CI job runs the same module checks and real direct/restart
experiment on pushes and pull requests, independently of the root module checks.

The trace command emits only aggregate successful UDP send/receive syscall
counts. Its temporary trace contains socket addresses, suppresses payloads with
`-s 0`, and is removed on exit. Do not publish raw traces or bootstrap addresses.
The [measured run](evidence/2026-10-16.md) contains safe observations.

Run application checks separately. The root module intentionally excludes this
large experimental dependency graph:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r models/test-requirements.txt
make PYTHON=.venv/bin/python check cross-build
```

## Immutable dependency and license

The lab pins `github.com/tailscale/tailcat` to
`v0.7.1-0.20261007201807-52fbad323e9d`, commit
[`52fbad323e9d352f1febb623e0975368e9a8cbdd`](https://github.com/tailscale/tailcat/tree/52fbad323e9d352f1febb623e0975368e9a8cbdd).
The commit timestamp is 2026-10-07T20:18:07Z. Its module requires Go 1.27.1.
`go.mod` pins the graph and `go.sum` records downloaded module checksums.
There are no local replacements or upstream patches.

Tailcat's [BSD-3-Clause license](https://github.com/tailscale/tailcat/blob/52fbad323e9d352f1febb623e0975368e9a8cbdd/LICENSE)
is retained in [TAILCAT-LICENSE](TAILCAT-LICENSE). Source redistribution retains
the notice, conditions, and disclaimer. Binary redistribution must reproduce
them in accompanying materials and must not imply Tailscale endorsement.

The other directly imported module is `tailscale.com` at
`v1.103.0-pre.0.20260929142145-a0e471a35b8f`, also
[BSD-3-Clause](https://github.com/tailscale/tailscale/blob/a0e471a35b8f/LICENSE).
Tailcat pins its userspace WireGuard fork at
`github.com/tailscale/wireguard-go v0.0.0-20260924224943-0a83b87f7908`, whose
[license is MIT](https://github.com/tailscale/wireguard-go/blob/0a83b87f7908/LICENSE).
This is a source lab, with no binaries committed. A production distribution
still needs a full transitive notice and dependency review.

## Actual upstream API compatibility

The adapter compiles against these pinned
[Tailcat definitions](https://github.com/tailscale/tailcat/blob/52fbad323e9d352f1febb623e0975368e9a8cbdd/tailcat.go):

| API | Lab use and verified boundary |
| --- | --- |
| `Server.Key`, `Server.PresharedKey` | Reload explicit network credentials. Zero keys are rejected before Tailcat can generate ephemeral replacements. |
| `Server.Region` | Supply exactly one local relay. No default map fetch or public relay selection. |
| `Server.AllowClient` | Admit exactly the configured nonzero node public key. A nil hook would admit everyone and is never used here. |
| `Server.StartContext`, `Server.Listen` | Start a real userspace engine and accept only the lab's TCP listener. Proxy, exit-node, SSH, and shell callbacks remain unset. |
| `Server.PeerKey` | Bind each accepted flow to the admitted network key before replying. |
| `Server.Status` | Observe `CurAddr`, peer identity, and increasing WireGuard RX/TX byte counters. |
| `Client.Key`, `Client.Server`, `Client.DialTCPPort` | Load the client's separate persisted key and dial through Tailcat. The address's server key is checked against a configured pin first. |
| `Client.DiscoPing` | Require a direct endpoint and zero DERP region in the result. The endpoint must belong to this host. |
| `Server.DisconnectClient` | Clean up an admitted wrong-PSK test peer. This is not a proof of production revocation. |

The bootstrap relay uses the real pinned `tailscale.com/derp/derpserver.New` and
`Handler`. Its loopback TLS listener uses `InsecureForTests`, following the
[upstream integration setup](https://github.com/tailscale/tailscale/blob/a0e471a35b8f/tstest/integration/integration.go).
STUN is disabled for this same-host test. The lab rejects a remote or default
relay configuration. Disabling TLS verification is not a production decision.

The current upstream public API requires DERP for its first discovery exchange.
A direct-only cold start with no bootstrap relay is not supported by this lab.
After a successful warmup and direct path selection in both directions, the
proof closes the relay listener and all its hijacked DERP connections. It checks
that the relay port refuses a TCP connection, then opens a **new** application
connection for eight fresh challenge-response round trips. Both peers exit.
The next phase restarts both OS processes from the same state files and relay
address and repeats the proof. The initial warmup is one additional round trip.

## Network admission and private state

The operator provisions client and server network state through
`InitializeClient` and `InitializeServer`. Initialization exclusively creates
0600 files and refuses to overwrite them. The server stores a node private key
and a separate WireGuard PSK. The client stores its own node private key.
Start paths fail on missing, malformed, oversized, symlinked, nonprivate,
unknown-version, zero-key, trailing-data, or missing-server-PSK state.

The test owns a temporary 0700 directory and removes it after all child
processes exit. Operators using the adapter outside the test must provide a
trusted private directory. The lab does not implement secure keystores,
directory-attack resistance, transactional enrollment, key rotation, backups,
or crash-consistent provisioning. An incomplete initialization file requires
explicit operator repair. A syntactically valid replacement key cannot be
identified as corruption without an external pin or protected storage.

The allowed network public key and pinned server key are configured out of band.
The Tailcat address embeds the PSK and is a secret, despite its name. The test
passes it through anonymous local pipes. It never writes it to stdout evidence,
argv, a fixture, or source control. Child environments omit inherited Tailcat
debug knobs, and logs and errors that could contain credential text are suppressed.
Reports contain SHA-256 fingerprints of public keys and the bootstrap address,
not secret keys, raw addresses, telemetry, or device identifiers.

This is manual **lab network admission**, not the authenticated HTTPS enrollment
service planned by #73 and #75. A client with the PSK but an unknown node key
receives no discovery acknowledgement and cannot dial the application. An
allowlisted client with a wrong PSK can complete discovery but cannot establish
an application connection. Those are distinct checks.

The [v1 envelope contract](../../packages/contracts/envelopes-v1.md) uses separate
Ed25519 application signing keys. This lab does not import or generate those
keys, verify telemetry, authorize application actions, or anchor chain evidence.
Network authentication proves possession of the admitted network key and PSK;
it does not prove endpoint measurements true. No blockchain payload is created.

## Limits and observed recovery edge case

- The proof uses two processes on one Linux host, with direct UDP through a host
  interface and a loopback bootstrap relay. It is not a two-machine LAN test.
- WAN, NAT traversal, public relay isolation on deployed hosts, Windows/macOS
  runtime, and long outages are not qualified. The separate
  [NET04 lab](../../infra/networking/derp-lab.md) covers same-host blocked-UDP
  DERP-only operation. Root cross-build checks the existing endpoint binaries,
  not either lab's cross-platform runtime.
- Restart measurement covers both peer processes exiting and starting again.
  Client-only, server-only, machine reboot, crash recovery, and in-place live
  revocation remain unqualified. Public key and bootstrap-address digests are
  stable across the tested process restart. UDP ports need not be stable.
- An exploratory run reused an allowlisted node identity after a wrong-PSK
  attempt against the same server and called `DisconnectClient` in between.
  Client discovery reported direct UDP, but the server's `CurAddr` stayed empty
  for five seconds and the relay-off application dial failed. The cause is not
  established. Admission-failure experiments use a fresh server, separate from
  the clean restart proof. Recovery from that failed-PSK sequence requires
  investigation before production #25, rather than a silent fallback.
- The lab has one configured peer and one bounded application protocol. It
  provides no production device-ID binding, durable admission database,
  organizational policy, multi-tenant authorization, or production availability
  claim. It makes no patent implementation or conformance claim.
