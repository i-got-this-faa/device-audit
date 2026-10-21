# NET01 completion and coverage record

## Scope and hard constraints

- Work only in `/home/radhey/.t3/worktrees/device-audit/t3-146f99ee`. Fetch first
  and branch from `origin/main`, not stale `48d1c76`. Keep the unrelated parent
  checkout and its roadmap changes untouched.
- Own `networking/` and minimal build wiring only. Keep production mesh
  constructors explicitly unavailable. Do not implement production enrollment,
  controller transport, telemetry signatures, DERP deployment, or chain anchors.
- Use actual immutable upstream Tailcat APIs and record license compatibility.
  Do not substitute HTTP or an invented UDP transport for the tunnel.
- Keep network credentials, Ed25519 evidence signatures, bootstrap authorization,
  and chain signing separate. Do not log or commit private keys, PSKs, raw device
  identifiers, payload logs, or full bootstrap addresses. Never put them on-chain.
- Do not claim fixtures, interfaces, this lab, cross-builds, or source mapping
  prove production capability, runtime on another OS, or patent conformance.
- Preserve nullable metrics and explicit units. No shared wire contract changes
  are needed for this local test protocol or its versioned local state.
- No Jev, MDM, configuration management, Nix workers, package deployment, or shell
  agents. No automatic transport fallback or legacy compatibility implementation.
- Run focused lab tests, real peer/socket checks, `make check`, and
  `make cross-build`. Do not call interrupted or partial work complete.
- Commit only scoped source, docs, checksums, and safe evidence with a Conventional
  Commit. Do not push, create a PR, merge, post comments, or send messages.

## Implementation choice

The lab initializes private network state explicitly, then loads it without
regeneration. `StartServer` installs the configured network-key allowlist before
starting Tailcat. `NewClient` verifies the expected server key and explicit local
bootstrap before any network IO. Both functions return real upstream objects,
so listener, peer-identity, status, and dial compatibility are exercised directly.

A nested module was selected over a root dependency because the experiment pulls
in userspace WireGuard, gVisor, and Tailscale internals. Root controller/endpoint
imports and cross-builds must not accidentally enable or depend on this lab.
The committed `run-proof.sh` reruns the real experiment and can count successful
UDP socket syscalls without retaining raw traces.

## Completion ledger

| Required result | Source / real boundary | Check | State |
| --- | --- | --- | --- |
| Correct isolated base | local branch from fetched `origin/main` `fcf1329` | Git branch/log inspection before edits | proved |
| Dependency pin, license, APIs | nested `go.mod`, `go.sum`, license, upstream code links | compilation and `go mod verify` | proved |
| Authenticated direct application traffic | two separate OS processes, Tailcat WireGuard engines | new TCP tunnel connection, 8 challenge-response round trips after relay shutdown | proved |
| Persisted identity and reconnect | processes exit and restart, same private files | stable two public fingerprints and address digest; measured times | proved |
| Network admission | real discovery/handshake and application listener | unknown key and wrong PSK rejected, zero application accepts | proved |
| Missing/corrupt state | actual private files through start/load paths | explicit error, no regeneration, exclusive provisioning | proved |
| Host UDP sockets | actual peer syscalls | optional `strace` aggregate, 132 sends / 91 receives in recorded run | proved |
| Application remains independent | production constructors and root module | root vet/race/format/Python checks and cross-build | proved |

## Surface ledger

| Surface | Applies? | Result / evidence |
| --- | --- | --- |
| Lab server start/listen/peer binding | applies | pinned APIs, configured single admitted network key, bounded listener |
| Lab client bootstrap/dial | applies | explicit server pin and nonzero PSK; no public map default |
| State initialization/load/restart | applies | separate keys, 0600 files in trusted private directory, fail-closed tests |
| Direct path in both directions | applies | client discovery endpoint and server `CurAddr`, relay-off new application dial |
| Unknown key / wrong PSK | applies | separate discovery and WireGuard failure experiments, no app accept |
| Shutdown / restart | applies | both engines exit in OS processes, relay closes, fresh processes reload state |
| Production `mesh` constructors | applies as retained guard | unchanged explicit errors, root regression test |
| Go build and dependency isolation | applies | nested module plus explicit Make targets; root cross-build unaffected |
| Docs and source references | applies | lab README, license, safe measured evidence, networking README |
| Application evidence wire contracts | does not apply | separate #75 signatures, no consumer implementation or schema change |
| Enrollment / controller / durable DB | does not apply | outside lab; manual out-of-band admission only |
| Live revocation / one-sided restart | not qualified | `DisconnectClient` used only to clean up denial experiments |
| WAN / NAT / deployed DERP / blocked UDP | not qualified | one Linux host; #84 and production #25 remain open |
| Windows/macOS runtime / reboot | not qualified | root binary cross-build is the available check, no lab runtime claim |
| Chain / real telemetry / patent claims | does not apply | no chain payload or production capability created |

## Validation and handoff

Base and branch: `origin/main` at `fcf1329`,
`lab/issue-20-tailcat-direct`. The first default Python check lacked the declared
RFC3339 validation package. Installing the pinned repository test requirements
in the worktree's ignored `.venv` resolved it without source changes.

Passed: nested vet, race tests, checksum verification, direct process proof,
optional UDP syscall proof, root Go vet/race/format checks, all 22 Python tests,
and endpoint Windows amd64/Darwin arm64 cross-builds. The helper-only test entry
point skips in the parent process and runs explicitly in each child process.

The [failed-PSK recovery observation](README.md#limits-and-observed-recovery-edge-case)
remains unresolved and is documented for the production task. No remaining
blocker prevents review of the bounded lab. No push or PR action is authorized
for this implementation subagent. The parent owns review and PR creation.
