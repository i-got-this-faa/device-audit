# NET03 #54 relay restart and long-partition recovery, 22 November 2026

Record for [issue #54](https://github.com/i-got-this-faa/device-audit/issues/54).

**Result: same-host recovery is proved; the real-machine item stays open.**
Only one physical Windows endpoint exists (see
[integration-gate-31.md](integration-gate-31.md#open-gates)), and no deployed
controller or public relay host exists (#73). No LAN, WAN or second-machine run
was made. Everything below ran on one Linux host.

## Acceptance

| Acceptance item | Status | Basis |
| --- | --- | --- |
| Real target machines pass direct LAN/WAN and forced DERP traffic with recorded path and reconnect timings | **Not met** | No second machine, no deployed relay or controller. Same-host direct and forced-DERP path and reconnect timings are [recorded below](#measured-run) as a reference, not as a target result. |
| Controller/relay restart and a long partition recover within documented limits while the spool drains once | Met on one Linux host | `TestRelayRestartAndPartitionRecovery`, [limits](#documented-limits) |
| Unavailable relay/direct paths fail visibly rather than bypassing admission | Met on one Linux host | Same test: no row is stored while a path is down, `self-hosted DERP relay unavailable` is logged within the limit, and a key removed from relay admission gets no delivery until it is restored |

## What the test runs

`make recovery-proof` (needs `TEST_DATABASE_URL`) runs
`TestRelayRestartAndPartitionRecovery` in `apps/endpoint-agent` twice:

- **direct**: Tailcat may use UDP between the processes.
- **derp**: every process has `TS_DEBUG_ALWAYS_USE_DERP=1`, so each packet
  crosses the relay. This is the upstream debug knob, not a UDP-blocked
  network. `make relay-fallback-proof` covers real blocked UDP separately but
  without restarts.

Each mode uses separate processes:

- the production `networking/relay` package, with a test CA trusted only
  through `SSL_CERT_FILE`, a persisted relay key and an admission file;
- a controller process with the controller binary's mesh startup (relay
  preflight reported but not fatal, `mesh.NewServer`, `WriteAddress`,
  `controller.MeshHTTPServer`) on a migrated PostgreSQL database. It is a test
  entry, not the `controller` binary, which also needs OIDC configuration;
- the endpoint service pipeline (`runServicePipeline`) with fixture CPU and
  memory readers that sample every 5 s, the real spool and delivery worker,
  and an identity enrolled through the TLS enrollment handlers.

The controller is stopped with SIGKILL and restarted with the same state. The
relay is closed and restarted on the same port with the same key.

Phases, in order:

1. Steady delivery. In derp mode the relay's non-Disco packet counter must rise.
2. Relay restart. In direct mode an established session must keep storing
   evidence with the relay down. In derp mode nothing may be stored during a
   15 s outage, and delivery must resume after the relay returns.
3. Controller crash and restart with the relay up.
4. Long partition: relay and controller both down for
   `RECOVERY_PARTITION` (default 90 s, longer than the 1-minute retry cap).
   Nothing may be stored. The service log must report the unavailable relay
   within the limit and must not stop delivery. The controller is then
   restarted while the relay is still down. It must report the relay
   unavailable and keep running, and nothing may be stored for 15 s. Then the
   relay returns and the whole backlog must be stored within the limit.
5. derp mode only: the endpoint's network key is removed from relay admission
   and the relay restarted. Nothing may be stored for 40 s, and the failure
   must be logged. The key is restored without a relay restart (admission is
   re-read on each connection) and delivery must resume.
6. Drain once. Wait for an empty spool, kill the service, then require
   contiguous stored sequences (`count = max - min + 1`), each verified against
   the device signing key, and a retired spool head matching the highest stored
   sequence.

## Documented limits

| Limit | Value | Basis |
| --- | --- | --- |
| Lost path reported as `self-hosted DERP relay unavailable` | 40 s | 15 s HTTP timeout on the in-flight request + 5 s session teardown bound + retry delay + 10 s relay preflight |
| Restored path to the whole backlog stored | 90 s | 1-minute retry cap + 30 s for preflight, request and Tailcat session setup |

A short relay outage need not log a retry. A request already in flight
can finish after Tailcat reconnects within its 15 s timeout.

## Defect found and fixed

In derp mode, after the controller was killed, delivery stopped for good with
nothing logged. A goroutine dump showed the delivery worker blocked in
`meshEvidenceSender.send` → `mesh.(*client).Close` → wireguard-go
`Device.Close` (`closeBindLocked`). The sender drops a failed session before
retrying, so one stuck teardown stopped all delivery.
[relay-fallback-88.md](relay-fallback-88.md#observed-limitation) had noted
this upstream hang under the debug knob only in test children.

`mesh.Client.Close` now waits at most 5 s. A teardown that does not return in
time keeps running in the background, and `Close` returns
`mesh.ErrCloseTimeout` (`TestBoundedCloseReturnsWhenTeardownHangs`). A
timed-out session is not reused. Its goroutines may stay alive until the
process exits. Neither the cause of the upstream hang nor whether it happens
with real blocked UDP after a peer crash is established. Controller-side
`Close` is unchanged.

## Measured run

22 November 2026, from `b578bde` plus this change, Linux amd64 (CachyOS kernel
7.3), Go 1.27.4, disposable PostgreSQL 17.12 cluster on loopback.
`make recovery-proof` with the default 90 s partition, without `-race`:

```text
direct steady: first record stored 5.129s after service start; relay non-disco packets +6
direct relay restart: established direct session stored a record 4.999s into the relay outage
direct relay restart: relay back after 9.964s
direct controller restart: process killed, restarted in 81ms, next record stored 25.51s after restart
direct long partition: relay unavailable first logged 15.82s into the partition; 7 retries logged in 1m30s
direct long partition: 1m30s with relay and controller down, then 15s with only the relay down; 22 queued records stored 49.648s after relay restart (limit 1m30s)
direct long partition: total outage 2m35s
direct drain once: sequences 2..41 stored once each (40 rows), spool empty, no delivery stop
derp steady: first record stored 5.128s after service start; relay non-disco packets +15
derp relay restart: no evidence stored during 15s outage (0 logged retries); next record stored 2.815s after relay restart
derp controller restart: process killed, restarted in 30ms, next record stored 27.843s after restart
derp long partition: relay unavailable first logged 25.071s into the partition; 7 retries logged in 1m30s
derp long partition: 1m30s with relay and controller down, then 15s with only the relay down; 21 queued records stored 27.234s after relay restart (limit 1m30s)
derp long partition: total outage 2m12s
derp relay admission: endpoint key removed, nothing stored for 40s, relay unavailable logged after 22.568s; key restored without relay restart, next record stored 10.052s later
derp drain once: sequences 2..48 stored once each (47 rows), spool empty, no delivery stop
--- PASS: TestRelayRestartAndPartitionRecovery (439.07s)
    --- PASS: TestRelayRestartAndPartitionRecovery/direct (200.70s)
    --- PASS: TestRelayRestartAndPartitionRecovery/derp (238.37s)
```

The "direct" path is inferred, not read from Tailcat. Evidence kept
reaching storage while the relay was down. Before the fix, two derp-mode runs
failed in phase 3 as described above. An earlier run with a 45 s
partition also passed both modes after the fix.

Also passed on the same tree: `make check`, `make cross-build`,
`make database-check`, `make relay-fallback-proof` (14 UDP packets dropped in the
namespace) and the CI path-filter tests. CI runs `make recovery-proof` in the
`database` job.

## Not covered

- Two machines, LAN, WAN, NAT, the selected Windows laptop and the installed
  LocalService service. The service pipeline ran in a Linux test process.
- Restarts under real blocked UDP. The derp mode uses the debug knob.
- A partition longer than the measured 90 s (plus 15 s relay-only). The retry
  delay is capped at 1 minute, so the bound should not grow, but longer runs
  and spool-cap pressure during a partition were not measured (#140).
- Power loss, host reboot, PostgreSQL restart during the partition, and relay
  certificate renewal.
- The `controller` binary itself. Its mesh startup was reproduced in a test
  entry.

No production, patent, prediction or privacy claim follows.
