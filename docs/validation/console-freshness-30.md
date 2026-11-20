# Console device freshness, WEB02 #30

Local validation on 20 November 2026 covers
[issue #30](https://github.com/i-got-this-faa/device-audit/issues/30).
The console reads enrolled devices from the durable repository and classifies
freshness from each latest sample's observed time. See the
[console guide](../../apps/web-console/README.md#enrolled-devices-and-freshness)
and the [decision](../decisions.md#enrolled-device-freshness-in-the-console-web02-30).

## Reproduction

From the repository root, with a disposable PostgreSQL 17 cluster:

```sh
npm ci --prefix apps/web-console --ignore-scripts
nix develop --command make check
nix develop --command env CGO_ENABLED=0 make cross-build
nix develop --command env TEST_DATABASE_URL=postgres://postgres@127.0.0.1:55432/device_audit_test?sslmode=disable make database-check
nix develop --command env BROWSER_PATH=/run/current-system/sw/bin/chromium make browser-check
```

This run used Go 1.27.3, PostgreSQL 17.11, Playwright Core 1.64.1 and system
Chromium 156.0.8078.79 on Linux. In this Nix shell `CGO_ENABLED=1` makes the
Darwin cross-build fail with `gcc: unrecognized command-line option '-arch'`.
Unchanged `main` fails the same way. With `CGO_ENABLED=0`, both targets build.

## Observed results

| Boundary | Evidence |
| --- | --- |
| Two devices through signed evidence | `TestConsoleFreshnessFromSignedEvidence` (PostgreSQL) enrolls two devices and commits CT04-signed telemetry through `AcceptEvidence`. Both show No sample, then Current. One device stops: at exactly 3 minutes only it is Stale; at 15 minutes only it is Offline. The other device stays Current. The JSON device state API returns the same sequences and observed times. |
| Request failure | A repository on a closed connection makes list and detail return 503 with no device rows, freshness, sensor values or fixture data. Unknown device returns 404 and a malformed cursor returns 400. |
| Units and missing data | The offline detail page keeps units and labels values historical. Unit tests cover a measured zero, a null metric with its missing reason, an omitted metric and every freshness boundary. A recent receipt does not refresh an old observation. |
| Fixture provenance | A signed sample with `source: fixture` carries a `Fixture source` badge. The enrolled view has no fixture catalogue banner. `?fixture=` still opens the labelled catalogue. A missing deployment shows a not-configured state, not fixtures. |
| Browser | Chromium, against a test-only in-memory reader, observes one device move from Current to Stale to Offline while the others stay Current. It checks units, missing reasons and the fixture-source badge, then shows a 503 outage page with no values. No horizontal overflow at 1280 and 320 CSS pixels. Navigation without JavaScript reaches enrolled detail. The existing fixture, auth and logout checks still pass. |
| Regression | `make check` and `make database-check` passed. |

Screenshots: `artifacts/console/enrolled-offline-detail-1280.png`,
`enrolled-offline-detail-320.png`, `enrolled-outage-1280.png` and
`devices-desktop.png`.

## Limits

Two physical Windows endpoints were not run against a deployed controller. The
two-device evidence is the real PostgreSQL repository with signed envelopes and
a controlled clock. Stopping a real endpoint service is not exercised here. The
browser freshness path uses a test reader, not PostgreSQL. The thresholds are
provisional and do not account for per-device cadence. Remote CI, a real IdP
and the multi-browser matrix were not observed. The issue still requires a
reviewed and merged PR.
