# Console device fixtures, WEB06 #99

Local validation on 30 October 2026 covers
[issue #99](https://github.com/i-got-this-faa/device-audit/issues/99).
The renderer and browser share the named catalogue in
[`apps/web-console/fixtures/devices.json`](../../apps/web-console/fixtures/devices.json).
The catalogue extends the console examples without changing any shared wire
contract. Its replay device preserves TST02's telemetry payload.

## Reproduction

From the repository root:

```sh
npm ci --prefix apps/web-console --ignore-scripts
nix develop --command make check cross-build
nix develop --command env BROWSER_PATH=/run/current-system/sw/bin/chromium make browser-check
```

Outside Nix, use the Go version required by `go.mod`, Python schema-test
dependencies and an absolute `BROWSER_PATH`, then run the same Make targets.
This run used Go 1.27.3, Python 3.12.15, Playwright Core 1.64.1 and system
Chromium 155.0.8059.84 on Linux. `go.mod` declares Go 1.27.1 as the minimum.

## Observed results

| Boundary | Evidence |
| --- | --- |
| Static and component checks | `make check` passed vet, race-enabled Go tests, 32 Python tests, deterministic fake scenarios and formatting. |
| Cross-compilation | `make cross-build` produced Windows amd64 and Darwin arm64 endpoint binaries. These are build checks, not device execution. |
| Fixture compatibility | Go validates telemetry v2 fixture payloads and compares the replay-device payload with the shared TST02 bundle. No missing value is filled with zero. |
| Authenticated browser path | Actual TLS HTTP service and OIDC/PKCE callback with a synthetic issuer and in-memory test sessions. Anonymous list/detail navigation, viewer reads, admin navigation, expired sessions, logout, history and auth-store outage passed. |
| List and detail states | Named live, offline, unknown, empty-component, loading, error and empty-list scenarios passed at 1280, 640 and 320 CSS pixels. Detail links, compatible scenario selection, Back navigation and recovery links passed. Invalid devices/scenarios and repeated fixture selection return 404. |
| Missing data | Browser assertions cover zero CPU utilization, all four missing-reason explanations, omitted metrics, unknown inventory, empty inventory, unknown component model and historical offline measurements. |
| Fixture provenance | Each tested state retains the synthetic-data banner and fixed reference clock. Every rendered list row retains a fixture badge. Browser checks confirm that the compact fixture label stays in the viewport when scrolling to network latency. |
| Layout and access | Horizontal-overflow checks passed at all three widths. Screenshots were inspected for desktop detail, 320px detail and 320px error. Keyboard skip link, visible focus and browsing/recovery/logout without JavaScript passed. |

The 640 CSS-pixel run checks reflow equivalent to a 1280-pixel layout at 200%
zoom. Browser-native zoom controls were not exercised. Screenshots are generated
under `artifacts/console/`, including `device-detail-1280.png`,
`device-detail-320.png` and `devices-error-320.png`. The existing CI browser job
runs the extended suite and uploads that directory; remote CI was not observed
in this local run.

## Limits

These are synthetic console examples, not production fleet reads, endpoint
measurements, device-signature verification, mesh admission, forecasts or health
assessments. Loading and error scenarios are deterministic UI previews rather
than network fault injection. The replay comparison establishes payload reuse,
not fresh or truthful telemetry. PostgreSQL integration and physical endpoint
execution were not needed or run for this change.

The current and previous Chrome, Edge and Firefox matrix, native browser zoom,
a real IdP, a deployed HTTPS proxy and assistive-technology qualification remain
untested. A reviewed and merged PR remains required by the issue's definition
of done. This record does not close the issue or establish release qualification.
