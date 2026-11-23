# Controller feature extraction, ML09 #105, 23 November 2026

This change adds `BuildDeviceFeatures`, which builds the
[`hdd-smart-7d.v1`](../../packages/contracts/features-v1.md) vector from one
device's persisted evidence. It calls the same `health.Preprocess` as the endpoint,
so it adds no rule and no fitted state. No endpoint serves it, and no model ran.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Controller turns persisted nullable evidence into CT03 features with versioned window provenance | `TestBuildDeviceFeaturesMatchesTheEndpointOverPersistedEvidence` writes samples to `device_evidence` in PostgreSQL and reads them back through `PostgresRepository.FeatureEvidence`. The vector names `hdd-smart-7d.v1`, `window_start`, `window_end` and `as_of`. The result adds the deployment, device, samples read and highest sequence read. Every metric in the stored payloads is nullable and one carries `sensor_unavailable`. |
| Controller matches endpoint and training preprocessing | Two tests. `TestBuildDeviceFeaturesMatchesTheSharedPipelineCases` runs the ten shared pipeline cases through the controller's window with known counters, each row's sequence running against its collection order, and matches the hand-written vectors within `1e-12 + 1e-12·abs(expected)`. The Go endpoint and the Python training path match the same cases ([preprocessing-102.md](preprocessing-102.md)). `TestBuildDeviceFeaturesMatchesTheEndpointOverPersistedEvidence` reads real PostgreSQL rows and equals `health.Preprocess` over the same payloads (`reflect.DeepEqual`). The known-value run uses a test-supplied reading function: telemetry v2 has no SMART counter, so no stored payload can carry one. |
| Out-of-order evidence cannot add future evidence | The test inserts sequence 4 with the earliest `collected_at`, then samples 1 µs and 1 h after `as_of`, one 1 s before the window and one of another device. Only the three in-window samples of the device are read. `TestBuildDeviceFeaturesAsksOnlyForTheSevenDayWindowEndingAtAsOf` checks the exact history window requested, for an `as_of` given in a non-UTC zone with a sub-microsecond part. |
| Incomplete windows cannot introduce fabricated values | Windows with no samples and with a sample on every day both give `incomplete` with every value null and `no_observation`. `health.ModelInput` refuses both. A failed page or a corrupt cursor returns an error and no vector (`TestBuildDeviceFeaturesFailsWithoutAPartialVector`). |

## Fault checks

Each mutation was applied to `features.go` and reverted. The tests failed each time.

- The window end excluded the instant `as_of`.
- The SQL dropped its lower bound (fails the persisted-evidence test).
- The window end moved one hour past `as_of`.
- The window start moved to eight days.

## Cost

A throwaway test seeded `device_evidence` with 40,320 rows, one every 15 s, ending at
`as_of`, then timed `BuildDeviceFeatures` three times on an 8-CPU Intel Core 5 210H
with a local PostgreSQL. 37,441 rows fall inside the window.

| Reader | Time per call | Allocated |
| --- | --- | --- |
| First version, paged `TelemetryHistory` (375 pages) | 6.4 s, 6.7 s, 8.2 s | 450 MB |
| `FeatureEvidence`, one query, no payload decode | 0.22 s, 0.24 s, 0.27 s | 11 MB |

Each page of the first version re-checked the device and decoded every payload. The test was
not kept; the numbers are from one machine and one local database, not a service budget.

## Commands and results

Go 1.27.3 linux/amd64 and Python 3.12.15 from `nix develop`. The database was a
fresh local PostgreSQL cluster.

```sh
make check
CGO_ENABLED=0 make cross-build
TEST_DATABASE_URL=... make database-check
make contract-check
```

- `make check`: `go vet`, `go test -race ./...`, 70 Python tests, controller fake scenarios and `go fmt`. Passed.
- `CGO_ENABLED=0 make cross-build`: Windows amd64 and Darwin arm64 built. The Nix shell sets `CGO_ENABLED=1`, which breaks the Darwin build as recorded in [features-32.md](features-32.md).
- `make database-check`: `infra/database`, `apps/controller`, `apps/endpoint-agent`, `internal/controller` and `internal/controller/auth` passed against the cluster.
- `make contract-check`: 367 golden vectors, 81 wire cases and 30 reader versions. Passed. No contract file changed.

## Not tested

- No stored sample has carried a known counter. The known-value run replaces the sample-to-reading step. A SMART collector, its Windows permission model and the NVMe mapping have no issue, so every controller vector is `incomplete` today.
- A sample that arrives after a vector was computed enters a vector computed later, because the window uses `collected_at` and not `received_at`. Rebuilding an old vector from current storage is not reproducible; see the [decision](../decisions.md#controller-feature-extraction-ml09-105-23-november-2026).
- Historical type, count and recurrence comparisons and health thresholds are #106.
- No route serves the result and no wire contract carries the provenance.
- The cross-owner approval of the shared vectors recorded for #32 is still open.
