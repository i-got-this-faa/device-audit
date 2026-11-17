# Bounded configurable telemetry sampling, TEL08 #94

Status on 17 November 2026: **the per-source scheduler, configuration
validation, isolation tests, the explicit fixture switch and three 10-minute
runs on the HP Victus target are recorded. Two runs met the declared budget; the
first exceeded its RSS limit once with an unattributed transient.** The budget
is a declared measurement ceiling, not an approved production budget.

## What was built

`packages/telemetry/sampling.go` adds `SamplingConfig` and `Scheduler`.

- **Configuration.** `device-audit.sampling-config.v1` is strict JSON (unknown
  fields, trailing data and documents over 16 KiB are rejected). Each listed
  source has an `interval` of 5–300 s and a `deadline` that is positive, at most
  30 s and at most its interval. `emit_interval` is 5–300 s. The budget declares
  `max_cpu_percent_one_core` (above 0, at most 100) and `max_rss_bytes`
  (4 MiB – 1 GiB). Unknown or duplicated sources are rejected and unlisted
  sources are not sampled.
- **Isolation.** Every source runs on its own goroutine at its own
  start-to-start interval without catch-up. Each read keeps the #92 per-source
  deadline and panic isolation. A provider still blocked from its previous read
  is not started again; that tick is `collection_error` / `provider_busy`. A hung
  provider therefore holds at most one goroutine and cannot delay other sources.
- **Snapshots.** Every `emit_interval` the latest result of each source forms one
  sample. No result yet is `collection_error` / `not_yet_sampled`; a result older
  than its interval plus deadline plus 1 s is `collection_error` / `stale_result`.
  Provider missing reasons pass through unchanged.
- **Budget.** The run measures this process's CPU over the whole run as percent
  of one core and samples RSS after every source read and emit. The report
  records the peak, what ran just before it and when, and whether each limit
  held. Process CPU excludes child processes such as `nvidia-smi`.
- **Default.** Every source at 15 s (the TEL04 fast candidate), the NVIDIA tool
  at 60 s because it starts a process, emits every 60 s, declared budget 2 % of
  one core and 64 MiB.

`endpoint-agent --sample --device-id <id> [--sampling-config f]
[--sampling-duration d] [--sampling-report f]` prints one validated
`source = endpoint` v2 payload per emit and writes a
`device-audit.sampling-report.v1` report to a new file. It exits 1 when the
budget is exceeded.

### Fixture mode

The agent no longer sends synthetic telemetry by default. With no mode it exits
1 and names `--fixture`. `--fixture` sends the loopback fixture and prints
`provenance=fixture: sending synthetic telemetry, not a device measurement` on
standard error; the payload keeps `source = fixture`. `tools/demo.py` checks
both the refusal and the provenance line.

## Tests

`packages/telemetry/sampling_test.go`:

- `TestSchedulerSlowProviderDoesNotStallOthers`: a healthy source at 10 ms,
  a provider that ignores its context and never returns, and a denied provider.
  The healthy source keeps its cadence, the hung provider is entered exactly
  once, its later ticks are `provider_busy`, and every snapshot keeps CPU
  known, memory `collection_error` and disk `permission_denied`.
- `TestSchedulerSnapshotMarksMissingAndStaleResults`, `TestEvaluateBudget`,
  `TestUsageMeterAttributesPeak`, `TestSchedulerRejectsUnboundSource`.
- `TestSamplingConfigValidation` and `TestParseSamplingConfigIsStrict`: every
  bound and strict decoding.

`apps/endpoint-agent/sampling_test.go` covers config loading, the report not
overwriting a file and duration bounds. On Windows `TestRunSamplingRealWindows`
runs a 6-second real schedule and validates the emitted v2 payload.

## HP Victus runs, 17 November 2026

Same machine as [telemetry-91.md](telemetry-91.md#hp-victus-run-17-november-2026):
interactive standard user, not elevated, Go 1.27.4. Each run used the built-in
default configuration for 10 minutes:

```powershell
endpoint-agent --sample --device-id <id> --sampling-duration 10m --sampling-report report.json
```

| Run | Start (UTC) | CPU, % of one core | Peak RSS | Within budget | Report |
| --- | --- | ---: | ---: | --- | --- |
| 1 | 17:54:00 | 0.167 | 85,123,072 B | **no** (RSS) | [run1](sampling-94-victus-run1.json) |
| 2 | 18:15:30 | 0.036 | 28,741,632 B | yes | [run2](sampling-94-victus-run2.json) |
| 3 | 18:26:36 | 0.031 | 27,742,208 B | yes | [run3](sampling-94-victus-run3.json) |

In every run each 15-second source was read 40 times and `nvidia-smi` 10 times,
with no busy skips and no overruns, and 9 snapshots were emitted. All readings
were known except the down second network interface, which stayed
`sensor_unavailable` / `interface_down` (80 null readings per run). The slowest
query was the GPU engine PDH read at about 444 ms.

Run 1 exceeded the declared 64 MiB (67,108,864 B) RSS limit, and the agent
exited 1 as designed. It was not reproduced:

- All sources at 5 s for 5 minutes, sampled externally every 2 s, plateaued at
  27.3 MB working set and about 60 MB private bytes.
- Run 2 repeated run 1 with `GODEBUG=gctrace=1` and a 0.5 s external
  working-set monitor. The Go heap never exceeded 3 MB before a collection and
  the working set peaked at 27.3 MB.
- Each provider alone peaked at 16–22 MB. The GPU engine counter had 546
  instances, about 0.08 MB of PDH buffer.

The run-1 excess was therefore outside the Go heap and is not attributed.
Run 3 added the `rss_peak_after` field, which named a `disk` read 360 s into the
run as the 27.7 MB peak. A future overrun report names its source.

## Not done

- **Run-1 RSS transient.** Its cause is unknown. Two of three runs met the
  budget; a single 10-minute run is not proof that the 64 MiB ceiling always
  holds.
- **Child processes.** `nvidia-smi` CPU and memory are not in the measured
  process cost.
- **Service token.** These runs used the interactive user, not LocalService.
- **Error evidence.** `--collect-errors` keeps its own invocation and is not on
  the scheduler.
- **Delivery.** Payloads are printed; signing, spooling and submission remain
  separate steps.
