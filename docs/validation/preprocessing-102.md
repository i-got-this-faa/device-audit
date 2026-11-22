# Feature preprocessing pipelines, ML07 #102, 23 November 2026

This change adds the training and endpoint pipelines that build the
[`hdd-smart-7d.v1`](../../packages/contracts/features-v1.md) input window and call
the frozen references. No model, SMART collector or controller pipeline was added.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Convert real nullable telemetry into CT03 ordered features with the frozen rules | `health.Preprocess` over `ReadingFromTelemetry` of the shared telemetry v2 payloads, whose nullable metrics include nulls with reasons, gives an `incomplete` vector with `no_observation` on all six ordered features. `endpoint-agent --features` ran over the same payloads with the built binary. Telemetry v2 carries no SMART counter, so no known value is possible today. |
| Training and endpoint paths match golden vectors within tolerance | Nine shared cases in `pipeline-cases.json`. `TestPreprocessMatchesSharedPipelineCases` (Go, timestamped readings at midday) and `test_training_path_matches_the_shared_cases` (Python, daily rows) both match the hand-written expected vectors within `1e-12 + 1e-12·abs(expected)`. |
| Sparse windows, counter resets and missing sensors yield declared missing outcomes | Cases `missing day row is sparse`, `null on the first day`, `missing sensor column`, `power-on hours reset`, `pending sectors remapped` and `no rows`. A missing counter is `no_observation` or `incomplete_history`, never filled; `ModelInput` and `model_input` refuse every incomplete vector. |
| No future-data leakage | Cases `future rows are never evidence` and `rows before the window are ignored`. `TestPreprocessNeverReadsAfterAsOf` places a reading 0.3 s after `as_of` inside the same whole second. `test_values_after_the_anchor_never_change_the_vector` changes every SMART value of the label horizon in the ML01 stream. |

## Fault checks

Each Go check was mutated once; the file was restored after each run.

- Keeping the earliest instead of the latest reading of a day failed `TestPreprocessKeepsTheLatestNonNullReadingOfEachDay`.
- Dropping the `as_of` upper bound failed `TestPreprocessMatchesSharedPipelineCases` (the future-rows case).
- Dropping the window lower bound failed the same test (the old-rows case).

## Commands and results

Go 1.27.3 linux/amd64 and Python 3.12.15 from `nix develop`:

```sh
python3 packages/contracts/fixtures/features/generate_pipeline.py
make check
make contract-check
CGO_ENABLED=0 make cross-build
```

- `make check`: `go vet`, `go test -race ./...`, 66 Python tests (10 new), controller fake scenarios and `go fmt`. Passed.
- `make contract-check`: 342 golden vectors, 79 wire cases and 29 reader versions, unchanged. Passed. The pipeline cases are not a conformance suite.
- `CGO_ENABLED=0 make cross-build`: Windows amd64 and Darwin arm64 built. The Nix shell sets `CGO_ENABLED=1`, which breaks the Darwin build as recorded in [features-32.md](features-32.md).
- `endpoint-agent --features --as-of 2026-10-13T06:00:00Z` over the three valid shared telemetry payloads printed an `incomplete` vector for 2026-10-07..2026-10-13. `--features` without `--as-of`, and `--as-of` with `--fixture`, exited 1.
- `git diff --check`: clean.

`make database-check` was not run; no database code changed.

## Not tested

- No real SMART counter exists on any endpoint, so no known endpoint vector has been produced. The six values a model would read were only produced from the shared fixture cases.
- The Backblaze archive was not downloaded or streamed. The ML01 stream ran on artificial frames in the archive's column layout, so the claim that a vector is `complete` exactly when ML01 counts complete history rests on the committed null counts in `partitions.json` and the stream tests, not on the archive.
- `--features` was run on Linux over fixture telemetry, not over a live Windows `--sample` stream or the service's local evidence file.
- No controller preprocessing (#105) or inference ran.
- Real-device and Windows behavior: no collector code changed.
