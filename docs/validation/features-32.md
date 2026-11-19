# Frozen feature version, CT03 #32, 18 November 2026

This change freezes [`hdd-smart-7d.v1`](../../packages/contracts/features-v1.md)
and adds Go and Python reference preprocessing with shared vectors. No model,
endpoint collector, controller pipeline or training run was added.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Feature ordering, windows, normalization, noise filter and null handling encoded from collectors and dataset decisions | `features-v1.md`, `features-v1.schema.json`, `FeatureWindowV1.Features()` and `features.compute`. Counter selection is tested against ML01's committed null counts. The collector mapping records that no endpoint collector reads SMART. |
| Cross-language fixtures reject incompatible feature versions | `hdd-smart-7d.v2` windows and vectors give `unsupported_feature_version` in Go (`ErrUnsupportedFeatureVersion`) and Python (`UnsupportedFeatureVersion`). Reordered features, a missing feature and an excluded counter are rejected. |
| Equal preprocessing results within recorded tolerance | All 10 valid windows produce the expected vector in both languages within `1e-12 + 1e-12·abs(expected)`. The expected values come from hand-written day values, not from either implementation. |
| Other owner approves before consumers merge | **Open.** The PR is the review boundary for #101, #102 and #105. |

## Fault checks

Each reference was mutated once to confirm the vectors detect a real defect:

- Go: keeping the earliest instead of the latest reading of a day failed
  `latest reading of each UTC day wins in any input order`.
- Python: dropping the `as_of` upper bound failed
  `samples after as_of are never evidence`.

Both mutations were reverted before the runs below.

## Commands and results

Go 1.27.3 linux/amd64 and Python 3.12.15 from `nix develop`:

```sh
python3 packages/contracts/fixtures/features/generate.py
python3 tools/generate_contract_wire_vectors.py
make check
make contract-check
CGO_ENABLED=0 make cross-build
git diff --check
```

- `make check`: `go vet`, `go test -race ./...`, 55 Python tests including
  the 4 new feature tests, controller fake scenarios and `go fmt`. Passed.
- `make contract-check`: 331 golden vectors (30 from this change), 79 wire cases (4 from this change)
  and 29 reader versions (2 from this change). Passed.
- `make cross-build` built Windows amd64, then failed the Darwin arm64 build in
  `runtime/cgo` (`gcc: unrecognized option '-arch'`). The Nix shell sets
  `CGO_ENABLED=1` with a Linux gcc. With `CGO_ENABLED=0` both builds passed.
  This change touches no endpoint code.
- `git diff --check`: clean.

`make database-check` was not run; no database code changed.

## Not tested

- No real telemetry passed through the preprocessing. No collector produces
  SMART counters, so the real endpoint window is empty and the vector is
  `incomplete` by construction.
- The Backblaze archive was not downloaded. The Backblaze-to-sample mapping is
  specified and its equivalence with ML01 complete history is argued from the
  committed null counts, not run over the archive. #102 runs it.
- Go's `math.Log1p` and Python's `math.log1p` were compared only on the fixture
  values, not over the whole counter range.
