# Model artifact manifest, CT10 #101, 23 November 2026

This change adds the [model manifest contract](../../packages/contracts/model-manifest-v1.md)
with Go and Python references and shared signed vectors. No model, trainer,
runtime or activation service was added.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Specify artifact digest/signature, architecture/runtime version, feature version and inference/training compatibility fields | `model-manifest-v1.md`, `model-manifest-v1.schema.json`, `ModelManifestV1` and `manifest.py`. The signature covers every field; `TestModelManifestSignatureCoversEveryField` changes each one. |
| Manifest fixtures reject mismatched runtime, feature ordering and digest | `runtime_name_mismatch`, `runtime_version_mismatch`, `feature_order_swapped`, `feature_order_reversed`, `feature_missing`, `feature_extra`, `artifact_digest_mismatch` and `empty_artifact_digest_mismatch`. Go and Python assert the exact code for each. |
| Unknown or unsupported model versions fail explicitly before activation | `unsupported_manifest_version`, `unsupported_feature_version` and `unsupported_architecture` return their own codes. A rejected manifest changes no state. |

## Fault checks

Each Go check was mutated once to confirm the vectors detect the defect. The
file was restored after each run.

- Digest comparison always passing failed `artifact_digest_mismatch` and `empty_artifact_digest_mismatch`.
- Skipping the feature order check failed the four `feature_*` vectors.
- Ignoring the runtime version failed `runtime_version_mismatch`.
- Dropping the purposes from the signed bytes failed every canonical-bytes and signature vector.

## Commands and results

Go 1.27.3 linux/amd64 and Python 3.12.15 from `nix develop`:

```sh
go run packages/contracts/fixtures/models/generate.go
python3 tools/generate_contract_wire_vectors.py
make contract-check
make check
CGO_ENABLED=0 make cross-build
```

- `make check`: `go vet`, `go test -race ./...`, 60 Python tests (4 new), controller fake scenarios and `go fmt`. Passed.
- `make contract-check`: 367 golden vectors (25 from this change), 81 wire cases (2 from this change) and 30 reader versions (1 from this change). Passed.
- `CGO_ENABLED=0 make cross-build`: Windows amd64 and Darwin arm64 built. The Nix shell sets `CGO_ENABLED=1`, which breaks the Darwin build as recorded in [features-32.md](features-32.md).
- `git diff --check`: clean.

`make database-check` was not run; no database code changed.

## Not tested

- No real model artifact exists. The fixture artifact is synthetic bytes.
- Python does not verify Ed25519 signatures; only Go does.
- No activation service, active-manifest store, rollback or revocation exists, so
  an older signed manifest is not refused as stale.
- No federated round was checked against a manifest. The round fields
  (`base_model_version`, `base_model_sha256`, `feature_version`,
  `parameter_count`) are the same values by design, but no consumer joins them yet.
- Real-device and Windows behavior: no endpoint code changed.
