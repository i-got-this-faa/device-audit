# Bespoke prediction and local training

The user selected a custom model, not Jev. Python/PyTorch was proposed and was
not adopted. This package has no ML framework dependency. ML02 fits one
standard-library logistic baseline; a larger architecture remains open.

`interfaces.py` defines prediction and local-training boundaries.
`federated.py` provides a tested sample-count-weighted vector average with
version/dimension validation. It is not a coordinator or a full training loop.

Before implementation, define the device data/labels, feature normalization,
missing-sensor handling, prediction horizon, temporal train/validation split,
health mapping, calibration, resource budget and artifact schema. Measure a
custom baseline before adopting a larger architecture. Local training returns
model updates; round coordination, model promotion, privacy and poisoning
protections remain separate work.

ML01's [dataset, label and leakage-safe partition decision](datasets/backblaze-2013/README.md)
pins a real historical HDD corpus and a seven-day recorded-event target.
`partitions.py` builds and verifies its deterministic device/temporal evidence
indexes. It does not train a model or map SMART values to the fixture endpoint;
the decision records the remaining labels, telemetry and evaluation blockers.

ML05's [predeclared evaluation and resource thresholds](evaluation/README.md)
fix the held-out procedure, baseline/false-positive/calibration/horizon gates
and endpoint budgets before fitting. `evaluation.py` checks reports against
them and returns pass, fail or blocked. It computes no metric.

CT03's [frozen feature version](../packages/contracts/features-v1.md),
`hdd-smart-7d.v1`, fixes the SMART counter order, seven-day window, `log1p`
transform and missing-value rules. `features.py` is the Python reference; it
matches the Go reference on the shared vectors within `1e-12`.

ML07's `training_features.py` feeds the ML01 example stream through that
reference (`training_vectors`) and gates model input to complete vectors
(`model_input`). Its endpoint twin is `packages/health`. Both match
`packages/contracts/fixtures/features/pipeline-cases.json`. No SMART collector
exists, so no real endpoint counter has passed through either path.
CT10's [model manifest](../packages/contracts/model-manifest-v1.md) is the
signed record a runtime checks before it activates an artifact. `manifest.py`
checks structure, feature order, runtime, architecture, purpose and the artifact
digest. It does not verify the Ed25519 signature; no cryptography library is a
dependency here, so the caller verifies `signing_bytes` first.

ML02's [logistic baseline](baseline/README.md) trains on the ML01 train
partition only, through `training_features`, and writes an artifact plus a
provenance record. The artifact is not publisher-signed, so CT10 activation
still refuses it. ML06's [held-out evaluator](evaluation/README.md) scores it
against the ML05 gates. The offline evaluator uses NumPy for device-clustered
resampling and metric computation.
