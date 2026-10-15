# Bespoke prediction and local training

The user selected a custom model, not Jev. Python/PyTorch was proposed, not
finalized. This Python package has no ML framework dependency yet.

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
