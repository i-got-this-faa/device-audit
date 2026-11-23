# ML02 logistic baseline

Decision for #33. One L2-regularized logistic regression is fit on the ML01
train partition and saved as an artifact plus a provenance record. The
hyperparameters in [`training-spec.json`](training-spec.json) were fixed before
the fit. They were not searched on validation or test.

This is not a hosted Jev model, not a synthetic stand-in, and not an evaluated
predictor. #103 scores it against the [ML05 gates](../evaluation/README.md).
Nothing here assigns `healthy`, `degraded` or `critical`. The artifact has no
publisher signature, so a CT10 activation check cannot accept it. No raw log,
serial number or device key is written to a chain; the provenance stores
digests and counts.

## What is fit

`baseline.py` reads the pinned Backblaze 2013 archive through
`partitions.archive_days` and `training_features.training_vectors`. Feature
values come from `features.compute`. Incomplete vectors are excluded.
`model_input` is the only row a coefficient update can see.

The fit uses every train window. Positives are never subsampled. The declared
negative keep rate is 1/1, which is above the ML05 floor of 1/20. A spec that
selects `validation` or `test`, or a keep rate below that floor, is refused.
There is no function argument that chooses a held-out split. A held-out example
that still carries a feature vector raises `HeldOutPartition` before Newton
starts. A train label on a validation or test device is refused the same way.

Each feature is centered and scaled by the population mean and standard
deviation of the fit rows. A constant feature uses scale 1, so it stays zero
after centering. Class weights are `n / (2 n_class)`. The intercept is not
penalized. Fifteen Newton steps start at zero. The seed is recorded and is not
drawn from. Example order is anchor date, then device key.

Learned parameters are the intercept and six weights, plus the train-row mean
and scale stored in the artifact. `parameter_count` is 7: the intercept and the
weights. The moments are training state, not a federated update.

## Provenance

`backblaze-2013/provenance.json` records:

- dataset name, URL, byte size and SHA-256
- partition-policy digest, manifest digest, and the train, validation and test
  example-stream digests
- seed 33, with `optimizer_draws` 0
- feature version `hdd-smart-7d.v1` and the frozen feature names
- the training spec and its SHA-256
- fit-row counts and the seven parameter names
- artifact SHA-256
- rerun tolerance: `abs(actual - declared) <= 1e-8 + 1e-7 * abs(declared)`
- observed wall time, peak RSS and one logical processor

`claims` are all false: not evaluated, not endpoint-qualified, not Jev, not
publisher-signed, not on-chain, and not trained on synthetic rows.

## Reproduce

Python 3.12 or newer, standard library only. The archive is the pinned file
from the [ML01 decision](../datasets/backblaze-2013/README.md)
(`7f5a53e79b16e695b4b034955806bb3bb194534b169f6eca460dfd3dc48096fe`,
80,983,520 bytes). It is not committed.

```sh
PYTHONPATH=models/src python3 -m device_audit_models.baseline verify \
  --archive artifacts/data_2013.zip
```

`verify` trains again and compares the result with the committed artifact.
Exit 0 prints `PASS exact` when the bytes match, or `PASS within_tolerance`
when only the learned floats move and they stay inside the recorded tolerance.
Any other difference, including a different seed, spec, split digest or row
count, exits nonzero. `train` rewrites the two committed files; use it only
when the spec itself is being replaced and reviewed.

`make model-check` does not download the archive. It checks determinism, the
tolerance window, held-out refusal and the committed digests. The
`dataset-reproduction` CI job downloads the archive, verifies the ML01 manifest,
then runs `verify`. The host run that produced these files is recorded in
[the validation note](../../docs/validation/baseline-33.md). On that run `verify`
printed `PASS exact` for artifact `3589078fbd4d8a1e2e797677439679c7d15f22b822d0a76852e4fb4400b15e3a`.
