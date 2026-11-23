# Logistic baseline artifact, ML02 #33, 23 November 2026

This change fits one standard-library L2 logistic regression on the ML01 train
partition and saves the artifact with its provenance. No endpoint inference,
health label, ML05 score, publisher signature or chain write was added.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Training saves dataset and split digests, seeds, feature version, parameters and artifact digest, with provenance, using the frozen preprocessing | `models/baseline/backblaze-2013/provenance.json` and `artifact.json`. Preprocessing is `training_features.training_vectors` calling `features.compute`. Fit rows are 1,646 positive and 1,879,883 negative, matching the train labels, with 0 incomplete vectors excluded. |
| A clean rerun reproduces the declared artifact or stays within the recorded tolerance, and cannot train on held-out partitions | Same-process refits in `test_baseline.py` match bytes. `verify` on this host reproduced the committed artifact exactly (below). Held-out vectors and a train label on a validation device raise `HeldOutPartition` before Newton. The spec cannot select `test`. |
| Hosted Jev and unevaluated synthetic output are not substitutes | The fit read the pinned archive `7f5a53e7…096fe` (80,983,520 bytes). Provenance `claims.hosted_jev` and `claims.synthetic_training_rows` are false. Synthetic tests cover the code and are not the packaged artifact. |

## Fit

Spec `ml02.logistic-baseline.v1`, SHA-256 `385053369c33ace73fc5af33885a68381bbc287a00211c8675eafd346380550a`.
Seed 33. Optimizer draws 0. Fifteen Newton steps, L2 1 on standardized weights, balanced class weights, population scaling, negative keep rate 1/1. The objective is weighted negative log likelihood plus `(l2/2) * ||weights||^2`. The intercept is unpenalized. The final logged gradient infinity-norm was `2.866e-11`.

The first packaged artifact, SHA-256 `3589078fbd4d8a1e2e797677439679c7d15f22b822d0a76852e4fb4400b15e3a`, added L2 only to the Hessian. At a zero start that term is zero, so the one-step check still passed and that digest does not implement the declared objective. The packaged files were regenerated after the gradient gained `l2 * weight`. The spec file did not change. The replacement artifact SHA-256 is `e5cbc59e4bb6cebe348e7d3edfab1bbe998720ed27c3445f1409b7ecc7c3d3c8`.

Split example digests, matching `partitions.json`:

| Split | Examples SHA-256 |
| --- | --- |
| Train | `25e5e4c2cce259ae4e23d5699fc2eba832f44a3d0c8cf0dc147d000e5239fd85` |
| Validation | `005f4cb5dcce8c9a7ea03bab075b8865cc677da6e2325f046cecf39c754865ba` |
| Test | `e68a3a8d8150753278dbd8f2ce2f604aa5560998afced1601814d6129e31de61` |

Policy SHA-256 `f5e1080c971001622a220d6843f3a0463084db79ea4e685a83c41a15bebfeff8`.
Manifest SHA-256 `a786dfefa4254308b65d7fd2a9d5a785976b2dc22b8ab26892e4b2f60a1be025`.

Observed resources on this Linux host, Python 3.12.3, one logical processor: wall 438,297 ms, peak RSS 261,038,080 bytes. Both are inside the ML05 central-training budget (1,800 s, 4 GiB, 4 processors). This is not an endpoint measurement.

## Commands and results

```sh
PYTHONPATH=models/src python3 -m device_audit_models.baseline train \
  --archive /tmp/backblaze/data_2013.zip
PYTHONPATH=models/src python3 -m device_audit_models.baseline verify \
  --archive /tmp/backblaze/data_2013.zip
PYTHONPATH=models/src python3 -m unittest models.tests.test_baseline models.tests.test_training_features
python3 tools/ci/path_filters_test.py -q
make model-check
```

`train` printed `PASS train artifact_sha256=e5cbc59e4bb6cebe348e7d3edfab1bbe998720ed27c3445f1409b7ecc7c3d3c8 positive_rows=1646 negative_rows=1879883 wall_ms=438297`.

`verify` printed `PASS exact artifact_sha256=e5cbc59e4bb6cebe348e7d3edfab1bbe998720ed27c3445f1409b7ecc7c3d3c8` and exited 0. The Newton gradient sequence matched the training run, ending at `2.866e-11`.

`path_filters_test.py`: 28 tests passed. The filter script was not changed for the gradient correction.

`make model-check`: 89 tests passed. Go was not changed, so `make check` was not run.

## Not tested

- The model was not scored on validation or test. #103 owns the ML05 gates. No health label was produced.
- No CT10 publisher signature was created, so the artifact cannot be activated.
- No endpoint, Windows host or SMART collector ran. The feature contract still has no endpoint counter.
- Cross-platform libm differences were not measured here. The tolerance (`1e-8` absolute, `1e-7` relative) is what `verify` accepts when bytes differ. This host's rerun and the GitHub `dataset-reproduction` job both printed `PASS exact` for `e5cbc59e4bb6cebe348e7d3edfab1bbe998720ed27c3445f1409b7ecc7c3d3c8`. The job on `bd43748` used the same gradient sequence and ended at `2.866e-11`. `windows-check` on that commit passed after `models/**/*.json` was pinned to LF.
- `windows-check` on `bd4db12` failed before Newton: Git for Windows checked the artifact and provenance out with CRLF, so `load_artifact` refused them as non-canonical. The packaged test also rejects a carriage return in those bytes. Merging #105 did not change the feature rules, the partitions, or this artifact.
