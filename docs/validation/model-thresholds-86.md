# ML05 predeclared thresholds, 17 November 2026

Issue #86. This records local checks of the evaluation and resource policy
declared in [models/evaluation](../../models/evaluation/README.md). No model,
training run, metric computation or Windows inference measurement exists yet.
The policy came before all of them.

## What was declared

- `models/evaluation/ml05-policy.json`, `policy_version` `ml05.v1`, canonical
  SHA-256 `9a5d1e1e490b81b701cd86fb739d80a3b4bdbe2330c489d38265ec40e84e3d48`.
- It pins the ML01 partition policy, canonical SHA-256
  `f5e1080c971001622a220d6843f3a0463084db79ea4e685a83c41a15bebfeff8`, and the
  `partitions.json` bytes, SHA-256
  `a786dfefa4254308b65d7fd2a9d5a785976b2dc22b8ab26892e4b2f60a1be025`.
- 14 numerical gates across the baseline, false-positive, calibration and
  horizon families. It also sets five minimum-evidence counts, a once-only
  held-out procedure with a 2,000-replicate device-clustered bootstrap, a
  health mapping, and endpoint inference, endpoint training, central training
  and sampling budgets.

## What was checked

`models/tests/test_evaluation_policy.py`, 17 tests, synthetic reports only:

- The committed policy verifies against the real ML01 policy and manifest. A
  changed horizon or a single extra manifest byte is reported as a mismatch.
- The real test partition meets every minimum: 45 events, 278 positive windows,
  186,676 negative windows and 4,047 devices. The real validation partition has
  4 events, below the 30-event minimum for positive use, so the procedure uses
  only validation negatives.
- The policy rejects weakened procedures: not declared before fit, evaluation on
  validation, repeated test evaluation, example sampling, operating points from
  test scores, window-level or short bootstraps, a zero minimum, a missing
  calibration family, non-numeric or duplicate gates, and missing budgets.
- A report at every threshold passes. Missing each gate in turn fails that
  gate. Boundary values follow the declared strict or non-strict operator.
- Too few events, a missing count, a missing class, too few validation
  negatives, null or NaN metrics, or a missing metrics block all give `blocked`.
  The reported thresholds stay at their declared values. A failed metric
  together with missing evidence stays `blocked`.
- A wrong policy or manifest digest, a validation partition, a 336-hour horizon,
  a second test evaluation, a changed bootstrap seed, a missing artifact digest,
  an unknown schema, or an interval with point outside its bounds is `blocked`.
  Relaxing a threshold in a copy of the policy makes the existing report
  `policy_mismatch`.
- Resource reports at budget pass. A single breach fails that check only. A
  VM, the hosted runner's EPYC CPU, build family 26100, fewer than 30
  predictions, no concurrent sampling, no AC-power record, subsampled positives
  or a wrong policy digest give `blocked`.
- The inference budget is below 0.5% of the laptop's 15.34 GiB visible memory
  and below the 98.58 MiB probe worker peak. Its CPU share is below 0.01% of a
  core. Latency max < timeout < sweep cadence. Endpoint training uses at most a
  quarter of the 12 logical processors.
- The CLI returns 0, 1 and 2 for pass, fail and blocked.

## Commands

Go 1.27.4 linux/amd64 (the repository targets Go 1.27.1). Python 3.14.10 in a
temporary virtual environment with `models/test-requirements.txt`:

```sh
python3 -m venv /tmp/da86-venv
/tmp/da86-venv/bin/pip install -r models/test-requirements.txt
make PYTHON=/tmp/da86-venv/bin/python check
make cross-build
make PYTHON=/tmp/da86-venv/bin/python model-check
PYTHONPATH=models/src python3 -m device_audit_models.evaluation \
  --policy models/evaluation/ml05-policy.json \
  --verify-pins models/datasets/backblaze-2013/policy.json models/datasets/backblaze-2013/partitions.json
git diff --check
```

## Results

Passed on 17 November 2026:

- `go vet ./...`, `go test -race ./...`, controller fixture scenarios and
  `go fmt` clean, all through `make check`
- 51 Python tests under `models/tests`, including the 17 new ones
- Windows amd64 and Darwin arm64 endpoint cross-builds
- `--verify-pins`: `PASS: ml05.v1 9a5d1e1e…3d48 pins ML01 evidence`
- `git diff --check`

`make database-check` was not run. This change touches no Go or database code.

## Untested flows

No metric was computed. No model was trained, calibrated or scored. No
inference or training cost was measured on the HP Victus or elsewhere. The
budgets are limits for #33, #103 and #104 to measure against, not
measurements. The thresholds were set from class balance and planned use. Their
adequacy for Windows laptops, NVMe drives or any non-HDD component is not
established. The collector cadence budget is still unapproved under #85.
Endpoint failure prediction stays blocked by the absent SMART collector
mapping recorded in ML01.
