# ML05 predeclared evaluation and resource thresholds

Decision for #86, declared on 17 November 2026 **before any model was fitted**.
[`ml05-policy.json`](ml05-policy.json) holds the numbers.
`device_audit_models.evaluation` checks reports against it. The module computes
no metric, trains nothing and does not create a validated model. #103 computes
the metrics. #33 trains the [logistic baseline](../baseline/README.md) and does
not score it. #104 measures inference on the target laptop.

The policy covers the ML01 [Backblaze 2013 HDD event study](../datasets/backblaze-2013/README.md).
It pins the partition policy (canonical SHA-256 `f5e1080c…eff8`) and the exact
`partitions.json` bytes (SHA-256 `a786dfef…e025`). The horizon stays at 168
hours (seven days). If the partitions, horizon or any threshold change, the
policy SHA-256 changes and every earlier evaluation report is blocked with
`policy_mismatch`. A changed policy needs a new `policy_version` and its own
review. It cannot be edited after results are seen.

## Held-out procedure

1. The model is fitted on the `train` partition only. Any probability
   calibration step is fitted on device-grouped 5-fold out-of-fold predictions
   inside `train`.
2. Validation has 20,131 negative windows and only **four** distinct positive
   events. Four is below the policy's 30-event minimum for any use of
   positives. Validation positives therefore do not select models, tune
   hyperparameters or fit calibration. Validation **negative** scores set the
   two operating points: `degraded` is the score quantile with a 0.5% target
   window false-positive rate, and `critical` uses a 0.1% target.
3. Test is evaluated once per candidate, using every eligible example with no
   subsampling. A report with `test_evaluations_for_candidate` other than 1 is
   blocked. A new candidate after a test result needs a new model version.
   The policy does not make a test result reusable for selection.
4. Uncertainty comes from a device-clustered percentile bootstrap: 2,000
   replicates, seed 86, 95% interval. Repeated windows around one failed drive
   are correlated, so the resampling unit is the device and not the window.
5. Baselines are scored on the same test examples. `prevalence` is the constant
   train positive-window rate, 1,646 / 1,881,529 ≈ 8.75 × 10⁻⁴.
   `smart_rule` uses the most recent non-null `smart_5_raw + smart_197_raw` in
   the window. Both columns have zero source nulls in ML01. All-null scores
   rank lowest.

## Minimum evidence (blocking, never relaxed)

| Count | Minimum | ML01 manifest |
| --- | ---: | ---: |
| Test distinct positive events | 30 | 45 |
| Test positive windows | 100 | 278 |
| Test negative windows | 10,000 | 186,676 |
| Test devices | 1,000 | 4,047 |
| Validation negative windows | 10,000 | 20,131 |

A count below its minimum, a missing count, `label_status` other than
`both_classes_present`, or a null, non-finite or inconsistent metric interval
gives `blocked`. A blocked result cannot pass, even if every reported metric
clears its threshold. A blocked result is not a failed model either. It means
the evidence cannot decide.

## Metric thresholds

Pass needs every gate. Where a gate uses a confidence bound, the bound must
clear the threshold, not only the point estimate.

| Family | Metric | Bound | Threshold | Reason |
| --- | --- | --- | --- | --- |
| Baseline | Average precision minus the better baseline | lower | > 0 | Must beat both baselines, not only on average |
| Baseline | Event recall minus `smart_rule` event recall at its own 0.5% FPR point | lower | ≥ −0.05 | No material loss against a trivial SMART rule |
| Baseline | ROC AUC | lower | ≥ 0.70 | Minimum ranking ability |
| False positive | Test window FPR at `degraded` | upper | ≤ 0.010 | Twice the 0.5% validation target |
| False positive | Test window FPR at `critical` | upper | ≤ 0.002 | Twice the 0.1% target |
| False positive | Fraction of never-positive test devices with any `degraded` alert | upper | ≤ 0.10 | Bounds administrator alert load over the 61-day test window |
| Calibration | Brier skill vs `prevalence` | lower | > 0 | Probabilities better than the base rate |
| Calibration | Observed/expected events ratio | point | 0.67–1.5 | Calibration-in-the-large within 1.5× either way |
| Calibration | Calibration slope (logistic of label on logit p) | point | 0.7–1.3 | Not grossly over- or under-confident |
| Horizon | Distinct events with any `degraded` alert in their 7 preceding anchors | point / lower | ≥ 0.30 / ≥ 0.15 | Useful warning at the declared horizon |
| Horizon | Median days from first alert to the event, detected events | point | ≥ 2.0 | Alerts must arrive before the last day |

These thresholds were chosen from the class balance and planned use, not from
any model output. They are not optimized and they do not establish that a
model meeting them is accurate for Windows laptops or NVMe drives.

## Health mapping

`degraded` is this project's term for the source's "warning" ([0057]). A
model probability maps to `critical` at or above the critical operating point,
`degraded` at or above the degraded point, and `healthy` below it. The mapping
applies only after a `pass`. Otherwise, and on timeout, missing model, or stale
or insufficient input, the result is `unknown`. #35 owns combining this with
historical fault type, count and recurrence. The mapping changes no wire
contract.

## Resource budgets

The target is the single selected physical laptop: HP Victus 15-fb0xxx,
`AMD Ryzen 5 5600H with Radeon Graphics`, 12 logical processors, 15.34 GiB
OS-visible memory, Windows build family 26200 ([14 October](../../docs/validation/windows-2026-10-14.md),
[19 October](../../docs/validation/windows-2026-10-19.md)). On 19 October,
memory use was 69–76% during development, so about 3.7–4.7 GiB was free.
The largest PowerShell probe worker peaked at 98.58 MiB. A probe sweep spent
5.3–8.9 CPU-seconds.

| Budget | Limit | Basis |
| --- | --- | --- |
| Inference artifact | ≤ 16 MiB | Fits approved model staging without spool pressure |
| Inference peak working set | ≤ 64 MiB | < 0.5% of OS-visible memory and below one measured probe worker |
| Inference latency | p95 ≤ 200 ms, max ≤ 1,000 ms, timeout 2,000 ms | Timeout is well under the 10 s source deadline and the 60 s sweep |
| Inference CPU | ≤ 250 ms CPU per prediction | Under 0.01% of one core at one prediction per hour |
| Inference cadence | ≥ 3,600 s between predictions | Daily-resolution labels; more frequent inference adds cost without new evidence |
| Sweep interference | ≤ 1,000 ms delay to a telemetry sweep start | Measured with 60 s sampling running at the same time |
| Measured predictions | ≥ 30 | Same sample count as the 30-sweep collector runs |
| Endpoint local training | ≤ 256 MiB, 1 logical processor, ≤ 600 s, ≥ 86,400 s apart, AC power, below-normal priority | One of 12 logical processors; breach aborts the round and discards the update |
| Central training (#33) | ≤ 1,800 s, ≤ 4 GiB RSS, ≤ 4 logical processors | GitHub-hosted Ubuntu runner, 4 cores and 16,780,623,872 bytes when measured under #85 |
| Training sampling | Negatives may be hash-subsampled with a keep-rate ≥ 0.05 declared before fit; positives never | Evaluation examples are never subsampled |

Inference adds no collector sweeps. It reads daily aggregates from existing
samples. #85 still owns the collector cadence budget, which is not approved.
An endpoint report is blocked unless it comes from a physical host matching the
CPU model, logical-processor count and build family. A CI VM or the Linux
development host cannot pass it. On breach, inference returns `unknown` with
`model_unavailable` and telemetry continues. #104 must demonstrate that
behavior.

## Commands

```sh
PYTHONPATH=models/src python3 -m device_audit_models.evaluation \
  --policy models/evaluation/ml05-policy.json \
  --verify-pins models/datasets/backblaze-2013/policy.json models/datasets/backblaze-2013/partitions.json
PYTHONPATH=models/src python3 -m device_audit_models.evaluation \
  --policy models/evaluation/ml05-policy.json --report REPORT.json      # ML06 #103
PYTHONPATH=models/src python3 -m device_audit_models.evaluation \
  --policy models/evaluation/ml05-policy.json --resources RESOURCES.json  # #104 / #33
```

Exit codes are 0 for pass, 1 for fail and 2 for blocked. Report schemas are
`device-audit.evaluation-report.v1` and `device-audit.resource-report.v1`. The
gate output is `device-audit.evaluation-gate.v1`. The tests in
`models/tests/test_evaluation_policy.py` show the field layout.
