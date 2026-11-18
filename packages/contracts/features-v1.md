# Frozen feature version `hdd-smart-7d.v1`, CT03 #32

This is the only feature version. Training (#102), endpoint preprocessing
(#102), controller preprocessing (#105), model manifests (#101) and federated
rounds (`feature_version`, #77) must name it and must not substitute another
ordering or transform. A change to any rule below needs a new feature version,
new fixtures and a new review. It cannot be edited in place.

Two reference implementations exist: Go in [`features_v1.go`](features_v1.go)
and Python in [`models/src/device_audit_models/features.py`](../../models/src/device_audit_models/features.py).
They were written separately and agree on every shared vector within the
recorded tolerance. Consumers call one of them; they do not reimplement it.

## Why these inputs

The feature set follows the only labeled study, ML01's
[Backblaze 2013 HDD decision](../../models/datasets/backblaze-2013/README.md),
and ML05's [pinned evaluation policy](../../models/evaluation/README.md).

| ML01 column | Selected | Reason |
| --- | --- | --- |
| `smart_5_raw` | yes | 0 null of 5,091,501 source rows; half of ML05's `smart_rule` baseline |
| `smart_9_raw` | yes | 0 null; power-on hours |
| `smart_187_raw` | **no** | 5,091,501 null of 5,091,501 rows. A model cannot learn from it |
| `smart_197_raw` | yes | 0 null; the other half of `smart_rule` |
| `smart_198_raw` | **no** | 5,091,501 null of 5,091,501 rows |

Serial, model, capacity, date and `failure` stay out, as ML01 requires.
Telemetry v2 metrics (CPU/GPU utilization, memory, disk-used, battery,
temperature, latency) and structured error events are **not** features of this
version. The selected study has no labels for them, so no model can be fitted
or evaluated on them against ML05. A future feature version that adds them needs
a labeled source first.

## Collector mapping

| Producer | `smart_5_raw` | `smart_9_raw` | `smart_197_raw` |
| --- | --- | --- | --- |
| Training, Backblaze 2013 | CSV column | CSV column | CSV column |
| Endpoint, `packages/telemetry` | no collector | no collector | no collector |
| Controller, persisted evidence | not in telemetry v2 | not in telemetry v2 | not in telemetry v2 |

No endpoint collector reads SMART attributes. Host uptime and
`disk_used_percent` are not substitutes (ML01). The endpoint and controller
therefore produce a window with no samples, and the vector is `incomplete`
with every value `no_observation`. Under ML05's health mapping that is an
`unknown` prediction with `insufficient_evidence`. **This feature version
cannot produce a known prediction on any endpoint until a SMART collector
exists.** That collector, its Windows permission model and its NVMe mapping
are not planned by any issue yet.

Training maps one Backblaze row for serial `s` on date `d` to one sample with
`observed_at = dT00:00:00Z` and the three selected columns. An anchor date `t`
uses `as_of = tT23:59:59Z`. The vector is then `complete` exactly when ML01
counts the anchor as having complete history, because the three selected
columns have no source nulls.

## Input: `device-audit.feature-window.v1`

```json
{
  "schema_version": "device-audit.feature-window.v1",
  "feature_version": "hdd-smart-7d.v1",
  "as_of": "2013-11-07T23:59:59Z",
  "samples": [
    {"observed_at": "2013-11-01T00:00:00Z", "smart_5_raw": 0, "smart_9_raw": 11000, "smart_197_raw": 0}
  ]
}
```

- Timestamps are UTC, whole seconds, `YYYY-MM-DDTHH:MM:SSZ`, years 0002–9999.
- Every sample has all three counter keys. `null` means not observed. It is
  never read as zero.
- A counter is an integer from 0 to 2^53 − 1. Negative, fractional and
  integral-float (`1.0`) tokens are rejected. JSON Schema alone accepts `1.0`.
- At most 10,080 samples (one per minute for seven days). Two samples with
  the same `observed_at` are rejected. Input order does not matter.
- A different `feature_version` is rejected as `unsupported_feature_version`.
  Readers must not fall back to another version.

## Preprocessing rules

1. **Window.** The window is the seven UTC calendar days ending on the UTC day
   of `as_of`, from 00:00:00 on the first day through `as_of` inclusive.
2. **Future and old evidence.** Samples after `as_of` or before the first day
   are ignored. A late-arriving or out-of-order sample can therefore never put
   future evidence into a window.
3. **Daily value (noise filter).** For each counter and day, the value is the
   reading with the latest `observed_at` that is not null. Earlier readings that
   day and later null readings do not change it. This reduces sub-daily
   samples to the daily resolution of the training labels. No smoothing,
   clipping, outlier removal or fitted filter is applied: any data-derived
   threshold would need a fitted parameter that training and inference could
   disagree on.
4. **Missing values.** A counter with a value on all seven days is known. A
   counter with no value on any day is `no_observation`. Any other count is
   `incomplete_history`. Both of that counter's features carry the same
   reason. Nothing is imputed, forward-filled or zero-filled. ML01 trained and
   evaluated only complete windows, so a partial window would be outside the
   evidence the model was judged on.
5. **Features.** With `first` the value on day 1 and `final` the value on day 7:
   - `<counter>.last = log1p(final)`
   - `<counter>.delta = sign(final − first) · log1p(|final − first|)`

   A decrease is kept as a negative change. SMART 197 (pending sectors) can
   fall when sectors are remapped, and a counter reset is real evidence of a
   changed drive state; v1 has no reset rule.
6. **Normalization.** `log1p` is fixed and has no fitted parameters, so the
   same transform runs in training and inference with no scaler state and no
   leakage from held-out data. Any learned scaling belongs inside the model
   artifact (#101), not in this contract.
7. **Status.** `complete` when every value is known; otherwise `incomplete`.
   Only a `complete` vector may reach a model. An `incomplete` vector yields an
   `unknown` prediction.

## Output: `device-audit.feature-vector.v1`

The features appear in this frozen order:

| Index | Name | Unit |
| ---: | --- | --- |
| 0 | `smart_5_raw.last` | `log1p_count` |
| 1 | `smart_5_raw.delta` | `signed_log1p_count` |
| 2 | `smart_9_raw.last` | `log1p_hours` |
| 3 | `smart_9_raw.delta` | `signed_log1p_hours` |
| 4 | `smart_197_raw.last` | `log1p_count` |
| 5 | `smart_197_raw.delta` | `signed_log1p_count` |

Each entry is `{name, value, unit}`. A null value also carries
`missing_reason`; a known value must not. The vector also records
`as_of`, `window_start`, `window_end` (dates) and `status`. A reader rejects a
vector whose version, order, units, window dates, status or missing reasons do
not match these rules, including a `.last` and `.delta` pair that disagree.

## Tolerance

Two implementations agree when, for every value,
`|a − b| ≤ 1e-12 + 1e-12 · |b|`, and every other field is identical. The values
are bounded by `log1p(2^53) ≈ 36.7`. Counter differences are exact integers in
both languages, so only the `log1p` implementations can differ.

## Shared vectors

[`fixtures/features/v1-vectors.json`](fixtures/features/v1-vectors.json) has
29 cases: 10 valid windows with expected vectors, 9 rejected windows, 2 valid
vectors and 8 rejected vectors. The expected values come from hand-written
first/final day values in [`generate.py`](fixtures/features/generate.py), not
from either implementation:

```sh
python3 packages/contracts/fixtures/features/generate.py
python3 tools/generate_contract_wire_vectors.py
make contract-check check
```

The cases cover intra-day selection in shuffled order, samples after `as_of`
and before the window, one missing day, no samples, all-null samples, falling
SMART 197, a power-on-hours reset, the largest exact counter and each input
and vector rejection, including `unsupported_feature_version`. The other
owner reviews these vectors before #101, #102 or #105 merges.

## Not claimed

These rules do not make a model, a SMART collector or an endpoint prediction.
The Backblaze source is a 2013 datacenter HDD population; it says nothing about
laptop drives, NVMe devices or any other component. Fixtures and references
are not production preprocessing evidence until #102 and #105 run them on real
inputs.
