# ML01 dataset, label and partition decision

Decision for #22: use the checksum-pinned **Backblaze Drive Stats 2013** archive
as the first reproducible, historical **HDD event-label study**. The initial
archive covers 266 daily snapshots, 10 April through 31 December 2013. Its
bounded size makes full-source reproduction practical in ordinary CI. It is
not a representative release dataset for modern Windows laptops or NVMe SSDs.
No model is trained or evaluated by this change.
The [verification record](verification.md) contains actual corpus counts,
partition/event totals, fingerprints, local results and CI reproduction details.

## Provenance and usage terms

- Publisher/source: [Backblaze Drive Stats](https://www.backblaze.com/cloud-storage/resources/hard-drive-test-data).
- Original release/schema explanation: [Backblaze, February 2015](https://www.backblaze.com/blog/hard-drive-data-feb2015/).
- Archive: [data_2013.zip](https://f001.backblazeb2.com/file/Backblaze-Hard-Drive-Data/data_2013.zip), 80,983,520 bytes.
- SHA-256: `7f5a53e79b16e695b4b034955806bb3bb194534b169f6eca460dfd3dc48096fe`.
- Retrieved via HTTPS during the October 2026 implementation. This is our
  content pin, not a publisher signature or independently published digest.
  A changed archive must fail reproduction until explicitly reviewed and
  reversioned; do not update the pin to conceal a mismatch.

The publisher supplies custom usage terms, rather than an identified SPDX
license: attribute Backblaze, take responsibility for use, and do not resell
the underlying data; selling derived work is permitted. This is a summary of
the linked terms, not a claim that the dataset is CC0, MIT or public domain.
Keep dataset terms separate from any repository/software license.

The ZIP and raw telemetry are not committed or sold. The committed manifest
is a derived index: source/policy pins, hashed device membership, example
digests, counts and date ranges. Public serial hashes are deterministic
pseudonyms, **not anonymization**, and must remain off-chain.

## What the label means

The original `failure` field is binary. A marked day represents Backblaze's
recorded terminal operational day. Their [later explanation of label semantics](https://www.backblaze.com/blog/backblaze-drive-stats-for-q3-2024/)
distinguishes proactive replacement from reactive failure and says the dataset
does not provide that distinction per record. Treat it as a recorded
drive-failure/replacement event, not a proven causal fault or sudden physical
breakdown. A zero in one daily row does not establish future health.

The selected target is **a recorded event in the next seven calendar days**:
for an anchor date `t`, label 1 means an observed `failure=1` in `(t, t+7]`.
Label 0 requires an observed, nonfailed row on **every** following day through
`t+7`. Missing follow-up without a known event is right-censored and omitted,
not filled with a negative label. A known event in the horizon remains a
positive even if other follow-up days are absent. The failure day and all later
rows for that serial are excluded as prediction anchors.

Seven days is an explicit first-study planning choice at the source's daily
resolution, selected before fitting. It is not an optimized or validated
lead time, an exact within-day timestamp guarantee, or a promise that a
Windows user gets seven days of warning. Horizon changes require a new policy
version and regenerated evidence, not tuning against held-out results.

## Mapping to available telemetry

The evidence index uses seven consecutive source days ending at the anchor,
with this fixed candidate column order. Blanks remain null; there is no
zero-filling, global normalization or imputation fitted on held-out data.

| Dataset field | Candidate interpretation | Current endpoint mapping |
| --- | --- | --- |
| `smart_5_raw` | Drive SMART counter 5 | Absent; `disk_used_percent` measures capacity use and is not equivalent |
| `smart_9_raw` | Drive power-on-hours counter | Absent; host uptime would not be equivalent |
| `smart_187_raw` | Drive SMART counter 187 | Absent; retain missing values |
| `smart_197_raw` | Drive SMART counter 197 | Absent; retain missing values |
| `smart_198_raw` | Drive SMART counter 198 | Absent; retain missing values |
| `serial_number`, `model`, `capacity_bytes`, `date` | Identity, domain metadata and time indexing | Identity only groups examples; serial/model/capacity and calendar date are not learned predictor inputs |
| `failure` | Outcome evidence | Label only, never an input feature |
| CPU/GPU, memory, network, battery, temperatures, structured OS errors | No corresponding component fault labels in this study | Existing v1 CPU/memory values are fixtures; no training mapping is inferred |

Raw SMART meaning/availability is vendor-dependent. Even a column with a
familiar name does not settle normalized units, vendor equivalence or a health
threshold. The actual null counts are published in `partitions.json`; columns
may be entirely unavailable in this historical archive. This ordering defines
the **index fingerprint**, not the shared CT03 training/inference feature
contract. Feature selection, scaling and missingness handling remain #32/#102.

There are no usable per-component CPU, GPU, memory, battery or network fault
labels, fault-type labels, or Windows service/diagnostic outcome labels in
this corpus. Those failure-prediction claims are blocked. Endpoint prediction
also remains blocked by the absent matching collector, historical/datacenter
domain shift, #86's evaluation thresholds and #33/#103's fitting/evaluation.
No existing healthy/risk value or production capability changes here.

## Deterministic device and temporal separation

`policy.json` is versioned and contains the complete constructive partition
rule. SHA-256 of the UTF-8 fixed salt, a NUL separator and the exact serial
assigns one global device key. The first 16 hexadecimal digits modulo 10,000
assign its permanent cohort. Model spelling changes cannot move a serial to a
different cohort. Blank or whitespace-ambiguous serials fail input validation.
No seed search, class balancing, random row split or outcome-based sampling is
performed.

| Partition | Device hash buckets | Entire permitted evidence interval | Eligible anchor dates |
| --- | --- | --- | --- |
| Train | 0–6999 | 10 Apr–31 Aug 2013 | 16 Apr–24 Aug |
| Validation | 7000–8499 | 1 Sep–31 Oct 2013 | 7 Sep–24 Oct |
| Test | 8500–9999 | 1 Nov–31 Dec 2013 | 7 Nov–24 Dec |

The seven-day feature history and seven-day forward label interval must both
fit inside the partition. Boundary anchors are purged: no validation feature
history borrows from training dates, and no training target observes validation
dates. Distinct cohort keys also prevent any physical serial's data from
appearing in two partitions. Reusing a drive's earlier rows as training and its
later rows as test is explicitly disallowed.

The manifest lists the eligible device keys, first/last anchor, class counts,
distinct positive events and SHA-256 of each partition's canonical example
stream. Each example binds device, split, anchor, feature dates/digest, fixed
label end, label-availability date and label. Generation order is anchor date,
then device key; ZIP-member and CSV-row order do not change examples. ZIP hash
changes still require an explicit source decision even when examples match.

Repeated windows around one failed drive are correlated, so positive example
counts are **not independent failure counts**. Use `positive_event_count` and
device-level uncertainty in later evaluation. Both classes merely being
present does not establish sufficient statistical power or a release gate.
An absent class is recorded as `blocked_missing_class`; never reclassify
unknown observations, relax a horizon or search a split to manufacture it.

## Reproduce the evidence

Python 3.12 or newer, standard library only. From the repository root:

```powershell
# PowerShell: download once into ignored local artifacts.
New-Item -ItemType Directory -Force artifacts | Out-Null
Invoke-WebRequest https://f001.backblazeb2.com/file/Backblaze-Hard-Drive-Data/data_2013.zip -OutFile artifacts/data_2013.zip
$env:PYTHONPATH = 'models/src'
python -m device_audit_models.partitions --archive artifacts/data_2013.zip --policy models/datasets/backblaze-2013/policy.json --verify models/datasets/backblaze-2013/partitions.json
python -m unittest discover -s models/tests -v
```

On POSIX shells, use `curl -fL ... -o artifacts/data_2013.zip`, and prefix the
Python commands with `PYTHONPATH=models/src`. `--verify` compares exact bytes
against the committed manifest and exits nonzero on mismatch. To intentionally
create a new reviewed manifest, replace `--verify` with `--output PATH`.
The source hash is checked before ZIP reading, CSV CRCs are checked while
streaming, and invalid dates, labels, numeric values, columns or duplicate
device/day observations fail closed. The reader never extracts archive paths.

`make model-check` exercises adversarial synthetic cases plus the real
manifest's membership/count invariants. The separate `dataset-reproduction`
CI job downloads the **actual** pinned archive and independently verifies every
example digest and the full manifest. Synthetic tests are not represented as
real-source evidence. The implementation keeps only fourteen daily frames,
permanent identity/failure metadata and manifest membership sets in memory.
