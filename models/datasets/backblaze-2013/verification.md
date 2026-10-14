# ML01 verification evidence

The committed policy and manifest were generated from the actual pinned
Backblaze ZIP, not the synthetic unit-test observations. The source archive
has 80,983,520 bytes and SHA-256
`7f5a53e79b16e695b4b034955806bb3bb194534b169f6eca460dfd3dc48096fe`.
The [decision](README.md) records terms, label semantics, commands and limits.

## Full-source result

- 266 daily CSV files, 10 April–31 December 2013.
- 5,091,501 rows, 29,072 source serials and 724 event-marked rows.
- Source rows with missing values: SMART 187 and 198 each **5,091,501**;
  SMART 5, 9 and 197 each **0**. Nulls remain null.
- 44,251 candidate anchors lack complete history; 122,437 are right-censored;
  381 are on/after a previously observed event. Another 2,645,244 lie outside
  their device cohort's permitted evidence window. These rejection counts
  describe anchors visited once their horizon can be processed; the archive's
  final seven unmatured anchor days do not enter that loop.

| Partition | Eligible serial hashes | Negative windows | Positive windows | Distinct positive events |
| --- | ---: | ---: | ---: | ---: |
| Train | 17,365 | 1,879,883 | 1,646 | 245 |
| Validation | 3,625 | 20,131 | 10 | 4 |
| Test | 4,047 | 186,676 | 278 | 45 |

The three device sets have zero intersection. Full feature+label intervals
stay inside their declared calendar partitions. The validation set contains
only **four** distinct positive events: class presence does not establish an
adequate evaluation population. This is a recorded blocker for generalization
or release claims, not a reason to tune the split after seeing the labels.

Canonical example-stream SHA-256 values:

```text
train       25e5e4c2cce259ae4e23d5699fc2eba832f44a3d0c8cf0dc147d000e5239fd85
validation  005f4cb5dcce8c9a7ea03bab075b8865cc677da6e2325f046cecf39c754865ba
test        e68a3a8d8150753278dbd8f2ce2f604aa5560998afced1601814d6129e31de61
```

Full `partitions.json` SHA-256:
`a786dfefa4254308b65d7fd2a9d5a785976b2dc22b8ab26892e4b2f60a1be025`.
The manifest contains each eligible serial hash, date bounds and counts, and
binds the policy SHA-256. Two local source passes produced identical example
stream digests; the later pass also recorded distinct event counts.

## Executable verification

Local Windows environment: Python 3.12.14, Go 1.27.1 windows/amd64 and WinLibs
GCC 16.2.0. GNU Make was provided by the winget-installed WinLibs toolchain;
Git for Windows `sh.exe` ran the existing POSIX recipes. Native invocation:

```text
mingw32-make SHELL="<Git directory>/usr/bin/sh.exe" PYTHON=python check
mingw32-make SHELL="<Git directory>/usr/bin/sh.exe" PYTHON=python cross-build demo
```

`models/src` is placed on `PYTHONPATH` by the Makefile. The interpreter, Go and
C compiler must be on `PATH`. No additional Python package is required.

| Check | Local result |
| --- | --- |
| `make check` targets: vet, race tests, model tests, Go formatting | PASS |
| `make model-check` through the check target | PASS, 15 tests |
| Windows amd64/macOS arm64 endpoint builds | PASS; macOS is a cross-build |
| Native controller/endpoint binary demo | PASS; fixture provenance, matching digest, unknown health |
| Actual archive generation | PASS, source hash and CSV integrity/row validation |
| Changed-document local links and `git diff --check` | PASS |

The 13 partition tests (plus two existing model tests) exercise device/time
separation, exact horizon edges, future SMART perturbations, future labels
excluded from feature fingerprints, censored follow-up, missing history,
terminal-day exclusion, null-vs-zero, invalid numbers, overlapping policies,
source tampering, duplicate device/day rows, absent labels, input order,
manifest tampering and the committed real-device membership/count invariants.

Hosted CI separately runs all existing checks and `dataset-reproduction` on
Linux/Python 3.12. The latter downloads the actual archive and invokes
`--verify` to reproduce the complete committed manifest byte-for-byte. The PR
checks provide the run-specific status and logs; this source document alone
does not assert that a hosted run passed.

No accuracy, calibration, false-positive rate, endpoint inference cost,
production health classification or patent conformance is measured here.
This completes the dataset/label/partition spike while preserving the
missing-label, missing-collector and subsequent evaluation gates.
