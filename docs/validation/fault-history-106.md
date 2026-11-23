# Fault history comparison, ML10 #106, 24 November 2026

`health.CompareFaultHistory` compares one device's fault reports in the current
window with a bounded baseline. `PostgresRepository.DeviceFaultHistory` feeds it
from persisted evidence. No route serves the result and no health state is
assigned; #35 owns the health rules.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Evidence-backed type/count/recurrence comparisons over bounded windows, retaining baseline and window references | The current window is the seven UTC days ending at `as_of` (the CT03 feature days); the baseline is the 21 days before it, 28 days in all, inside the 31-day history bound (`TestFaultWindowsAreBoundedAndAdjacent`). Each type carries current and baseline report counts, distinct report days, duplicates, a count change and every distinct report with its sample sequence and digest. The result names both windows with their sampled days, and the controller result adds deployment, device, samples read and the highest sequence read. `TestDeviceFaultHistoryReadsPersistedEvidence` checks these against PostgreSQL rows. |
| Tests distinguish recurrent faults, isolated incidents, duplicate reports and insufficient history | `TestCompareFaultHistoryClassifiesRecurrence` has ten cases: reports on two current days, current plus baseline, a one-day burst (isolated, count 3), one isolated report, baseline only, a steady rate, no history, 13 of 21 baseline days, recurrence without history and an unsampled current window. `TestCompareFaultHistoryCountsDuplicateReportsOnce` re-sends one digest in three samples: one report, two duplicates, the earliest kept. The PostgreSQL test repeats the duplicate case through stored log references. |
| Missing history is not a healthy baseline | No samples give no faults with both windows insufficient (`TestCompareFaultHistoryNoFaultsIsNotAHealthyBaseline`). One report with no or thin baseline is `insufficient_history` with count change `unknown`, never `isolated`; the same holds for a device enrolled one week before `as_of` in PostgreSQL. A baseline-only type with an unsampled current window is `insufficient_history`, not resolved. |

Inconsistent input is an error, not a result: a report after `as_of` or before
the baseline, a sample day outside the windows, a report on a day with no
sample, one digest under two types, an uppercase digest and an invalid type
(`TestCompareFaultHistoryRejectsInconsistentEvidence`).

## Fault checks

Each mutation was applied and reverted. The tests failed each time.

- `isolated` without requiring both windows to be sufficiently sampled.
- A duplicate digest counted as a new report.
- The baseline always treated as sufficient.
- The SQL window end moved one hour past `as_of`.

## Commands and results

Go 1.27.3 linux/amd64 and Python from `nix develop`, with a fresh local
PostgreSQL 17.11 cluster.

```sh
TEST_DATABASE_URL=... make check
CGO_ENABLED=0 make cross-build
make contract-check
```

All passed. `make check` ran with `TEST_DATABASE_URL` set, so the database
tests ran instead of skipping. The Nix shell's `CGO_ENABLED=1` breaks the
Darwin cross-build as recorded in [features-32.md](features-32.md).

## Not tested

- Every persisted report is type `unclassified`. A telemetry v2 log reference
  has a digest and a window but no fault type, and no classifier exists. Typed
  comparisons are proven with typed reports in the unit tests only.
- The endpoint sends an empty `log_references` list today, so a real device has
  no persisted report. An empty list does not show that error collection ran:
  a sampled day without a report is "no report", not "no fault".
- The thresholds (two thirds of window days sampled, two report days for
  recurrence) are provisional choices, not fitted to any fleet.
- The read decodes `log_references` in PostgreSQL for every sample in 28 days.
  Its cost on a 15 s sampler's month was not measured.
