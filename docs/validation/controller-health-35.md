# Controller inference and health assignment validation, ML04 #35

Issue `#35` wires evaluated ML02 logistic-baseline inference and ML10 historical fault comparison into `packages/health` (`evaluation.go`, `rules.go`, `logistic.go`) and `internal/controller` (`health.go`).

## Implemented scope

- **Runtime boundary (`packages/health/logistic.go`)**: `ControllerInferenceRuntime()` pins `device-audit-controller-go` (`1.0.0`, `logistic-baseline.v1`), keeping controller activation distinct from endpoint inference manifests (`device-audit-endpoint-go`).
- **ML05 gate enforcement (`packages/health/evaluation.go`)**: `LoadControllerModel` and `VerifyEvaluationReport` verify the publisher Ed25519 signature, `inference` purpose, artifact digest, logistic layout, `ml05.v1` policy hash, `ML01` partition manifest hash, `168`-hour horizon, bootstrap config, all five minimum cohort counts, all 14 ML05 metric bounds, matching gate checks, and ordered finite logit operating points.
- **Health rules (`packages/health/rules.go`)**: `AssessHealth` implements `health-rules.v1`, combining evaluated model predictions with ML10 fault recurrence/rate comparisons and validating every non-empty result against `contracts.PredictionV2.Validate()`.
- **Controller repository snapshot (`internal/controller/health.go`)**: `PostgresRepository.EvaluateDeviceHealth` reads `device_enrollments`, latest `device_evidence` up to `asOf`, `model_references` (`active` slot only), `model_artifacts`/`model_approvals`, CT03 features (`FeatureEvidence`), and ML10 fault history (`DeviceFaultHistory`) inside a single `REPEATABLE READ READ ONLY` transaction, loading bounded evaluation JSON from `EvaluationReportDir` through `os.Root`.

## Evidence ledger

| Case | Evidence source | Verified behavior |
| --- | --- | --- |
| ML05 gate & model rejection | `TestVerifyEvaluationReportAndRealBaselineModel`, `TestControllerInferenceRuntimeCompatibility` | Rejects the real ML06 failed report, forged `"pass"` gates over failing metrics/counts, wrong runtime, wrong key/purpose, and bad operating points. |
| Python CT03 scoring parity | `TestVerifyEvaluationReportAndRealBaselineModel`, `TestEvaluateDeviceHealthEndToEnd` | Scores the `pipeline-cases.json` complete-week SMART fixture (`0.79956738641351921`) and zero-reallocated SMART fixture (`0.24889408556703072`) within `<1e-12` of Python (`ML02`). |
| Health rules (`health-rules.v1`) | `TestAssessHealthRules` | Covers all model × fault transitions (`healthy`, `degraded`, `critical` escalation), insufficient 7d/21d baselines (`unknown`), `>= 1h` / future `stale_evidence`, missing telemetry (`Prediction == nil`), and `model_unavailable`. |
| PostgreSQL 17 integration | `TestEvaluateDeviceHealthEndToEnd`, `TestEvaluateDeviceHealthModelFailuresAndBoundaries` | Real `ModelRegistryService` upload/approval/activation + `AcceptEvidence` signed `TelemetryV2` envelopes -> `unknown` (`insufficient_evidence`); known fixture CT03 + persisted `log_references` across 28 days -> `healthy` / `degraded` / `critical`; future-sample isolation, `1h` staleness, symlink escape block, and missing/candidate-only/runtime/policy/eval failure cases. |
| Fault-injection checks | Temporary mutations on `packages/health/evaluation.go` & `rules.go` | Verified tests fail immediately when ML05 gate checks, controller runtime check, 21d baseline sufficiency check, or `1h` staleness check are bypassed. |

## Explicit boundaries and open items

- **No SMART telemetry yet**: `device-audit.telemetry.v2` carries no SMART counters, so `PostgresRepository.EvaluateDeviceHealth` produces `unknown` (`insufficient_evidence`) with null probability and horizon until SMART collectors exist (`TEL01`/`TEL04`). Known-SMART end-to-end checks inject fixture readings at the test reader seam (`evaluateDeviceHealth`).
- **Unclassified persisted faults**: Persisted `log_references` carry no fault type in storage (`ML10`), so PostgreSQL fault history groups stored references under `unclassified`.
- **ML06 baseline failure**: The checked-in Backblaze baseline report failed ML05 precision and calibration gates, so controller inference remains fail-closed (`model_unavailable`) until an evaluated model passes `ml05.v1`.
- **Persistence and HTTP endpoints**: Storing prediction history and serving health endpoints belong to open downstream issue `#107` (ML11).
