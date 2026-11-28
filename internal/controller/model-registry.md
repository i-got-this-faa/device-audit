# Model artifact registry, FED07 #112

The controller keeps model artifacts in PostgreSQL
([migration 007](../../infra/database/migrations/007_model_registry.sql)) with
the [registry contract](../../packages/contracts/model-registry-v1.md).

## Enable it

```sh
controller --deployment-id <id> --database-url <url> <OIDC flags> \
  --model-publisher-key-file publisher.pub.pem
```

`publisher.pub.pem` is a PKIX PEM Ed25519 public key. Every uploaded manifest
must verify against it. It is not a device, mesh, TLS, acknowledgement or chain
key. The registry needs a deployment, a database and console authentication;
the controller refuses to start with the flag and without them. `/healthz`
reports `model_registry` as `configured` or `not_configured`.

## Routes

| Route | Role | Result |
| --- | --- | --- |
| `POST /console/api/models` | fresh admin | `201` stored, `200` identical repeat |
| `GET /console/api/models/{version}` | viewer | Entry with manifest, provenance and approval |
| `GET /console/api/models/{version}/artifact` | admin | Exact bytes with `Repr-Digest: sha-256=:…:` |
| `POST /console/api/models/{version}/evaluation` | fresh admin | `201` stored, `200` identical repeat |
| `GET /console/api/models/{version}/evaluation` | viewer | Verdict, reasons and metrics |
| `POST /console/api/models/{version}/promotion` | fresh admin | `201` decided, `200` identical repeat |
| `GET /console/api/models/{version}/promotion` | viewer | Decision, baseline and checks |
| `GET /console/api/model-references` | viewer | `active` and `candidate` slots |
| `PUT /console/api/model-references/{slot}` | fresh admin | Both slots after the change |

A fresh admin authenticated within five minutes; writes also need the console
Origin and CSRF token. A refusal body is the stable code from the contract.

| Status | Codes |
| --- | --- |
| 400 | `invalid_request`, `invalid_manifest`, `unsupported_manifest_version`, `unsupported_feature_version`, `feature_order_mismatch` |
| 403 | `key_mismatch`, `invalid_signature` (not the trusted publisher) |
| 409 | `version_conflict`, `reference_mismatch`, `not_approved`, `not_candidate` |
| 413 | `artifact_too_large` |
| 422 | `digest_mismatch`, `purpose_unsupported` |
| 500 | Stored bytes failed their digest check; they are not served |
| 503 | Database unavailable or commit uncertain; repeat the request |

## What the database enforces

- `model_artifacts`, `model_approvals`, `model_evaluations` and `model_promotions` refuse every `UPDATE` and `DELETE`.
- An approval needs a stored passing evaluation of the same artifact, so the
  active slot cannot name an unevaluated or failing model, even by direct SQL.
- The active slot has a foreign key to an approval of the same digest, so even
  a direct insert cannot make an unapproved artifact active.
- References are rows, so a restart reads the same slots. Nothing changes a
  slot on startup.

A download re-hashes the stored bytes and refuses them if they no longer match
the signed digest.

## Evaluation and promotion, FED10 #115

A candidate is promoted by evidence, in three steps.

1. **Stage.** Point the `candidate` slot at the stored artifact.
2. **Evaluate.** `POST /console/api/models/{version}/evaluation` (fresh admin)
   submits the ML05 held-out report for that exact artifact. The model
   publisher signs it: `signing_key_id` and `signature` cover the version, the
   artifact digest and the SHA-256 of the report bytes, so a console session
   alone cannot supply evidence. The controller reads the report itself and
   stores a `pass`, `fail` or `blocked` verdict with reason codes; it never
   trusts the verdict inside the report. A candidate has one evaluation,
   because the held-out partition is scored once per candidate: a different
   report for the same version is `version_conflict`, and a report naming
   another model is `reference_mismatch` and stores nothing.
   `GET .../evaluation` (viewer) returns the verdict, reasons and metrics.
3. **Promote.** `POST /console/api/models/{version}/promotion` (fresh admin)
   cites the artifact and evaluation digests. In one transaction the controller
   applies the frozen ML05 gates and the [FED10 regression gates](../../models/evaluation/promotion-policy.json)
   against the model active now, then records one immutable decision.
   `promoted` writes the approval and the `active` slot together. `rejected`
   leaves `active` untouched. Both clear the candidate slot. Only the model in
   the candidate slot can be promoted (`not_candidate`). `GET .../promotion`
   (viewer) returns the decision, reasons, baseline and per-gate checks.

| Situation | Decision |
| --- | --- |
| Metrics miss an ML05 threshold, such as calibration | `rejected`, `evaluation_fail` and `gate_failed:<id>` |
| Missing counts or metrics, too little evidence, interrupted or reused evaluation | `rejected`, `evaluation_blocked` and the reasons |
| Candidate is worse than the active model beyond a frozen tolerance | `rejected`, `regression:<gate>` |
| Active model has no stored evaluation, or scored other examples | `rejected`, `baseline_not_comparable` |
| Candidate does not declare the `inference` purpose | `rejected`, `purpose_unsupported` |
| No model is active | ML05 gates alone decide |

A decision is final. Repeating the same request returns it; citing other
evidence afterwards is `version_conflict`. Successful aggregation alone never
promotes: it creates an unapproved candidate. `PostgresRepository` implements
`EvaluationReportStore`, so the health path can reload exactly the report a
promotion judged.
