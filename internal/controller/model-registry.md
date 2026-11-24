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
| `POST /console/api/models/{version}/approval` | fresh admin | `201` approved, `200` identical repeat |
| `GET /console/api/model-references` | viewer | `active` and `candidate` slots |
| `PUT /console/api/model-references/{slot}` | fresh admin | Both slots after the change |

A fresh admin authenticated within five minutes; writes also need the console
Origin and CSRF token. A refusal body is the stable code from the contract.

| Status | Codes |
| --- | --- |
| 400 | `invalid_request`, `invalid_manifest`, `unsupported_manifest_version`, `unsupported_feature_version`, `feature_order_mismatch` |
| 403 | `key_mismatch`, `invalid_signature` (not the trusted publisher) |
| 409 | `version_conflict`, `reference_mismatch`, `not_approved` |
| 413 | `artifact_too_large` |
| 422 | `digest_mismatch`, `purpose_unsupported` |
| 500 | Stored bytes failed their digest check; they are not served |
| 503 | Database unavailable or commit uncertain; repeat the request |

## What the database enforces

- `model_artifacts` and `model_approvals` refuse every `UPDATE` and `DELETE`.
- The active slot has a foreign key to an approval of the same digest, so even
  a direct insert cannot make an unapproved artifact active.
- References are rows, so a restart reads the same slots. Nothing changes a
  slot on startup.

A download re-hashes the stored bytes and refuses them if they no longer match
the signed digest.
