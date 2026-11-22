# Model artifact manifest v1, CT10 #101

`device-audit.model-manifest.v1` is what a model artifact must declare, and what
the activating process must check, before an endpoint loads it for inference or
a trainer loads it as a base. Go is [`model_manifest_v1.go`](model_manifest_v1.go);
Python is [`models/src/device_audit_models/manifest.py`](../../models/src/device_audit_models/manifest.py).
They were written separately and share
[`fixtures/models/v1-vectors.json`](fixtures/models/v1-vectors.json).

No model architecture is selected yet (see `docs/decisions.md`). The manifest
therefore names an architecture as an opaque identifier and does not describe
weights. The artifact stays opaque bytes; its digest is the only link.

## Manifest

```json
{
  "schema_version": "device-audit.model-manifest.v1",
  "model_version": "synthetic.1",
  "artifact_sha256": "<64 lowercase hex>",
  "architecture": "synthetic.v1",
  "parameter_count": 6,
  "runtime_name": "device-audit-runtime",
  "runtime_version": "1.0.0",
  "feature_version": "hdd-smart-7d.v1",
  "features": ["smart_5_raw.last", "smart_5_raw.delta", "..."],
  "purposes": ["inference", "training"],
  "signing_key_id": "ed25519:<64 lowercase hex>",
  "signature": "<128 lowercase hex>"
}
```

| Field | Rule |
| --- | --- |
| `model_version` | Opaque application ID. The same string federated rounds call `base_model_version`, and prediction v2 calls the model version. |
| `artifact_sha256` | SHA-256 of the exact artifact bytes. Same value as `base_model_sha256` in a round and the artifact digest in a prediction. |
| `architecture` | Opaque ID of the model family and layout. The runtime lists the architectures it implements. |
| `parameter_count` | 1..4096, the bound federated rounds already use. |
| `runtime_name`, `runtime_version` | The one runtime that may load the artifact. Compared exactly. There is no range, newer-is-compatible rule or fallback. |
| `feature_version`, `features` | The [frozen feature version](features-v1.md) and its output names in the frozen order. The reader derives the expected list from the version; it never takes it from the manifest. |
| `purposes` | `inference` and/or `training`, each at most once. A manifest that omits `training` cannot be a federated base. |
| `signing_key_id`, `signature` | Ed25519 over the signing bytes below, by the model publisher's key. |

Learned scaling or other normalization belongs inside the artifact. Only the
unfitted `log1p` transform is in the feature contract, so training and
inference share it without scaler state.

## Signature

The signed bytes use the application signing format of
[envelopes](envelopes-v1.md): the domain `device-audit/signature/v1` and NUL,
then each field as a big-endian `uint32` byte length and its UTF-8 bytes, in the
order `schema_version`, `model_version`, `artifact_sha256`, `architecture`,
decimal `parameter_count`, `runtime_name`, `runtime_version`, `feature_version`,
`signing_key_id`, the decimal feature count and each feature name, the decimal
purpose count and each purpose. Counts keep a list entry from shifting a boundary.
The first field already separates this message from every other signed record.

The publisher key is a trust root configured on the activating process. The
process passes it in; a key named by the manifest is never trusted. It is not a
device signing key, a network (Tailcat/WireGuard) key or a chain key. This
contract does not say who holds the publisher key or how it rotates or is revoked.

## Activation check

`CheckActivation` in Go and `check_compatibility` in Python refuse in this order
and return one stable code. Nothing is loaded until it returns nil.

| Order | Code | Cause |
| ---: | --- | --- |
| 1 | `unsupported_manifest_version` | `schema_version` is not `device-audit.model-manifest.v1`. |
| 2 | `invalid_manifest` | Missing, extra, null or malformed field, a duplicate or unknown purpose, or a malformed signature. |
| 3 | `unsupported_feature_version` | A well-formed feature version this reader does not implement. |
| 4 | `feature_order_mismatch` | `features` is not exactly the frozen list for the version: reordered, missing or extra. |
| 5 | `key_mismatch`, `invalid_signature` | The trusted key is not the one named by `signing_key_id`, or the signature does not verify. |
| 6 | `runtime_mismatch` | Runtime name or version differs from the manifest. |
| 7 | `unsupported_architecture` | The runtime does not list `architecture`. |
| 8 | `purpose_unsupported` | The manifest does not declare the requested purpose. |
| 9 | `digest_mismatch` | SHA-256 of the artifact differs from `artifact_sha256`, including an empty artifact. |

The artifact is hashed last, after the manifest is authenticated. The signature
covers the digest, so a changed artifact or a changed digest both fail.

Python takes no cryptography dependency. `check_compatibility` skips step 5 and
`signing_bytes` returns the bytes a caller must verify. A Python caller that
activates a model must verify the signature itself first.

## Evidence

[`generate.go`](fixtures/models/generate.go) signs 25 vectors with public RFC 8032
test seeds. Each carries the expected rejection code, so a vector cannot pass
for the wrong reason, and a signed vector isolates one defect: the swapped,
reversed, missing and extra feature lists and the unsupported feature version all
carry valid signatures. Vectors also cover runtime name and version mismatch, an
unsupported architecture, a purpose the manifest lacks, a modified or empty
artifact, a field changed after signing, an untrusted key, malformed digest,
signature, parameter count and purposes, and a manifest that smuggles raw weights.

```sh
go run packages/contracts/fixtures/models/generate.go
python3 tools/generate_contract_wire_vectors.py
make contract-check check
```

`TestModelManifestSignatureCoversEveryField` changes each signed field in turn.

## Not claimed

The manifest does not select an architecture, produce a model or qualify a
runtime. The fixture artifact is synthetic bytes, not a trained model. Nothing
here tracks which manifest is active, rolls back, expires or revokes a manifest;
a consumer needs that state before it can refuse a replayed older manifest. The
publisher key has no issuer yet. Another owner reviews these vectors before a
consumer (#102, #105, a trainer or a promotion service) merges.
