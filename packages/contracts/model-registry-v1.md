# Model artifact registry v1, FED07 #112

[`model_registry_v1.go`](model_registry_v1.go) defines what the controller's
model registry accepts and returns. It builds on the
[model manifest](model-manifest-v1.md): the registry stores a signed manifest
and the exact artifact bytes, and never stores an artifact whose manifest it
cannot verify. These types are Go only. There is no JSON Schema or Python
reader yet, because the only consumer is the controller's console API.

## Namespaces

| Namespace | Direction | Purpose |
| --- | --- | --- |
| `device-audit.model-artifact-upload.v1` | request | Signed manifest, artifact bytes (base64 in JSON) and an opaque `source_reference`. |
| `device-audit.model-artifact.v1` | response | One stored entry: manifest, byte size, source reference, upload time and uploader, and the approval or null. |
| `device-audit.model-evaluation-submission.v1` | request | One ML05 held-out report (base64) for a stored artifact, signed by the model publisher over the version, artifact digest and report digest. |
| `device-audit.model-evaluation.v1` | response | The controller's `pass`, `fail` or `blocked` verdict with reason codes and the report's metric intervals (null when the report was unreadable). |
| `device-audit.model-promotion-request.v1` | request | Asks for a decision on one candidate, citing its artifact and evaluation digests. It carries no verdict. |
| `device-audit.model-promotion.v1` | response | The immutable `promoted` or `rejected` decision: reasons, the active baseline it was compared with (or null), each regression check, time and actor. |
| `device-audit.model-reference-request.v1` | request | Points the `active` or `candidate` slot at one stored version and its digest. |
| `device-audit.model-references.v1` | response | Both slots. A null slot names no model; there is no fallback. |

Requests reject unknown, duplicate, missing and null fields. The controller
assigns every time, the deployment and the actor; a request cannot set them.

## Upload checks

`ModelArtifactUploadV1.Verify` runs in this order and returns one stable code.

| Order | Code | Cause |
| ---: | --- | --- |
| 1 | `invalid_request` | Wrong `schema_version` or malformed `source_reference`. |
| 2 | manifest codes 1–4 | `Validate` of the [manifest](model-manifest-v1.md#activation-check): version, shape, feature version and order. |
| 3 | `key_mismatch`, `invalid_signature` | The manifest does not verify against the publisher key configured on the controller. A key named by the manifest is never trusted. |
| 4 | `invalid_request` | Empty artifact. |
| 5 | `artifact_too_large` | More than 16 MiB, the ML05 #86 inference artifact budget. |
| 6 | `digest_mismatch` | SHA-256 of the bytes differs from the signed `artifact_sha256`. |

The registry does not run the runtime and architecture steps of
`CheckActivation`. It records them; the process that loads the artifact checks
them against itself.

## Registry rules

- **Immutable.** A version and its bytes are stored once. A repeat of the same
  manifest and bytes returns the stored entry. Any other upload of a stored
  version, or of stored bytes under another version, is `version_conflict`.
- **Approval.** One approval per artifact, bound to its digest. It exists only
  as the result of a promotion from a stored passing evaluation (FED10 #115);
  there is no request to approve a model. A digest that is not the stored one
  is `reference_mismatch`.
- **Evaluation and promotion.** One evaluation per candidate version, signed by
  the publisher and read by the controller. One decision per candidate:
  `promoted` or `rejected`, immutable. A repeat returns the stored record;
  other evidence afterwards is `version_conflict`.
- **Active.** Only an approved artifact that declares `inference` can be active:
  otherwise `not_approved` or `purpose_unsupported`. Activating the candidate
  clears the candidate slot.
- **Candidate.** Any stored artifact. It needs no approval and is never served
  as the active model.

The approval request is the seam for FED10 #115, which must decide promotion
from held-out evaluation. Until then an administrator records it and cites the
evaluation digest. The registry does not read or check the evaluation.

## Not claimed

Nothing here selects who holds the publisher key, rotates or revokes it, or
revokes an approved artifact. There is no reference history beyond the current
actor and time of each slot, no endpoint download over the mesh, and no
rollback rule other than activating another approved version.
