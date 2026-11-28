# Approved model download, FED04 #44

These read-only routes are served on the authenticated device mesh. Both
requests require a currently admitted peer, and the controller resolves the
deployment from that binding. Replies use `Cache-Control: no-store`.

- `GET /v1/models/active` returns
  [model-download.v1 metadata](fixtures/models/download-v1.json) as JSON.
  A nonempty active slot, matching approval and passing evaluation must exist
  in the deployment. Its metadata includes the deployment ID, the signed
  [CT10 manifest](model-manifest-v1.md), the exact byte count (1 through
  16 MiB), and the approval's evaluation SHA-256. Every field is required.
  Missing, null, unknown and duplicate fields are rejected.
- `GET /v1/models/active/artifact/{sha256}` returns the exact bytes as
  `application/octet-stream`. The lowercase SHA-256 must still identify
  the approved artifact in the active slot when the controller reads it.
  The response has a full `Content-Length`. Clients restart interrupted
  downloads from metadata.

Both routes return 403 for denied admission, 404 for an unavailable active
artifact or a digest that no longer matches it, 400 for malformed requests,
500 for corrupt registry data and 503 for unavailable registry storage.
Candidate artifacts have no mesh download route.

The authenticated mesh controller is the source of deployment and approval
metadata. The separately pinned publisher key authenticates the CT10 manifest,
whose signed digest binds the artifact bytes. Clients check deployment,
signature, purpose, feature order and runtime compatibility before requesting
the bytes and check byte count and digest before staging.
