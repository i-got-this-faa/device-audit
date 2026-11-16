# NET02 #25 admitted mesh adapter evidence

Acceptance evidence for [issue #25](https://github.com/i-got-this-faa/device-audit/issues/25).
The merged implementation is PR #197. This record adds the Windows controller
state store and separates what was executed here from qualification that this
environment cannot perform.

## Acceptance criteria

| Criterion | Result | Evidence |
| --- | --- | --- |
| Persisted admitted client and server sessions on the pinned Tailcat API | Implemented | `networking/mesh` replaces the old unimplemented constructors. The controller loads a persisted node key and PSK. The endpoint imports its existing protected X25519 key and does not create a second transport identity. |
| Direct transport accepts an admitted peer and rejects an unknown peer after restart | Exercised on Linux in this workspace | `TestPersistedAdmittedDirectTransport` starts separate Tailcat processes, checks direct UDP and peer-bound HTTP, restarts both sides on the same server state, and rejects an unknown key before and after restart. The test file is Linux/Darwin. |
| Application APIs use the mesh; bootstrap and administrator HTTPS stay separate | Implemented and covered by existing handler tests | Mesh HTTP exposes `POST /v1/evidence` only. The public listener in mesh mode omits fixture ingestion, device reads and the evidence route. PostgreSQL admission is checked before the tunnel session and again on the request. Signature, sequence and revocation checks stay in the evidence transaction. |

HTTP 204 remains a commit result. It is not a CT04 signed acknowledgement. That
work stays with #89.

## Controller state on Windows

Unix state remains owner mode 0700/0600, `flock`, and directory fsync.
Windows state is the same JSON document under a protected DACL for the current
user, or for an enabled per-service SID when the token is LocalService.
LocalService without that SID fails closed. The node key and PSK are not
DPAPI-encrypted. Windows flushes the state file and has no directory fsync.
An existing directory with any other ACL is rejected rather than repaired.

`TestPersistedServerState` reloads the public key, rejects a second owner, a
changed address and corrupt state on whichever store the host provides.
`TestWindowsMeshStateRejectsUnprotectedDirectory` and
`TestWindowsMeshStateRejectsBroadACL` run only on Windows. This Linux workspace
compiled those tests with `GOOS=windows` and did not execute them. The
repository Windows CI job runs `tools/check-windows.ps1`, which includes
`go test -race ./...`.

The selected physical laptop, an installed LocalService token, NAT/WAN, a
deployed DERP host and an external IdP were not available here and are not
qualified by those tests.

## Commands run for this continuation

Passed on 16 November 2026 in this Linux amd64 workspace, Go 1.27.1:

- `make PYTHON=/tmp/device-audit-venv/bin/python check cross-build`. The
  virtualenv used `models/test-requirements.txt`. This included `go vet`,
  `go test -race ./...` (mesh package 17.390s, including direct UDP restart and
  `TestPersistedServerState`), 32 model tests, the fake-controller scenarios,
  formatting, and Windows amd64 / Darwin arm64 endpoint builds.
- `TEST_DATABASE_URL` pointed at a disposable local PostgreSQL 16.15 cluster on
  loopback with trust authentication for that temporary cluster.
  `make database-check` passed, including `TestEndpointEnrollmentPostgres` and
  its fresh-process Tailcat request before and after mesh restart.
- `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go test -c` compiled
  `./networking/mesh` and `./apps/endpoint-agent`. Those binaries were not
  executed here.
- `git diff --check` passed.

The Windows ACL tests are part of `tools/check-windows.ps1` through
`go test -race ./...`. Their result is whatever that CI job reports for the
pull request. A successful compile on Linux is not that result.

No production, patent, prediction or privacy claim follows from this record.
