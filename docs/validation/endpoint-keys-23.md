# SEC02 #23 implementation and evidence

Work branch `feat/issue-23-endpoint-keys`, based on remote main
`5a79934`. Worktree `/tmp/device-audit-issue-23`. The original checkout's
uncommitted roadmap/source edits are preserved. The user authorized opening and
babysitting the PR on 1 November 2026, including scoped commits and pushes.
Merge, issue closure and unrelated project mutations remain unauthorized.

Hard constraints retained from repository and user instructions: keep unrelated
work; no commit unless requested and no push without permission; existing shared
wire contracts first; separate networking, signing and chain identities; never
disclose private material; no raw identifiers/logs on-chain; no unimplemented
production or patent claims; no MDM/configuration/deployment/shell-agent scope;
run `make check` and `make cross-build` for Go changes. No Python code is changed.

## Completion ledger

| Result | Source/runtime | Check | State | Evidence |
| --- | --- | --- | --- | --- |
| Distinct persistent signing/network identities | `apps/endpoint-agent/identity.go`, OS storage files | TLS enrollment plus fresh-process identity-status | proved on Linux | `TestEnrollmentAndProcessRestart` checks both proofs and unchanged key bytes |
| Damaged or unsafe storage fails closed | endpoint storage and tests | corruption, partial/missing keys, size, modes, links, concurrent lock | proved on Linux | focused package race tests |
| Secrets absent from routine output | redacted identity formatting and bounded generic transport errors | fresh-process output and formatting checks | proved for exercised paths | endpoint package tests; no real credential used |
| Windows DPAPI and ACL implementation | `storage_windows.go`, Windows-only tests | Windows test-binary cross-build | in progress | Native Windows run still required; cross-build is portability evidence only |
| Real controller and database integration | endpoint client, existing enrollment handlers/repository | PostgreSQL-backed integration | proved on Linux | `TestEndpointEnrollmentPostgres`: actual TLS handlers, committed signing/network binding and fresh-process receipt |
| Whole-repository validation | existing Makefile | `make check cross-build` | proved | Vet, race suite, Python suite, fixture scenarios, formatting and both endpoint builds passed |
| LocalService restart on selected Windows laptop | selected Windows endpoint/service boundary | installed service with per-service SID | blocked | Host is currently Linux; native Windows is a separate installation; do not switch it automatically |
| Reviewed PR merged | remote GitHub | review and merge | in progress | PR publication/babysitting authorized; merge not requested; issue remains open |

## Applicable paths

| Path | Applies | Reason and evidence |
| --- | --- | --- |
| Explicit enrollment and identity-status CLI | yes | Enrollment alone creates keys; status loads only. Existing fixture mode remains separately identified. |
| Windows provider | yes | DPAPI user scope, protected directory DACL, inherited file DACL, service SID under LocalService; native tests provided but not run here. |
| Linux/Darwin provider | development only | Restricted Unix files; Linux runtime tests and Darwin cross-build. No V1 support claim. |
| Bootstrap controller and contracts | yes, unchanged | Existing challenge/admission v1, Ed25519 canonicalization and NaCl sealed box. No wire change required. |
| Restart, corruption, unreadable state | yes | Fresh process, immutable files, bounded parsing, ownership/ACL validation and fail-closed errors. |
| Reverse action | separate work | No automatic deletion, rotation, recovery or de-admission is added. A consumed token or saved receipt is not revocation reconciliation. |
| HTTPS and failed/uncertain responses | yes | System/custom CA, TLS 1.3, no redirects/proxy/plaintext, wrong scope/proof rejection. |
| Offline mesh, relay, telemetry signing | no | Persisted network/application keys prepare identities; production transport/evidence submission remain #25/#24. |
| Console, model, chain | no | No endpoint secret is sent there and no behavior changes. |
| Operations and CI | yes | Endpoint README and controller enrollment docs; existing Windows workflow already runs all Go tests. |

## Final validation results

Passed on 1 November 2026, Linux amd64, Go 1.27.3:

- `TEST_DATABASE_URL=... make PYTHON=/tmp/device-audit-issue23-venv/bin/python check cross-build database-check contract-check`.
  The test database is a disposable local PostgreSQL 17.11 cluster, bound to
  loopback. Its development trust authentication is not a deployment model.
  The native endpoint test uses actual controller enrollment handlers and
  PostgreSQL migrations/repository. External administrator login is bypassed by
  authorized test token issuance. `database-check` now includes the endpoint
  package so CI cannot silently omit this integration.
- `make PYTHON=/tmp/device-audit-issue23-venv/bin/python check cross-build demo`,
  with the disposable database configured for integration tests. The default
  fixture demo still passes and explicitly reports in-memory/unknown-model state.
- Focused endpoint race tests, including rejected/lost/mismatched admission
  responses, unchanged keys on retries, pending-scope changes, corrupted receipt
  error redaction, damaged key storage, permissions, links and concurrent access.
- Windows amd64 and Darwin arm64 endpoint test-binary cross-compilation. These
  binaries were not executed on this Linux host.
- Contract conformance: 289 golden vectors, 71 wire cases and 25 reader versions.
- `git diff --check`; original checkout changes remain untouched.

The host's initial Python installation lacked the pinned RFC3339 validator and
produced four existing timestamp-related test failures. Installing the exact
`models/test-requirements.txt` dependencies in a disposable virtual environment
resolved them. No Python source, host package or dependency pin was changed.

Native Windows/LocalService/physical service restart,
power-loss durability, external IdP/bootstrap delivery, proxy deployment,
off-host recovery and remote review/merge remain untested. A protocol fixture,
development Unix process restart or Windows cross-build does not satisfy those
release gates. Issue #23 must not be marked Done from this record.

Next steps: publish and monitor the PR so native Windows CI can execute the
DPAPI/ACL tests, then qualify the selected physical Windows laptop under the
LocalService/per-service token with service registration work. Obtain the other
developer's review and merge before closing #23. No automatic OS switch or
service-account permission change has been attempted.
