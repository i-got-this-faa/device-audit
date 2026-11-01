# SEC02 #23 implementation and evidence

Implementation and qualification evidence for
[PR #195](https://github.com/i-got-this-faa/device-audit/pull/195), based on
main `5a79934`. Signing, networking and chain identities remain separate.

## Completion ledger

| Result | Source/runtime | Check | State | Evidence |
| --- | --- | --- | --- | --- |
| Distinct persistent signing/network identities | `apps/endpoint-agent/identity.go`, OS storage files | TLS enrollment plus fresh-process identity-status | proved on Linux | `TestEnrollmentAndProcessRestart` checks both proofs and unchanged key bytes |
| Damaged or unsafe storage fails closed | endpoint storage and tests | corruption, partial/missing keys, size, modes, links, concurrent lock | proved on Linux | focused package race tests |
| Secrets absent from routine output | redacted identity formatting and bounded generic transport errors | fresh-process output and formatting checks | proved for exercised paths | endpoint package tests; no real credential used |
| Windows DPAPI and ACL implementation | `storage_windows.go`, Windows-only tests | Native Windows CI plus test-binary cross-build | proved for CI account | Windows endpoint race tests passed on `712fa36`; physical LocalService qualification remains open |
| Real controller and database integration | endpoint client, existing enrollment handlers/repository | PostgreSQL-backed integration | proved on Linux | `TestEndpointEnrollmentPostgres`: actual TLS handlers, committed signing/network binding and fresh-process receipt |
| Whole-repository validation | existing Makefile | `make check cross-build` | proved | Vet, race suite, Python suite, fixture scenarios, formatting and both endpoint builds passed |
| LocalService restart on selected Windows laptop | selected Windows endpoint/service boundary | installed service with per-service SID | blocked | Host is currently Linux; native Windows is a separate installation; do not switch it automatically |

## Applicable paths

| Path | Applies | Reason and evidence |
| --- | --- | --- |
| Explicit enrollment and identity-status CLI | yes | Enrollment alone creates keys; status loads only. Existing fixture mode remains separately identified. |
| Windows provider | yes | DPAPI user scope, protected directory DACL, inherited file DACL, service SID under LocalService; native tests passed under the Windows CI account, not the physical LocalService token. |
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

## PR review follow-up

CodeRabbit completed review of `712fa36` with one valid finding. HTTP 5xx can
arrive after a controller commit, so the client now reports uncertain admission
and advises preserving identity and reconciling with the operator. Regression
tests cover 500/502/503/504, unchanged stored keys, no accepted receipt, and no
server-body or credential disclosure. HTTP 403 remains a definite rejection.

Both native Windows CI runs passed the endpoint package, including DPAPI/DACL
tests. One full Windows run failed the existing OIDC login/replay test at
`internal/controller/auth/auth_test.go:994`; the duplicate full Windows run
passed. No authentication code changes are included in this endpoint fix.
The follow-up push reruns CI and automated reviews on the new head.
