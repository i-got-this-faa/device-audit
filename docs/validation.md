# Initial scaffold validation

Follow-up: [Windows sensor and native-check evidence, 19 October 2026](validation/windows-2026-10-19.md)
records real development sensor measurements, probe cost, repeated native checks
and the remaining two-machine/service/runtime gates.

Follow-up: [Windows development-machine evidence, 14 October 2026](validation/windows-2026-10-14.md)
records native Windows execution, available hardware and remaining qualification gates.

Local run on 2026-10-13 with Go 1.27.1 on Linux amd64 and Python 3.12.3:

```text
make check cross-build demo
go vet ./...                          PASS
go test -race ./...                   PASS
Python weighted aggregation tests    PASS (2 tests)
Go formatting check                  PASS
Windows amd64 endpoint build         PASS
macOS arm64 endpoint build           PASS
Controller + endpoint binary demo    PASS
```

The demo launched the actual Go binaries, submitted fixture telemetry, retrieved
the stored device record, and checked matching evidence digests, fixture
provenance and unknown health. The controller was shut down afterward.

HTTP tests cover telemetry round-trip, missing sensor semantics, malformed or
out-of-range inputs, trailing JSON and bounded device storage. Transport tests
reject non-loopback development binding and ensure mesh constructors return an
explicit error. Aggregation tests cover sample weighting and invalid base
versions, dimensions, counts and nonfinite weights.

Cross-compilation is not evidence of a real Windows/macOS collector or service.
Mesh, durable telemetry, real-IdP authentication, bespoke trained models, full
federated coordination, smart-contract transactions and patent conformance have
not been validated. CI is configured to repeat the available checks; this record
describes the local run, not a claim about a hosted CI result.

## Telemetry conformance subset of #80

Validated locally on 2026-10-13 with Go 1.27.1 and Python 3.13. Go, make and
GCC were supplied by an ephemeral Nix shell; pinned Python test dependencies
were installed in a temporary virtual environment.

```sh
nix shell nixpkgs#go nixpkgs#gnumake nixpkgs#gcc --command \
  make check cross-build demo PYTHON=/tmp/device-audit-contract-check/bin/python
```

All checks passed: Go vet, race tests, formatting, Python model/schema tests,
Windows amd64 and macOS arm64 endpoint builds, and the actual fixture binary
round-trip demo. Dependency consistency and `git diff --check` also passed.

Go decoding/validation and Python Draft 2020-12 JSON Schema validation consume
the same 21 telemetry vectors, four valid and 17 invalid. They cover nullable
and omitted sensors, explicit units in metric names, numeric boundaries,
required fields, unknown fields, versions, source labels and timestamps.
The suite exposed a schema regex accepting device IDs with a terminal newline;
the schema now rejects them consistently with Go. Date-time format checking
requires the pinned RFC 3339 validator dependency.

Go-only regressions cover two spellings of the zero time instant. JSON Schema
checks timestamp syntax and still accepts those syntactically valid dates;
Go validation remains authoritative at ingestion. This records the telemetry-only
subset of #80 on that date. The shared conformance command described below now
adds signature canonicalization, replay classifications and other contracts. No production collector,
patent conformance or hosted CI result is asserted by these checks.

## Provisional telemetry/inventory v2, #15

The same local command above passed after the separate v2 contract was added:
Go vet/race/format checks, four Python tests, Windows/macOS endpoint builds,
and the actual v1 fixture binary demo. The 22 shared v2 vectors include two
valid examples and 20 invalid examples. They exercise units, missing reasons,
null/missing/nested fields, Unicode metadata lengths, collection/byte bounds,
version rejection, exact property spellings and fixture versus endpoint source labels. Go-only tests
check log-window ordering, direct DTO construction and metric decode reuse.

The v2 contract is a platform-neutral proposal. It is not bound to the
controller or an actual collector. JSON Schema does not enforce timestamp
ordering or Go's zero-instant policy. Release scope from #14 and the patent
PDF remain unresolved; #15's merged-PR definition of done is outstanding.

## Provisional prediction/forecast v2, #16

Validated locally on 2026-10-14 with Go 1.27.1 and Python 3.13.15 using the
Nix shell and temporary Python test environment described above. The same
`make check cross-build demo` command passed: Go vet/race/format checks, five
Python tests, Windows/macOS endpoint builds, and the actual v1 binary fixture
round trip. `git diff --check` also passed.

Go and Python JSON Schema validation share 39 prediction vectors, seven valid
and 32 invalid. Coverage includes unknown null risk versus known zero risk,
model/evidence/version references, units, horizons, bounded forecasts, exact
field spellings, null/missing fields, Unicode version lengths and identifier/
digest boundaries. Go tests also verify direct construction, serialization,
decode reuse, timestamp ordering, zero timestamps and the exact expiry boundary
using a supplied clock.

These are illustrative wire-contract examples. No trained model or runtime
prediction path is supplied. Portable JSON Schema checks date-time syntax;
Go also rejects zero instants and non-increasing validity windows. Dataset and
horizon selection, health thresholds, release scope and the patent PDF remain
unresolved. #16's merged-PR definition of done remains outstanding.

## Provisional signed envelopes v1, #75

Validated locally on 2026-10-15 in the separate `issue-75-envelopes` worktree,
based on `f1615d8`, with Go 1.27.1 on Linux amd64 and Python 3.13.15. The
installed Nix Go launcher resolved the module's requested toolchain. Existing
pinned Python test dependencies were installed in a temporary virtual environment;
no repository dependency was added. The final check command was:

```sh
/nix/store/c011mk580m964s1zxjccvdax3fcmppnl-gnumake-4.4.1/bin/make \
  check cross-build \
  GO=/nix/store/h3rc4y3szd0391wryw9hslrijdvni030-go-1.26.8/share/go/bin/go \
  PYTHON=/tmp/device-audit-75-python/venv/bin/python \
  CC=/nix/store/79mr0jw3qccq7hhf1hh62knxd88dwazc-gcc-wrapper-15.3.0/bin/gcc
```

Go vet, all Go race tests, formatting, all 22 Python tests on the stacked
worktree through `model-check`, Windows amd64 and macOS arm64 endpoint builds
passed. Python dependency consistency and `git diff --check` passed.
Regenerating the vectors with
`go run packages/contracts/fixtures/envelopes/generate.go` produced identical
bytes.

The 61 shared vectors include 36 structurally/semantically valid envelopes and
25 invalid envelopes. Valid structure does not mean an accepted request. The
signed evidence vectors also cover missing and null telemetry log byte sizes;
both fail Go, JSON Schema and Python validation. Go
checks real Ed25519 signatures against fixed public RFC 8032 test keys; Python's
test reader independently checks schemas, semantic invariants, canonical bytes,
request fingerprints, acknowledgement correlation and pure freshness outcomes.
Python does not verify signatures. Coverage includes wrong keys, changed signing
fields, altered payloads with stale/recomputed digests, explicit signed rejection
reasons, consumed sequences, supplied restart high-water marks, exact expiry/skew
boundaries, sequence gaps and limits, null versus known-zero marks, and missing
or inconsistent acknowledgement fields.

Go also checks strict JSON/duplicate rejection, payload size and UTF-8 boundaries,
wrong signers and domains, unsigned construction, rejection correlation for an
invalid body, invalid receiver clocks/state and decode reuse. Python independently
rejects duplicate keys, trailing JSON and noninteger sequence tokens. Binding
conflicts and challenge admission remain documented provisional classifications;
the validators neither decide admission nor mutate state.

This is component-level contract evidence. Restart inputs in fixtures do not
prove real durable restart/restore, concurrency, enrollment, authenticated mesh
traffic or key storage. Another owner's sequence/restart review is still required
before consumers. #17 controller/fake-server behavior, issue metadata and runtime
routes were unchanged by #75; #80's conformance evidence follows below. No production or patent
verification claim follows. #14 remains open; SRC05 #72 records the supplied
PDF reconciliation separately from implementation and legal coverage.


## Shared contract conformance, CT05 #80

Validated locally on 2026-10-19 in the #80 worktree based on the #174 stack head.
The parent Projects flake supplies Go 1.27.1, Python 3.13.15, jsonschema 4.26.0,
Make and the C toolchain. CI separately installs the repository-pinned Python
test requirements; local results do not assert a hosted CI outcome.

```sh
nix develop /home/cier/Projects --command make contract-check check cross-build demo
```

The command passed 240 shared golden vectors, 52 raw-wire cases and all 16 reader
versions. Full Go vet/race/format checks and 29 Python tests passed, as did the
Windows amd64/macOS arm64 cross-builds and actual endpoint-fixture/controller
round trip. Regenerating the envelope and derived wire fixtures produced identical
bytes. The report under `artifacts/contracts/conformance-v1-report.json` records
fixture/schema hashes, tool versions and verified classifications.

Negative command tests deliberately substitute semantic validity for schema
expectations and declare a Go reader that does not run. Both fail with the
expected diagnostic and remove a pre-existing passing report. Incompatible
versions, null measurements, duplicate keys, fractional sequence tokens,
signature framing, exact expiry and replay-after-restart/lost-response examples
are covered by shared fixture cases.

[The harness specification](../packages/contracts/conformance-v1.md) defines the
reader limits. Python does not authenticate signatures, and prediction/lifecycle
schema readers do not reproduce all Go semantics. Replay clocks and durable marks
are fixture inputs, not real persisted/restarted services. Both owners' fixture
review remains required before dependent implementations merge. No live collector,
authorization, database, training, chain or patent capability is established.

## Independent controller fake, TST01 #17

Validated locally on 2026-10-21 with Go 1.27.1 on Linux amd64. The command below
uses the public envelope vectors and fixed fixture clock; the CI workflow runs
the same suite and stores its JSON report as the `controller-fixture` artifact.

```sh
nix develop /home/cier/Projects --command make fake-check
```

The four scenarios passed: enrollment assignment (sequences 1 and 2), inclusive
`expired` rejection, unreachable-controller failure with no acknowledgement, and
`replay` rejection with an unchanged sequence-2 mark. The client verified each
controller acknowledgement signature and contract before accepting the result.

This is fixture evidence only. The fake stores identities and sequence marks in
memory, accepts only public RFC 8032 test keys, issues no enrollment challenge
and implements no production admission, concurrency or restart durability.

## Review follow-up for #178

On 2026-10-22 both review findings reproduced before the fixes: the fixture CLI
failed to serve a loopback host:port, and a correctly signed enrollment with a
non-fixture key was accepted. Regression tests now exercise the compiled CLI's
health route, reject non-literal/non-loopback listeners, and verify rejection of
non-fixture keys without consuming device, sequence or challenge state.

`nix develop --command make check cross-build replay-check` passed after rebasing
onto main. The conflict resolution retains both controller-fixture and
endpoint-replay commands and documentation.

## PostgreSQL binding and migrations, DB01 #19

Validated locally on 2026-10-21 with Go 1.27.1 and PostgreSQL 17.11 on Linux
amd64. A disposable local cluster used trust authentication on port 55432; the
same target is configured in CI against a PostgreSQL 17 service.

```sh
TEST_DATABASE_URL='postgres://deviceaudit@127.0.0.1:55432/device_audit_test?sslmode=disable' \
  make database-check
```

The tests passed for a fresh schema and idempotent restart, a prior-schema
upgrade that retained rows, concurrent migration attempts that produced one
ledger row per applied migration, and an injected syntax-error migration that
left version 1 applied with no half-written table. Controller startup tests
confirmed that an unavailable database and a changed migration-ledger name both
abort before a listener opens, while a successful run reports
`database=connected` and `schema_version=2`.

This evidence covers schema application only. Telemetry, enrollment
and replay state are still memory-only; backup/restore, database outage
behavior for writes, retention, TLS and least-privilege roles remain untested.

## Review follow-up for #179

On 2026-10-22 a compiled-controller regression test reproduced disclosure of a
synthetic database password in both help and malformed-argument usage output.
The flag now registers an empty default and resolves its environment fallback
after parsing. Tests also verify that an explicitly empty database URL disables
that fallback. `nix develop --command make check cross-build database-check`
passed with `TEST_DATABASE_URL` pointing to a disposable PostgreSQL 17.11 cluster.

## Administrative authentication, SEC06 #82

Validated locally on 2026-10-21 with Go 1.27.1 on Linux amd64 and PostgreSQL
17.11. The same disposable cluster and `TEST_DATABASE_URL` used for #19 were
used here. The full check command was:

```sh
nix develop /home/cier/Projects --command make check cross-build demo
TEST_DATABASE_URL='postgres://deviceaudit@127.0.0.1:55432/device_audit_test?sslmode=disable' \
  nix develop /home/cier/Projects --command make database-check
```

The HTTP suite uses a temporary TLS OIDC issuer and the auth service's
in-memory test store. It passed the full authorization-code login exchange with
PKCE S256, state and nonce checks, MFA `amr` enforcement, cookie attributes,
viewer/admin scope, forged identity and device headers, CSRF and exact Origin
checks, logout replay, 15-minute idle and eight-hour absolute expiry, role-change
revocation, fresh-authentication rejection for stale/future `auth_time`,
last-admin rejection, store outage, IdP outage, expired and replayed
login transactions, and secret-free logs. A deliberately invalid token-exchange
code confirmed that provider error bodies are not copied into logs.

The PostgreSQL lifecycle test applied schema version 2 and passed binding
creation/update, one-use and expired login transactions, session touch/revoke,
subject-session revocation, idle-expiry touch rejection, role-change revocation
that survives a role cycle, and a closed-store failure. Controller startup tests
reported `auth=oidc`, preprovisioned the bootstrap admin, rejected incomplete
auth configuration and missing database/admin bindings before listening, and
served an anonymous console redirect without protected data.

These are component and local integration results. The fake issuer is not a
real identity provider, and no browser was run. Provider-specific `amr`/`acr`
mapping, durable audit events, IdP single logout/back-channel revocation, rate
limiting, expired-row cleanup and production secret custody remain untested or
unimplemented. No production identity, telemetry durability, enrollment or
release qualification is established.

## Review follow-up for #183

On 2026-10-22 regression tests reproduced OIDC client-secret disclosure in help
and malformed-argument output. A separate test reproduced an old-issuer admin
session reading protected routes and creating an admin binding for a replacement
issuer. The fixes resolve the secret fallback after flag parsing and reject and
revoke issuer-mismatched sessions before authorization. Tests verify that
explicitly empty secrets override the environment and that restoring the old
issuer does not revive a denied session.

With Go 1.27.3 and disposable PostgreSQL 17.11, the following passed:

```sh
TEST_DATABASE_URL='postgres://deviceaudit@127.0.0.1:55432/postgres?sslmode=disable' \
  nix develop --command make check cross-build database-check replay-check demo
```

This remains local component/integration evidence with a fixture IdP. A real
issuer migration, browser matrix and production secret custody remain unqualified.

## Inventory revisions, API03 #97, 27 October 2026

On Linux amd64 with Go 1.27.1, Python 3.13.15 and disposable PostgreSQL 17.11,
`make check cross-build database-check` passed with `TEST_DATABASE_URL` pointing
at the disposable cluster. `make contract-check` passed with 289 golden vectors,
71 wire cases and 25 reader versions after the inventory contract addition.

Real PostgreSQL tests verified revision history and clearing unknown metadata,
enrollment/actor/source provenance, reopen persistence, independent concurrent
writers with one conflict, deferred commit rollback, storage outages, unknown and
revoked-device rejection, fresh-admin/role/Origin/CSRF denials, strict bounded
updates and exact historical queries. They use synthetic identities and sessions;
they do not qualify a production IdP, physical component identity, off-host
backup recovery, cohort analytics or inventory tamper resistance.

## Console shell, WEB01 #29, 27 October 2026

Local Linux amd64 validation passed with Go 1.27.1, Python 3.13.15, Node
22.23.3, Chromium 155.0.8059.84 and disposable PostgreSQL 17.11:

```sh
TEST_DATABASE_URL='postgres://audit_test@127.0.0.1:55439/postgres?sslmode=disable' \
BROWSER_PATH=/run/current-system/sw/bin/chromium \
nix develop /home/cier/Projects --command \
  make check cross-build contract-check database-check browser-check
```

The browser suite drove the actual embedded shell and auth routes with a fake
TLS OIDC issuer and in-memory test sessions. It passed anonymous direct navigation,
exact return paths, real OIDC/PKCE exchange, viewer denial without protected
bindings, administrator navigation, 320-pixel navigation with no horizontal
overflow, keyboard skip/focus, server-expired session rejection, unknown-account
rejection, logout with actual browser Origin, browser Back after logout,
auth-store outage, the local expiry timer and navigation/logout without
JavaScript. Browser JavaScript reported no uncaught errors. Desktop device and
narrow workflow screenshots in `artifacts/console/` were visually inspected.

The first browser run reproduced a real logout defect: `no-referrer` caused
`Origin: null`, which correctly failed CSRF/Origin authorization. Changing only
the rendered page policy to `strict-origin` preserved Origin, omitted URL paths
and queries, and passed the same form-logout regression. No Origin relaxation
or CSRF bypass was added.

The shared T3 browser could not inspect the self-signed fixture: navigation
returned `ERR_CERT_AUTHORITY_INVALID`, and two snapshots timed out. The isolated
Chromium test context ignored certificates for its disposable loopback fixture.
The browser did not use a real IdP, deployed TLS proxy, production PostgreSQL
sessions or physical endpoint. Edge, Firefox, previous stable browsers, native
200% zoom and assistive-technology checks were not run. The workflow now runs
`browser-check` and uploads screenshots, but no remote CI result is claimed.
Reviewed PRs, shared-owner review and merge remain outstanding for issue closure.
