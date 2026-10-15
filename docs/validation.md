# Initial scaffold validation

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
Mesh, database migrations, bespoke trained models, full federated coordination,
smart-contract transactions and patent conformance have not been validated.
CI is configured to repeat the available checks; this record describes the
local run, not a claim about a hosted CI result.

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
Go validation remains authoritative at ingestion. This is telemetry-only
coverage of #80. Signature canonicalization, replay classifications and the
other application contracts remain outstanding. No production collector,
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
before consumers. #17 controller/fake-server behavior, the in-progress #80 harness,
issue metadata and runtime routes are unchanged. No production or patent
verification claim follows; #14 and the original PDF remain unresolved.
