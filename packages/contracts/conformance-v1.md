# Shared contract conformance, CT05 #80

Run the same versioned fixtures through the existing Go contract validators,
JSON Schemas and test-only Python readers with:

```sh
make contract-check
```

CI runs that exact command after installing `models/test-requirements.txt` and
the Go version from `go.mod`. This repository provides those tools through its
own development flake:

```sh
nix develop --command make contract-check check cross-build demo
```

Without Nix, a standalone checkout needs Go 1.27.1, Make, Python 3.12+ and the
pinned test dependencies described in the root README. The Nix shell versions
are recorded in `flake.lock`; see [dependency profiles](../../nix/README.md).
No new production dependency or Python signature library is introduced.

## Catalogue and evidence

`conformance-v1.json` lists eight source suites, their payload/expectation fields,
schema files, Go golden-test names and Python reader tests. It covers 240 existing
vectors across telemetry v1/v2, prediction, lifecycle, signed envelopes,
diagnostics, federation and audit. The command checks all declared schemas and
all fixture expectations, then runs the actual Go contract tests without cached
results and the listed Python tests. It verifies the number of passed Go golden
subtests against each source file. An omitted fixture/schema, empty suite,
duplicate reader version, missing Go reader or failing Python test fails the run.
This catalogue is test metadata, not an application wire registry.

The eight golden suites retain their existing contract-specific assertions.
Go checks typed decoding and semantic rules, signatures and applicable context.
Python tests check schema shape, plus the independently implemented envelope
reader, canonical signing bytes, finite binary model weights, update digests and
audit commitment reconstruction where supplied. Python lifecycle/prediction
checks remain schema checks, not independent semantic evaluators. This command
does not make all three layers equivalent.

Envelope fixtures now explicitly declare `schema_valid` separately from
`contract_valid`. A syntactically valid timestamp can violate lifetime policy;
a shape-valid digest can mismatch payload bytes. Those fixtures correctly pass
schema and fail semantic readers. Expectations are reviewed fixture data, never
inferred from the validator result during a run.

A passing run writes `artifacts/contracts/conformance-v1-report.json` with tool
versions, source/catalogue/schema hashes, per-suite vector counts and test names,
and verified wire classifications. CI retains that report for 14 days. The
command removes the previous report before checking and writes a new one only
on success. Failure details remain in the command/CI log; a stale passing report
cannot survive a failed run. The report identifies fixture integrity, not a
production deployment or real-device result.

## Shared raw-wire cases

`fixtures/conformance/v1-vectors.json` preserves exact JSON text in `wire`, so
repeated keys, numeric token spelling, whitespace and escaped strings survive
loading the fixture container. Go and Python read the same 52 cases across all
16 supported reader namespaces. `reader_version` selects the intended consumer;
a valid v2 telemetry payload presented to a v1 reader is deliberately incompatible.
The file separately declares `expected_go`, `expected_schema` and
`expected_python` for each case.

Reader classifications are:

- `accepted`: the tested reader accepts the input at its documented boundary.
- `invalid_json`: invalid/trailing JSON, repeated keys in strict readers, or
  nonfinite JSON constants. JSON Schema receives an already parsed object and
  cannot reject repeated keys itself, so that case has schema `accepted`.
- `unsupported_schema`: the wire version differs from the selected reader,
  including a deliberately unknown `.v999` namespace.
- `invalid_contract`: shape, required-field, scalar or applicable semantic failure.
- `key_mismatch` and `invalid_signature`: Go authenticates the fixture using its
  supplied public test key. Python/schema acceptance in these cases is deliberate;
  neither authenticates signatures.
- `replay`, `expired` and `future_timestamp`: pure #75 freshness outcomes with an
  explicit clock and durable-mark input. Expiry takes precedence over replay,
  including at the exact expiry instant. The exact five-minute skew boundary is
  accepted, while one second beyond it is rejected.

Go verifies canonical bytes and Ed25519 signatures when a wire case provides a
public key. Python reuses the independent envelope reader/canonical framing and
checks pure freshness using fixture-supplied context; it does not establish that
context's authorization or authenticate its signer. The original golden suites
also check the later namespaces' signing bytes and commitments. Null GPU/battery
measurements retain their reasons, and a missing reason fails all three layers.
Escaped string spelling and property order do not change signing bytes.

The strict raw-wire test reader rejects duplicate keys before typed decoding.
This does not retrofit that policy into the legacy development HTTP handler.
No production route, enrollment, sequence transaction, durable replay store,
restart recovery, endpoint collector, federation or chain implementation is added.
A pure `replay` result does not demonstrate durable replay rejection in a service.

## Fixture changes and review

Regenerate envelopes before the derived raw-wire cases, then run the command:

```sh
go run packages/contracts/fixtures/envelopes/generate.go
python3 tools/generate_contract_wire_vectors.py
make contract-check check cross-build
```

Golden source files remain the source of truth. The wire generator copies public
fixture payloads and adds deliberate serialization/version mutations; it generates
no operational key. Add a new schema/suite to the catalogue and a valid/unsupported
reader pair before implementing a consumer. Do not overwrite expected outcomes
to match a failing implementation without reviewing the contract decision.

Both owners still need to review fixture/classification changes before dependent
implementations merge. The PR and its CI evidence are that review boundary;
a passing harness is not human approval. These tests establish no production,
prediction, privacy, patent-conformance or legal-coverage claim.
