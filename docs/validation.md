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
