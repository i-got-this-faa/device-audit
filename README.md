# Device Audit

Scaffold for **System and Method for IT Operational Audit and Device Lifecycle
Management**, in a dedicated repository under `i-got-this-faa`.

The intended flow is device telemetry → bespoke health/failure prediction →
autonomous diagnostic workflows → federated local training and aggregation →
audit recommendations → lifecycle and sustainability analysis.

This repository is an engineering starting point. The original `patent.pdf`
was not available when it was created. Its [provenance and reference
inventory](docs/source/patent-map.md) are now verified against the supplied PDF.
[Requirements](docs/requirements.md) now link claims 1-10 to planned tasks,
acceptance gaps and retained exclusions. Platform and conditional-scope
decisions remain open under [#14](https://github.com/i-got-this-faa/device-audit/issues/14)
and [#138](https://github.com/i-got-this-faa/device-audit/issues/138).
Source traceability does not establish implementation or patent conformance.

## Start locally

Install Go 1.27.1 and Python 3.12+. Go's toolchain auto-selection can download
the version in `go.mod`. Python dependencies are test-only; install them in a
virtual environment before running the checks:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r models/test-requirements.txt
make PYTHON=.venv/bin/python check cross-build
make demo
```

Or use two terminals:

```sh
go run ./apps/controller
go run ./apps/endpoint-agent --device-id demo-device
curl http://127.0.0.1:8080/v1/devices/demo-device
```

The endpoint sends one **fixture**, not real system measurements. The controller
validates it, computes a SHA-256 digest of its normalized Go JSON representation,
and retains the latest sample for up to 1,000 devices in memory. Data disappears
on restart. The digest is not a signature or proof that a device is truthful.
Health remains `unknown`; no trained model or failure forecast is fabricated.

Run `make contract-check` for the shared Go/schema/Python fixture harness and its
machine-readable evidence report. See [contract conformance](packages/contracts/conformance-v1.md)
for the exact reader boundaries and Nix command.

## Repository

- `apps/controller`, `internal/controller`: working loopback ingestion skeleton.
- `apps/endpoint-agent`: working one-shot fixture sender; real read-only collectors are next.
- `packages/contracts`: shared versioned telemetry, prediction, training, workflow, audit types.
- `packages/{telemetry,health,workflows,federated,lifecycle,audit}`: implementation interfaces.
- `models`: custom model/training interfaces and a tested weighted aggregation primitive.
- `networking`: Tailcat/WireGuard/DERP adapter boundary carried over from Shepherd's design.
- `infra/networking`: relay/bootstrap deployment requirements.
- `infra/database`: initial PostgreSQL schema candidate, not connected to the demo.
- `contracts`: smart-contract commitment requirements; blockchain selection is open.
- `apps/web-console`: dashboard scope; frontend selection is open.

Mesh constructors return `ErrNotImplemented`; `--transport mesh` exits with an
error. The fixture demo accepts literal loopback addresses only. Production
enrollment, device authentication, durable storage, real collectors, predictions,
diagnostics, federated coordination, lifecycle reports, and contract transactions
are not implemented. [Architecture](docs/architecture.md) explains the boundaries.

## Decisions and source

Go controller and endpoint, a custom prediction model (no Jev), federated
learning, smart contracts plus cryptographic verification, and the
Tailcat/WireGuard/DERP network are retained from the handoff. Python/PyTorch,
PostgreSQL, Windows-first support, and frontend choices have different levels of
certainty; see [decisions](docs/decisions.md).

[Shepherd](https://github.com/i-got-this-faa/shepherd) remains a separate product.
Its broad configuration/MDM/build-worker scope is not part of this scaffold.
[Network provenance](networking/README.md) records exactly what is reused.

CI installs the pinned test-only Python dependencies, then runs Go
validation/race tests, Python aggregation and telemetry schema tests,
Windows/macOS cross-compilation, and the binary round-trip demo.
