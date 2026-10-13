# Device Audit repository instructions

Build the IT Operational Audit and Device Lifecycle Management system. Use
`docs/requirements.md` for scope and `docs/decisions.md` for decision provenance.
The original patent PDF has not yet been supplied to this environment; do not
claim that the scaffold implements or has been checked against the patent.

- `apps/controller` and `internal/controller`: Go controller and ingestion.
- `apps/endpoint-agent`: Go endpoint process; the initial collector is a fixture.
- `packages/contracts`: versioned telemetry, prediction, workflow, and audit types.
- `packages/health`, `packages/federated`, `packages/lifecycle`, `packages/audit`:
  application boundaries. Missing implementations must return explicit errors.
- `models`: bespoke prediction/training interfaces; hosted Jev is out of scope.
- `networking`: Shepherd-derived Tailcat/WireGuard/DERP design and adapter seam.
- `contracts`: smart-contract architecture; chain selection remains open.

Run `make check` and `make cross-build` for Go changes. Run `make model-check`
for Python changes. Never confuse fixture telemetry, in-memory storage, or an
interface with a production capability. Keep networking authentication separate
from device signatures and from smart-contract evidence anchoring. Do not put
raw logs or device identifiers on a blockchain. Update wire contracts before
dependent features and preserve nullable metrics and explicit units.

Use Conventional Commits. Do not expand into Shepherd's configuration manager,
Nix build workers, MDM, package deployment, or unrestricted shell agents.
