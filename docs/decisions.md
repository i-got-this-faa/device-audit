# Decisions retained from the handoff

The user explicitly requested a new organization repository and selected reuse
of Shepherd networking. The attached `chat_handoff_full_transcript.md` ends with
Turns 15–17 describing the current direction. Earlier security and fleet-manager
discussion can drift and does not automatically become product scope.

| Decision | Evidence | Treatment |
| --- | --- | --- |
| New repository under i-got-this-faa | Current user request, handoff 15–17 | Dedicated `device-audit`; Shepherd remains separate |
| Go controller | Handoff 15/17 | Selected |
| Go endpoint agent | Handoff 17 | Selected |
| Tailcat / userspace WireGuard / DERP | Current request, handoff 15/17, Shepherd spec 14 | Preserve design and package boundary; adapter absent upstream |
| Bespoke prediction model, no Jev | Explicit user statement in handoff 17 | Selected; architecture and dataset open |
| Local training + central aggregation | Handoff 15–17 patent interpretation | Core product capability, exact PDF references pending |
| Smart contracts + cryptographic verification | Explicit user statement in handoff 17 | Selected direction; chain and contract implementation open |
| Python + PyTorch | Assistant marked proposed in handoff 17 | Python interfaces included; no PyTorch dependency or model architecture selected |
| PostgreSQL | Marked proposed in handoff | Initial schema candidate only; no runtime DB binding |
| Windows-first | Handoff 15 marks it proposed; the backlog prioritizes a Windows collector; on 14 October 2026 the owner supplied a Windows session for validation | One HP Victus development laptop is available: Windows 11 25H2 build 26200.9457, x64, standard-user access. Native fixture execution and source-availability checks are recorded in [Windows evidence](validation/windows-2026-10-14.md), superseding the earlier no-machine blocker. Final release scope, production permissions and collector/service qualification remain open. See [release scope](roadmap/release-scope.md). |
| Additional platforms | No handoff decision approves macOS, Linux, or other device families | Blocked, neither included nor excluded; target OS versions, hardware classes, permissions, and real machines are not selected. See [release scope](roadmap/release-scope.md). |
| Asset-system integration | Supplied specification [0022] page 4, [00109] page 25, and Figure 2 page 31 | Blocked pending #72 (SRC05) source reconciliation and explicit product selection; no adapter is selected. See [release scope](roadmap/release-scope.md). |
| Independent network observation | Conditional scope is noted in the release context; no product decision or acceptance boundary is recorded | Blocked pending #72 and explicit product selection; endpoint telemetry, network identity, and chain verification do not imply it. See [release scope](roadmap/release-scope.md). |
| ML01 dataset/labels/partitions (#22) | Pinned Backblaze 2013 source, custom publisher terms and reproducible manifest | Select a historical HDD recorded-event study with a seven-day horizon, disjoint device cohorts and purged chronological evidence intervals. CPU/GPU/other component labels and matching endpoint SMART telemetry are absent; endpoint failure-prediction claims remain blocked. See the [decision and reproduction commands](../models/datasets/backblaze-2013/README.md). |
| Frontend | Explicitly not finalized | Reserve dashboard surface; no framework selected |
| LLM explanations | Optional in handoff | Future optional component; prediction and aggregation do not depend on it |

Scaffold choices made here: private repository by default, stdlib-only local
demo, Go 1.27.1 aligned with Shepherd/Tailcat, an ephemeral bounded sample store,
strict versioned inputs, and explicit errors for unavailable mesh transport.
These choices do not settle production hosting, tenancy, identity, model
runtime, chain, frontend or collector cadence.

## Provisional telemetry/inventory contract v2

Task #15 adds a separately named `device-audit.telemetry.v2` proposal alongside
v1. The metric set and explicit units are CPU/GPU utilization, memory/disk/
battery percent, Celsius temperature, and millisecond network latency. Null
metrics require one of `sensor_unavailable`, `not_applicable`,
`permission_denied`, or `collection_error`; known metrics cannot include a
missing reason, and at least one metric must be known. Inventory supports
opaque group/network-segment IDs and up to 64 component records. Telemetry
supports up to 8 bounded log references with opaque IDs, SHA-256, at most 10
MiB per reference, and a time window; raw logs are excluded. These choices are
provisional and platform-neutral pending the missing patent PDF and unresolved
release platform/hardware scope from #14. They do not settle enrollment,
network identity, signature, or chain policies.
