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
| Bespoke prediction model, no Jev | Explicit user statement in handoff 17 | Selected; architecture and endpoint qualification open. #22 selects only a historical HDD study. |
| Local training + central aggregation | Handoff 15–17; supplied claims 1/4/8, pp.26-28; [0059]-[0061], pp.13-14 | Core product capability; source references are mapped in SRC05 #72. Two-endpoint training, validated aggregation and evaluated forecast generation remain implementation work. |
| Smart contracts + cryptographic verification | Explicit user statement in handoff 17; description [0078], p.19 and FIG.2, p.31 | Selected direction; chain and contract implementation open. Claims 1-10 do not expressly specify blockchain or smart contracts. |
| Python + PyTorch | Assistant marked proposed in handoff 17 | Python interfaces included; no PyTorch dependency or model architecture selected |
| PostgreSQL | Marked proposed in handoff | Initial schema candidate only; no runtime DB binding |
| Windows-first | Handoff 15 marks it proposed; the backlog prioritizes a Windows collector; on 14 October 2026 the owner supplied a Windows session for validation | One HP Victus development laptop is available: Windows 11 25H2 build 26200.9457, x64, standard-user access. Native fixture execution and source-availability checks are recorded in [Windows evidence](validation/windows-2026-10-14.md), superseding the earlier no-machine blocker. Final release scope, production permissions and collector/service qualification remain open. See [release scope](roadmap/release-scope.md). |
| Additional platforms | No handoff decision approves macOS, Linux, or other device families | Blocked, neither included nor excluded; target OS versions, hardware classes, permissions, and real machines are not selected. See [release scope](roadmap/release-scope.md). |
| Asset-system integration | Supplied specification [0022] page 4, [00109] page 25, and Figure 2 page 31 | SRC05 maps this broader description; explicit product selection remains blocked under #14/#138. Internal inventory is a subset, not an external adapter. See [release scope](roadmap/release-scope.md). |
| Independent network observation | SRC05 review of [0051], p.10, [0074], p.18, [0078], p.19 and FIG.2, p.31 finds no defined observer/source/trust boundary | Explicit product selection remains blocked under #14/#138. Endpoint telemetry, network identity and chain verification do not imply an observer. See [release scope](roadmap/release-scope.md). |
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
provisional and platform-neutral pending release platform/hardware scope (#14)
and provider/feature definitions (#21/#32/#85). SRC05 #72 records metric gaps:
disk space, battery charge and latency cannot stand in for disk health/I/O,
battery health/life and throughput. PDF provenance and claim reconciliation are in
[the source inventory](source/patent-map.md). They do not settle enrollment,
network identity, signature, or chain policies.

## Provisional prediction contract v2

Task #16 proposes a separate `device-audit.prediction.v2` contract and leaves
v1 types and fixture behavior intact. Predictions bind an opaque device ID,
model version plus artifact SHA-256 when a model is available, evidence digest,
telemetry schema version, generated/expiry timestamps, health state, and bounded
fault forecasts. Evidence must reference `device-audit.telemetry.v2` in this
proposal. `healthy`, `degraded`, and `critical` states carry a numeric probability
from 0 through 1, the explicit `probability` unit, and a positive horizon in
hours; they also require model and evidence references. `unknown` carries null
probability and horizon plus `insufficient_evidence`, `model_unavailable`, or
`stale_evidence`; a null model reference is required for `model_unavailable`.
Unknown predictions may not carry fault forecasts. Other unknown reasons may
retain a selected model reference as provenance.

Forecasts are limited to eight entries from the provisional set
`cpu`, `gpu`, `memory`, `storage`, `battery`, `thermal`, and `network`. Each has
its own probability unit and positive horizon; a category may recur at
different horizons. These fields do not claim
calibration: no health thresholds, probability relationships, or sum-to-one
constraint are selected. Expiry is stale at the exact `expires_at` instant;
`IsStale(now)` takes its clock explicitly. Timestamp ordering and Go's zero-time
instant check are semantic Go validation rules because JSON Schema checks only
date-time syntax. Shared prediction vectors are validated by Go and Python.
These are provisional choices pending #14 and endpoint model qualification.
SRC05 #72 records the source's warning/degraded terminology difference and
assigns the versioned health policy to #86/#35. #22 selected a historical HDD
dataset study; the source PDF and claim reconciliation are indexed. These contracts provide neither patent
compliance evidence nor a production model capability.

## Source reconciliation and retained scope, SRC05 #72

The [claim map and disposition register](source/patent-map.md) separate all ten
printed claims from broader description and figure material. Current product
work maps read-only health-specific diagnostics, local training, evaluated
aggregation/forecast workflows, recommendations and methodology-based lifecycle
analysis. This mapping is engineering traceability, not proof of implementation
or legal coverage. It uses the handoff decisions recorded above; the original
transcript was not reread in the Windows source review.

OS tuning, CPU throttling and self-repair in [0062], p.14, [0077], p.19 and FIG.2
stage 208, p.31 conflict with the retained read-only/no-remediation boundary.
That exclusion remains in force. General executable-agent replacement,
hierarchical controllers, gamification, vendor marketplaces and particular
ML/XAI algorithms have unmatched or unselected details. SRC02 #14/CAP02 #138
must explicitly disposition any proposed expansion and approve owned,
dependency-linked rebaseline work. No existing release task is removed here.
