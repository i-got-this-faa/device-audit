# Requirements and source reconciliation

The supplied PDF is primary for its own text and printed references. Explicit
user instructions and retained handoff decisions govern implementation scope;
source descriptions do not silently override exclusions. The verified Windows
copy is `C:/Users/radhe/Downloads/patent.pdf`; the earlier Linux source path is
recorded with its matching digest in [`source/patent-map.md`](source/patent-map.md).

The source map now reconciles claims 1-10, metric terminology, broader
embodiments and retained exclusions for SRC05
[#72](https://github.com/i-got-this-faa/device-audit/issues/72). It identifies
planned work and gaps; it establishes neither implementation nor legal
coverage. SRC02 [#14](https://github.com/i-got-this-faa/device-audit/issues/14)
records the [V1 endpoint matrix](roadmap/release-scope.md): one Windows laptop
configuration selected for qualification, other endpoint platforms excluded from
V1 support claims, and explicit blocked asset/independent-observation dispositions.
CAP02 [#138](https://github.com/i-got-this-faa/device-audit/issues/138) retains
the later reconciliation and unresolved conditional-capability gates. Selection
does not qualify the target or remove any implementation/acceptance task.

## Requirement identifiers used by the roadmap

These identifiers already appear in the project's epic and task acceptance
criteria. They identify planned product requirements, not implemented or
patent-verified capabilities. A task reference supplies an implementation and
evidence owner; it does not mean that task is complete.

| Requirement | Planned boundary | Representative stable task keys and issues |
| --- | --- | --- |
| RQ-01 | Real, read-only device telemetry, structured error evidence and explicit missing measurements | TEL01 [#21](https://github.com/i-got-this-faa/device-audit/issues/21); TEL05 [#91](https://github.com/i-got-this-faa/device-audit/issues/91); TEL06 [#92](https://github.com/i-got-this-faa/device-audit/issues/92); TEL07 [#93](https://github.com/i-got-this-faa/device-audit/issues/93) |
| RQ-02 | Enrollment, signed evidence, replay rejection, authorization and durable evidence state | SEC01 [#18](https://github.com/i-got-this-faa/device-audit/issues/18); SEC03 [#24](https://github.com/i-got-this-faa/device-audit/issues/24); SEC08 [#89](https://github.com/i-got-this-faa/device-audit/issues/89); DB02 [#83](https://github.com/i-got-this-faa/device-audit/issues/83) |
| RQ-03 | Admitted Tailcat/WireGuard transport, persistent network identity and self-hosted DERP fallback | NET01 [#20](https://github.com/i-got-this-faa/device-audit/issues/20); NET02 [#25](https://github.com/i-got-this-faa/device-audit/issues/25); NET04 [#84](https://github.com/i-got-this-faa/device-audit/issues/84) |
| RQ-04 | Versioned preprocessing, bespoke model training, evaluated predictions and evidence-backed health | CT03 [#32](https://github.com/i-got-this-faa/device-audit/issues/32); ML02 [#33](https://github.com/i-got-this-faa/device-audit/issues/33); ML06 [#103](https://github.com/i-got-this-faa/device-audit/issues/103); ML10 [#106](https://github.com/i-got-this-faa/device-audit/issues/106) |
| RQ-05 | Authenticated, bounded, read-only scheduled and health-triggered diagnostics | DIA01 [#36](https://github.com/i-got-this-faa/device-audit/issues/36); DIA02 [#37](https://github.com/i-got-this-faa/device-audit/issues/37); DIA04 [#108](https://github.com/i-got-this-faa/device-audit/issues/108) |
| RQ-06 | Local training, validated compatible updates, central aggregation and evaluated model promotion | FED02 [#42](https://github.com/i-got-this-faa/device-audit/issues/42); FED03 [#43](https://github.com/i-got-this-faa/device-audit/issues/43); FED10 [#115](https://github.com/i-got-this-faa/device-audit/issues/115); FED06 [#70](https://github.com/i-got-this-faa/device-audit/issues/70) |
| RQ-07 | Signed off-chain audit evidence and finality-aware opaque chain commitments | AUD01 [#45](https://github.com/i-got-this-faa/device-audit/issues/45); AUD03 [#120](https://github.com/i-got-this-faa/device-audit/issues/120); CHAIN07 [#123](https://github.com/i-got-this-faa/device-audit/issues/123); CHAIN06 [#127](https://github.com/i-got-this-faa/device-audit/issues/127) |
| RQ-08 | Evidence-backed lifecycle recommendations, sustainability, longevity and fleet/component trends | LIF01 [#46](https://github.com/i-got-this-faa/device-audit/issues/46); LIF02 [#121](https://github.com/i-got-this-faa/device-audit/issues/121); LIF03 [#122](https://github.com/i-got-this-faa/device-audit/issues/122); FLEET01 [#71](https://github.com/i-got-this-faa/device-audit/issues/71); FLEET02 [#128](https://github.com/i-got-this-faa/device-audit/issues/128) |
| RQ-09 | Authorized device/fleet console, inspectable provenance and bounded report exports | WEB02 [#30](https://github.com/i-got-this-faa/device-audit/issues/30); WEB05 [#53](https://github.com/i-got-this-faa/device-audit/issues/53); WEB11 [#131](https://github.com/i-got-this-faa/device-audit/issues/131) |
| RQ-10 | Real-device integration, resource/failure tests, packaging, recovery and release evidence | INT02 [#31](https://github.com/i-got-this-faa/device-audit/issues/31); TST06 [#61](https://github.com/i-got-this-faa/device-audit/issues/61); CAP01 [#58](https://github.com/i-got-this-faa/device-audit/issues/58); REL01 [#68](https://github.com/i-got-this-faa/device-audit/issues/68) |
| RQ-11 | Source traceability, explicit scope/platform decisions and retained exclusions | SRC05 [#72](https://github.com/i-got-this-faa/device-audit/issues/72); SRC02 [#14](https://github.com/i-got-this-faa/device-audit/issues/14); CAP02 [#138](https://github.com/i-got-this-faa/device-audit/issues/138) |

The contracts epic spans multiple requirements. RQ-02 and RQ-07 describe
different evidence boundaries: transport admission, device signatures and
chain commitments remain separate. A verified commitment establishes integrity
of the committed evidence; it does not prove the endpoint's measurements true.

## Measured release capability matrix, CAP01 #58

Status on 18 November 2026. **No capability below is qualified for release.**
The [release scope](roadmap/release-scope.md#evidence-and-release-gates) states
that no OS/hardware target is qualified until the service-token, packaging,
resource/failure and release-approval gates pass; this matrix is one of those
inputs, not the approval. The owner has ruled out the second physical target
for this matrix, so two-machine items are recorded as not run rather than
pending.

Each row has exactly one evidence class. A class says *where* a result was
measured, not that the capability is supported:

| Class | Meaning | Not evidence of |
| --- | --- | --- |
| **Target hardware** | Real OS calls on the selected HP Victus 15-fb0xxx, Windows 11 Home SL 25H2 build 26200, as the interactive standard user, or as LocalService where the row cites the service run | Other hardware or builds, a second machine |
| **Hosted CI OS** | Real OS calls on a GitHub-hosted `windows-2025` VM (build 26100) or Ubuntu runner | The 26200 target, a physical machine, a service token unless stated |
| **Local lab** | Real binaries on a Linux development host, loopback or network namespaces | NAT/WAN, Windows endpoints, deployed infrastructure |
| **Fixture** | Fixtures, fakes, synthetic harnesses, in-memory stores | Any device or production behavior |
| **Contract** | Schemas, golden vectors and interfaces without a running implementation | Runtime behavior |
| **Cross-build** | Compiles for the target | Runtime behavior |
| **Unsupported** | No evidence, excluded, or blocked | — |

The JSON reports from the Victus carry `host.role =
development_or_ci_not_physical_target` because the process cannot attest its
machine; the dated validation records make the attribution. Reproduction
commands per class are in [validation.md](validation.md#reproducing-the-capability-matrix-cap01-58).

### Platform

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| Windows 11 Home SL 25H2 x64 on HP Victus 15-fb0xxx | RQ-10, RQ-11 | Target hardware | [release-scope](roadmap/release-scope.md#endpoint-platform-matrix) (baseline 26200.9711); [14 Oct](validation/windows-2026-10-14.md), [19 Oct](validation/windows-2026-10-19.md); 17 Nov runs below report `10.0.26200` | Release qualification; regression evidence for later cumulative builds |
| Second physical Windows target | RQ-10 | Unsupported | Owner decision; recorded unavailable in release scope | — |
| GitHub-hosted Windows VM | — | Hosted CI OS | [sensors-92](validation/sensors-92.md#hosted-windows-ci-run) run 44079287075, `windows-2025`, 10.0.26100 | Build 26200 target; physical hardware |
| Windows amd64/386 and macOS arm64 builds | — | Cross-build | `make cross-build`, `tools/check-windows.ps1` | Any runtime on those builds |
| Linux, macOS, Android, iOS, ChromeOS, BSD endpoints; other Windows editions and builds | RQ-11 | Unsupported | Excluded in [release-scope](roadmap/release-scope.md#endpoint-platform-matrix) | — |

### Telemetry and error evidence

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| CPU utilization | RQ-01 | Target hardware | [telemetry-91](validation/telemetry-91.md#hp-victus-run-17-november-2026), 17 Nov, Go 1.27.4; LocalService in [windows-service-26](validation/windows-service-26.md), 18 Nov | Observed counter reset (tests only); multi-processor-group hosts (null by design) |
| Memory in use | RQ-01 | Target hardware | telemetry-91, 17 Nov; LocalService, windows-service-26 | — |
| Fixed-volume space used | RQ-01 | Target hardware | telemetry-91, 17 Nov (90.518 % vs `Get-Volume` 90.516 %) | Disk health, SMART or I/O; observed volume denial (tests only) |
| Disk health / SMART | RQ-01, RQ-04 | Target hardware | NVMe health log read on demand by the `storage_health.v1` probe, [probe-catalog-36](validation/probe-catalog-36.md), 18 Nov | Not a scheduled telemetry source; SATA/ATA SMART; [Backblaze mapping](../models/datasets/backblaze-2013/README.md) features |
| Network receive/send rate | RQ-01 | Target hardware | telemetry-91, 17 Nov; down interface reported `interface_down` | Not on the telemetry v2 wire; interface removal and counter reset (tests only) |
| Network latency | RQ-01 | Unsupported | No collector | — |
| Battery charge | RQ-01 | Target hardware | telemetry-91 and [sensors-92](validation/sensors-92.md), 17 Nov; LocalService, windows-service-26 | Battery health/life |
| ACPI thermal zone (PDH) | RQ-01 | Target hardware | telemetry-91, 17 Nov (65.85–67.85 °C); the CIM class was `permission_denied` on [19 Oct](validation/windows-2026-10-19.md); LocalService, windows-service-26 | Observed PDH denial (tests only) |
| GPU engine utilization (PDH) | RQ-01 | Target hardware | telemetry-91, 17 Nov, three adapters; LocalService, windows-service-26 | — |
| NVIDIA utilization and temperature (`nvidia-smi`) | RQ-01 | Target hardware | telemetry-91, 17 Nov; LocalService, windows-service-26 | Child-process cost in the budget |
| Missing-reason isolation per source | RQ-01 | Fixture | [sensors-92](validation/sensors-92.md#tests), [telemetry-91](validation/telemetry-91.md#tests); real APIs also run in `windows-check` | An observed sensor denial on the target |
| Endpoint telemetry v2 payload (`--collect-telemetry`) | RQ-01 | Target hardware | telemetry-91, 17 Nov | Delivery; network rates and providers on the wire |
| System/Application error records with persistent read positions (`--collect-errors`) | RQ-01 | Target hardware | [error-evidence-93](validation/error-evidence-93.md#hp-victus-run-17-november-2026), 17 Nov: IDs match `Get-WinEvent`, repeat poll returns none, Security log `permission_denied` observed | LocalService read of System/Application; observed rollover, clear or oversized message (tests only); delivery |
| Scheduled sampling with declared CPU/RSS budget (`--sample`) | RQ-01, RQ-10 | Target hardware | [sampling-94](validation/sampling-94.md#hp-victus-runs-17-november-2026), 17 Nov: four 10-minute runs, three within 2 % / 64 MiB, run 1 exceeded RSS (unattributed); hosted by the LocalService service in [windows-service-26](validation/windows-service-26.md), 18 Nov, where one first start also peaked at 86 MB | Root cause of the RSS peaks; child-process cost; error collection on the scheduler |
| Source access under LocalService and a denied account | RQ-01, RQ-10 | Hosted CI OS | [collector-budget-85](validation/collector-budget-85.md) run 43859814735, `windows-2025`, PowerShell probe and harness only; the Go collectors under LocalService on the target in [windows-service-26](validation/windows-service-26.md) | A denied account on the target |
| Collector cost harness and cadence candidates | RQ-10 | Fixture | collector-budget-85, 16 Nov, Linux and hosted Windows | `production_budget_approved` is always false |
| Loopback fixture telemetry demo (`--fixture`) | — | Fixture | `tools/demo.py` in `check` and `windows-check`; requires `--fixture` and prints `provenance=fixture` | Any device measurement |

### Contracts and diagnostics

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| Telemetry, prediction, lifecycle, envelope, bootstrap, inventory, federated, diagnostic and audit wire contracts | RQ-01–RQ-09 | Contract | [validation.md](validation.md#shared-contract-conformance-ct05-80) and `make contract-check` in `check` | Live collectors, authorization, training, chain behavior |
| Read-only typed diagnostic assignments and results | RQ-05 | Contract | [diagnostics-v1](../packages/contracts/diagnostics-v1.md) | Scheduler, executor, cancellation, result storage |
| Typed read-only probe catalog (`storage_health.v1`, `system_errors.v1`, `--run-probe`) | RQ-05, RQ-01 | Target hardware | [probe-catalog-36](validation/probe-catalog-36.md), 18 Nov: NVMe health log and System/Application errors as the standard user | Assignment verification and signed results (#38); an observed OS denial (tests only); LocalService; non-NVMe health |

### Models

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| Backblaze 2013 dataset, labels and partitions | RQ-04 | Local lab | [verification](../models/datasets/backblaze-2013/verification.md); `dataset-reproduction` job | Laptop or NVMe representativeness; validation split has 4 events |
| Predeclared evaluation and resource thresholds | RQ-04 | Contract | [model-thresholds-86](validation/model-thresholds-86.md), 17 Nov | Any computed metric, trained model or measured cost |
| Frozen feature version `hdd-smart-7d.v1` | RQ-04 | Fixture | [features-32](validation/features-32.md), 18 Nov; Go/Python agree on 41 shared vectors | Real telemetry or archive runs; no SMART collector, so endpoint vectors are `incomplete` |
| Trained model, inference and health prediction | RQ-04 | Unsupported | [models/README](../models/README.md); demo health is `unknown` | — |
| Federated aggregation | RQ-06 | Fixture | Weighted-average primitive in `models` | Two-endpoint training, validated updates, promotion |

### Networking, identity and evidence

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| Tailcat direct UDP | RQ-03 | Local lab | [2026-10-16](../networking/tailcat-lab/evidence/2026-10-16.md), same host; `tailcat-lab` job | Two machines, LAN/WAN/NAT, Windows |
| Self-hosted DERP with UDP blocked | RQ-03 | Local lab | [2026-10-21-derp](../networking/tailcat-lab/evidence/2026-10-21-derp.md), network namespace | Public deployment; Windows |
| Admitted mesh adapter | RQ-03, RQ-02 | Local lab | [mesh-adapters-25](validation/mesh-adapters-25.md), 16 Nov, Linux, PostgreSQL 16.15 | NAT/WAN; deployed DERP; the target; LocalService |
| Scoped relay and UDP-blocked fallback | RQ-03 | Local lab | [relay-fallback-88](validation/relay-fallback-88.md), 17 Nov; `relay-fallback` job | Public relay host, DNS, CA; NAT/WAN; the target |
| Deployed relay, NAT/WAN, two machines | RQ-03 | Unsupported | [networking/README](../networking/README.md) | — |
| Bootstrap enrollment over TLS | RQ-02 | Local lab | [enrollment README](../infra/enrollment/README.md), PostgreSQL 17 | Real IdP and proxy; rotation, rate limits |
| Endpoint identity storage, Windows DPAPI and DACL | RQ-02 | Target hardware | [endpoint-keys-23](validation/endpoint-keys-23.md), CI account; created and reused by the LocalService service under its per-service SID in [windows-service-26](validation/windows-service-26.md), 18 Nov | Power loss |
| Signed evidence and crash-safe sequence | RQ-02 | Local lab | [evidence-sequence-87](validation/evidence-sequence-87.md), 13 Nov, an unidentified Windows 11 host; 15 envelopes across stop, restart and kill under LocalService in [windows-service-26](validation/windows-service-26.md) | Power loss; spool |
| Controller verification before ingestion | RQ-02 | Local lab | [evidence-verification-24](validation/evidence-verification-24.md), 17 Nov, Linux, PostgreSQL 17.11 | Rejections over a real tunnel; durable audit table |
| Replay rejection and signed acknowledgements | RQ-02 | Local lab | [replay-acknowledgements-89](validation/replay-acknowledgements-89.md), Linux, PostgreSQL 17.11 | Acknowledgement-key rotation; Windows controller; deployed database |
| Device revocation authority and audit record | RQ-02 | Local lab | [device-revocation-90](validation/device-revocation-90.md), 18 Nov, Linux, PostgreSQL 17.11 | Real IdP; rejection over a real tunnel; relay admission export; Windows controller |
| Durable signed spool and retry | RQ-02 | Local lab | [spool-drain-96](validation/spool-drain-96.md), Linux, PostgreSQL 18.7 | Installed LocalService delivery, NAT/WAN and power loss |
| Identity rotation and re-enrollment | RQ-02 | Unsupported | Open in #130 | — |

### Controller, storage and console

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| PostgreSQL binding and migrations | RQ-02 | Local lab | [validation.md](validation.md#postgresql-binding-and-migrations-db01-19), PostgreSQL 17.11; `database` job | Backup/restore, TLS, least-privilege roles, retention |
| Inventory revisions | RQ-08, RQ-09 | Local lab | [validation.md](validation.md#inventory-revisions-api03-97-27-october-2026) | Physical component identity |
| Administrator OIDC sessions | RQ-09 | Fixture | [validation.md](validation.md#administrative-authentication-sec06-82), fake TLS issuer | A real identity provider |
| Console shell and device views | RQ-09 | Fixture | [validation.md](validation.md#console-shell-web01-29-27-october-2026), [console-fixtures-99](validation/console-fixtures-99.md), Chromium 155 | Production fleet reads; Edge/Firefox; exports |
| Independent controller fake | RQ-02 | Fixture | [validation.md](validation.md#independent-controller-fake-tst01-17) | — |

### Chain, lifecycle and service

| Capability | RQ | Class | Evidence (date, environment) | Not shown |
| --- | --- | --- | --- | --- |
| Base chain release policy and descriptor | RQ-07 | Contract | [chain-policy-47](validation/chain-policy-47.md), [release-policy](../contracts/release-policy.md) | Any RPC call, compiled contract, deployment or transaction |
| Audit manifests and opaque commitments | RQ-07 | Contract | [audit-v1](../packages/contracts/audit-v1.md) | Accounts, resolver, retention |
| Smart contract and anchoring runtime | RQ-07 | Unsupported | `packages/audit` has no anchorer | — |
| Lifecycle recommendations, sustainability, longevity, fleet trends | RQ-08 | Contract | [lifecycle v2](#provisional-lifecycle-wire-contract-ct08-78) | Evaluator, calibrated model, aggregator |
| External asset integration; independent network observer | RQ-11 | Unsupported | Blocked in [release-scope](roadmap/release-scope.md#conditional-scope-decisions) | — |
| Endpoint Windows service host as LocalService (start, stop, restart, SCM recovery, refusals) | RQ-10, RQ-02 | Target hardware | [windows-service-26](validation/windows-service-26.md), 18 Nov, four runs; enrollment through the real controller handlers on PostgreSQL 18.1; SCM restart after a kill and after a non-crash exit | Delivery and spool (#27); reboot and power loss; a real collector failure in the service (tests only) |
| Endpoint packaging, signed install, upgrade, uninstall and release | RQ-10 | Unsupported | `tools/service` is a development install; no package (#57, #137, #68) | — |

Open dependencies of this matrix (#138, #51, #130, #137) and later evidence must
update the affected rows. A row moves class only when a dated record with its
environment exists.

## Capability and acceptance boundaries

The [source map](source/patent-map.md#claim-to-requirement-map-src05--72)
contains the exact printed references and stable task owners for each row.
Source claim numbers below identify text, not a completion or coverage claim.

| Planned capability / requirement | Printed claim(s) | Current evidence and acceptance still needed |
| --- | --- | --- |
| Real telemetry and structured errors / RQ-01 | 1, 8 | Windows collectors (TEL05 #91–TEL08 #94) were measured on the target as the interactive user; see the [matrix](#telemetry-and-error-evidence). The LocalService service run is in [windows-service-26](validation/windows-service-26.md); delivery remains open. TEL01 #21/TEL04 #85 must distinguish disk utilization from disk health/I/O, battery charge from health/life, and latency from throughput before CT03 #32 freezes features. Unavailable sensors remain missing with reasons. |
| Preprocessing, faults, predictions and health / RQ-04 | 1, 2, 8, 9 | Versioned wire contracts and model interfaces exist. ML09 #105 runs the endpoint's CT03 preprocessing over persisted evidence ([validation](validation/controller-features-105.md)), but telemetry v2 holds no SMART counter, so every controller vector is `incomplete`. ML10 #106 compares fault type, count and recurrence over a seven-day current and 21-day baseline window ([validation](validation/fault-history-106.md)); persisted log references carry no fault type, so every stored report is `unclassified`; The [ML06 held-out evaluation](../models/evaluation/README.md#ml06-held-out-result) failed the ML05 baseline precision and calibration gates, so model health remains unknown. Health thresholds and warning/degraded terminology remain explicit versioned choices. |
| Health-specific local analysis / RQ-05 | 1, 8 | Typed runner/task boundaries are scaffolds. DIA02 #37/DIA05 #109 must demonstrate authenticated health-specific assignments; the source's general agent replacement is an unmatched broader mechanism. No shell or remediation executor is selected. |
| Local learning and central aggregation / RQ-06 | 1, 4, 8 | Training interfaces and weighted averaging do not demonstrate federation. FED07 #112 stores signed artifacts with approved-only activation ([validation](validation/model-registry-112.md)); approval does not yet check an evaluation. FED01 #40 records rounds against a registered base with an enrolled-participant snapshot, a deadline and recorded transitions ([validation](validation/federated-rounds-40.md)); it admits no update. FED02 #42/FED03 #43/FED10 #115 require compatible training on two endpoints, validated updates and evaluated promotion. FED12 #117 must document data flows and privacy limits. |
| Forecast-driven diagnostic workflows / RQ-05/RQ-06 | 1, 8 | FED13 #118/FED06 #70 must connect evaluated fresh forecast data to bounded local diagnostics with deduplication, stale-data handling and traceable results. A timer or unrelated local job is insufficient. |
| Device audit reports and lifecycle recommendations / RQ-07/RQ-08 | 1, 5, 8 | AUD01 #45/LIF01 #46 must ground reports in actual evidence and cost inputs. Claim 5 allows at least one repair instruction, upgrade recommendation or replacement suggestion. Written advice does not authorize executing repairs or configuration changes. |
| Carbon/e-waste estimates, sustainability score and longevity / RQ-08 | 1, 3, 6, 8, 10 | Nullable types do not establish measured estimates. LIF02 #121/LIF03 #122 must define methodology, factors, score scale, units and uncertainty, using diagnostics and usage trends. The source supplies no calibrated formula. |
| Cross-device component trends and batch recommendations / RQ-08 | 7 | API03 #97 stores versioned administrator inventory assertions tied to enrolled devices, preserving unknown identities. FLEET01 #71/FLEET02 #128 still require verified component identity, deduplicated cohorts, explicit windows/denominators and evidence-backed recommendations. Inventory alone does not demonstrate the analysis. |
| Hierarchical console and on-demand exports / RQ-09 | Description [0072]-[0073], p.18 | WEB05 #53/WEB11 #131 cover planned internal views and report exports. External asset-system integration is a separate, blocked product choice under #14/#138, not an implicit consequence of fleet views. |

Custom prediction models and smart-contract audit verification remain explicit
handoff decisions. Blockchain audit logs also appear in description [0078],
p.19, and FIG.2, p.31; claims 1-10 do not expressly specify blockchain or smart
contracts. No independent observer or its trust boundary is defined in the
reviewed source. RQ-03 mesh transport, device signatures and chain integrity
cannot establish endpoint truth. A general web-browsing agent and an LLM on
every device are not prerequisites.

The source's OS tuning/self-repair examples conflict with retained exclusions.
Automatic remediation, configuration management, MDM, package rollout,
unrestricted shell agents and Jev remain excluded. General agent deployment,
hierarchical controllers, gamification, vendor marketplaces, particular ML/XAI
algorithms, additional platforms and asset adapters have unresolved or unmatched
details in the [disposition register](source/patent-map.md#broader-embodiments-unmatched-passages-and-retained-exclusions).
The register assigns those choices to #14/#138 and the relevant existing task;
this reconciliation selects no new capability and removes no planned work.

## Provisional lifecycle wire contract, CT08 #78

The separately versioned lifecycle v2 contract defines batch evidence/cost/age
inputs, nullable sustainability and longevity quantities, and cohort/window
component trends. Shared Go/Python vectors validate the wire shape; Go also
checks cross-field semantics. No evaluator, calibrated model, fleet aggregator
or external asset adapter is implemented. The implementation and evidence tasks
in the source map above remain open.

## PDF verification gate

1. [x] Obtain the original `patent.pdf` and record its SHA-256 digest; see the source inventory.
2. [x] Index the printed claims, paragraphs, and available figures with PDF and printed-page references; see the source inventory.
3. [x] Map all ten indexed claims and relevant description passages to requirement IDs, stable task keys and acceptance gaps; see the source map.
4. [x] Reconcile the source against recorded handoff decisions and exclusions, retaining unmatched passages and assigning open choices to SRC02/CAP02. This records the reconciliation, not approval of those product choices. The original handoff transcript was not reread in this Windows review; its retained decisions are the repository's recorded evidence.

The source shows the patent agent's signature date as 12 June 2025. Filing and
publication dates and grant status remain unverified; do not infer them from
the transcript or Shepherd's map.
