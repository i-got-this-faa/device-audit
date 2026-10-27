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

## Capability and acceptance boundaries

The [source map](source/patent-map.md#claim-to-requirement-map-src05--72)
contains the exact printed references and stable task owners for each row.
Source claim numbers below identify text, not a completion or coverage claim.

| Planned capability / requirement | Printed claim(s) | Current evidence and acceptance still needed |
| --- | --- | --- |
| Real telemetry and structured errors / RQ-01 | 1, 8 | The runtime uses fixtures; v2 defines a proposed nullable subset. TEL01 #21/TEL04 #85 must distinguish disk utilization from disk health/I/O, battery charge from health/life, and latency from throughput before CT03 #32 freezes features. Unavailable sensors remain missing with reasons. |
| Preprocessing, faults, predictions and health / RQ-04 | 1, 2, 8, 9 | Versioned wire contracts and model interfaces exist. ML09 #105/ML10 #106 must implement controller normalization/filtering and historical type/count/recurrence comparisons; ML06 #103 must supply held-out evaluation. Health thresholds and warning/degraded terminology remain explicit versioned choices. |
| Health-specific local analysis / RQ-05 | 1, 8 | Typed runner/task boundaries are scaffolds. DIA02 #37/DIA05 #109 must demonstrate authenticated health-specific assignments; the source's general agent replacement is an unmatched broader mechanism. No shell or remediation executor is selected. |
| Local learning and central aggregation / RQ-06 | 1, 4, 8 | Training interfaces and weighted averaging do not demonstrate federation. FED02 #42/FED03 #43/FED10 #115 require compatible training on two endpoints, validated updates and evaluated promotion. FED12 #117 must document data flows and privacy limits. |
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
