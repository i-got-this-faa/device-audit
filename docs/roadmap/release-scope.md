# V1 release scope and platform qualification

Decision record for SRC02 [#14](https://github.com/i-got-this-faa/device-audit/issues/14), 19 October 2026. The owner requested completion of this decision task and confirmed that only the existing Windows laptop is available. This concrete V1 selection replaces the earlier all-platforms-undecided record. It is an engineering decision submitted for review; merging the #14 decision PR records its acceptance. It does not claim that the owner previously selected every detail or that a platform passed release qualification.

The fixed 12-week, 150-issue plan and 4 January 2027 deadline remain unchanged. No implementation or acceptance task is removed. Source reconciliation #72 is complete. Selection, implementation, measured qualification and release approval are separate gates.

## Endpoint platform matrix

| Platform or class | V1 decision | Exact boundary and reason | Real test machine |
| --- | --- | --- | --- |
| Windows 11 Home Single Language 25H2, x64 laptop | Included as the initial qualification target | Build family 26200; initial qualification baseline 26200.9711. Hardware class: HP Victus 15-fb0xxx, Ryzen 5 5600H, 16 GB installed RAM (about 15.34 GiB OS-visible), AMD integrated graphics plus NVIDIA RTX 3050 Laptop GPU. The claim is bounded to the available configuration. Later cumulative builds require recorded regression evidence before a support claim. | One physical laptop owned by @jR4dh3y, available in this Windows session and exercised on 14 and 19 October; see evidence below. No serial, hostname or private identifier is needed to identify this test slot. |
| Other Windows 11 versions, editions, architectures and hardware | Excluded from V1 endpoint support claims | Pro/Enterprise/Education, other feature releases, ARM64, and other laptop/desktop/server/thin-client/edge configurations have no selected, available real test target. They are not covered by the x64 binary or this laptop's results. | None selected; another target needs an explicit matrix amendment and its own real machine. |
| Windows 10, Windows Server and other Windows versions; x86 endpoints | Excluded from V1 endpoint support claims | No version/build, collection permission evidence or real qualification machine is selected. | None selected. |
| Linux endpoints, all distributions and architectures | Excluded from V1 endpoint support claims | A Linux development/CI host and networking lab do not select or qualify a Linux endpoint. Controller/relay hosting remains separate under #73. | No physical Linux endpoint selected. |
| macOS endpoints, Intel and Apple silicon | Excluded from V1 endpoint support claims | Darwin arm64 cross-compilation remains a portability check; no macOS qualification machine or sensor/service evidence is available. | None available. |
| Android, iOS/iPadOS and ChromeOS endpoints | Excluded from V1 endpoint support claims | No mobile/ChromeOS runtime, permissions, package or real test machine is selected. Source device examples are not OS commitments. | None selected. |
| BSD, other embedded operating systems and every other OS/device combination | Excluded from V1 endpoint support claims | No additional endpoint target is selected; broad source examples do not implicitly expand this matrix. | None selected. |

The build number identifies the first test baseline, not evidence that all of Windows 11 or all 25H2 hardware works. A second physical endpoint matching the included class is still needed for #21/#85 and later two-endpoint gates. It is **unavailable**, not an invented second test slot or a CI substitute. Those tasks retain their two-machine criteria. #14 requires a real machine for each claimed target; one included configuration has one identified machine. Reviewing this decision does not pass later qualification gates.

This is an **endpoint** matrix. Excluding Linux endpoints does not exclude Linux development, CI, controller hosting or DERP hosting. Deployment host OS, provider and sizing remain with #73 and their implementation tasks. No cross-build or delivery task is removed by this selection.

## Windows collection and service permission model

Select read-only measurement access with these implementation requirements:

- Run the endpoint service as `NT AUTHORITY\LocalService`, with a per-service SID for its own state ACLs. LocalService is the selected account. Its actual source access must be measured under #85 and exercised by service tests in #26; the interactive user token is not a service-token test.
- Start with that account's default privileges. Blanket administrator, performance/log-reader group membership, WMI namespace grants, driver installs and security-setting changes are not selected. If a required source is inaccessible, its capability gate fails until a narrowly scoped permission proposal is measured and reviewed. Do not silently elevate or switch to LocalSystem.
- Read CPU, memory, fixed-volume space and network providers where permitted. Battery, ACPI thermal and vendor GPU sensors remain nullable with provider, units and explicit missing reasons. Thermal denial cannot become zero temperature or a healthy result. #21/#85/#91/#92 establish the actual supported subset and cost.
- Limit the error-source candidate set to System and Application logs for evaluation in #21/#93. Security-log access is not selected. Readable log metadata does not prove event-content access, durable bookmarks or correct ingestion. Required error sources and exact read rights need those tests.
- Permit writes to endpoint-owned operational state: protected identity, bounded spool and approved model staging. #23/#87/#27 must implement and test the per-service state boundary; Unix file modes do not qualify Windows ACLs. This document changes no existing machine permissions.
- Installation/service registration may need an explicit administrator install step under #57/#64. That is separate from the steady-state token. Mesh credentials and application signing keys remain separate; Windows network credentials replace neither identity.
- Keep diagnostics typed, allowlisted, bounded and read-only. No unrestricted shell executor, device configuration changes, MDM or automatic remediation is authorized by this selection.

Microsoft documents [LocalService's limited local privileges and anonymous network credentials](https://learn.microsoft.com/en-us/windows/win32/services/localservice-account) and the purpose of [per-service resource isolation](https://techcommunity.microsoft.com/blog/askperf/ws2008-windows-service-hardening/372702). Those properties support the planning choice; they do not prove our collector, storage, transport or service works under that token.

## Evidence and release gates

The [14 October record](../validation/windows-2026-10-14.md) identifies the physical laptop, hardware, standard-user access, native fixture demo and source-availability observations. The later [19 October measurements in PR #169](https://github.com/i-got-this-faa/device-audit/blob/4e1f2e5c7806406165dbbfa73a4854b643b33075/docs/validation/windows-2026-10-19.md) record the same laptop at build 26200.9711, real development probes and native checks. That evidence is pinned to its commit because #169 is a separate PR; #14 does not depend on merging its probe implementation.

No OS/hardware target is currently qualified for release. The fixture round trip uses in-memory storage and unknown health. Development probes do not establish an installed real collector, service, inference worker, authenticated diagnostics or mesh. Second-machine access, service-token checks, packaging and resource/failure-path evidence remain gates in #21/#85/#26/#104/#57/#61 and the integration/release tasks. Support is asserted only after those tests, the measured capability matrix #58 and release approval pass.

## Conditional scope decisions

CAP02 [#138](https://github.com/i-got-this-faa/device-audit/issues/138) closes
the reconciliation using the [source register](../source/patent-map.md#broader-embodiments-unmatched-passages-and-retained-exclusions).
Included means selected for the existing V1 scope. Excluded means outside
V1. Blocked means the applicable capability claim remains gated on a missing
decision or missing evidence.

| Capability | V1 disposition | Decision and release boundary |
| --- | --- | --- |
| Endpoint platforms and source device classes | Included / excluded | The [platform matrix](#endpoint-platform-matrix) under #14 selects one physical Windows laptop configuration and excludes every additional endpoint OS and hardware target. Cross-builds and controller or relay hosting do not qualify an endpoint. |
| Hierarchical controller deployment | Excluded | #73 selects one controller per organization deployment with private PostgreSQL and separate relay transport. Subordinate controllers and hierarchical failover remain outside V1. Device and group dashboard hierarchy remains included. |
| Hierarchical dashboards and on-demand reports | Included | #74 selects the console and administrator identity boundary. Existing authorized reporting and inventory work stays in scope. The console browser target does not expand the endpoint OS matrix. |
| Model update, rollback and job cancellation | Included / excluded | Signed model promotion and rollback, typed diagnostic cancellation and controlled endpoint release upgrades retain their existing tasks. Health-driven agent binary withdrawal or redeployment, arbitrary package rollout and unrestricted execution are excluded. |
| OS tuning, throttling and self-repair | Excluded | The record supports read-only diagnostics and report instructions. MDM, configuration changes and automatic remediation remain outside V1. |
| Bespoke prediction, tinyML, reinforcement learning, hybrid models and KRA optimization | Blocked / excluded | Prediction remains gated. #103 found that the frozen logistic model failed the predeclared average-precision and calibration gates. No release health classification follows. The named alternative algorithms and general KRA optimization are excluded from V1. |
| Model and evidence explanations | Included / excluded | Inspectable evidence and existing dashboard explanation work stay in scope. LIME, SHAP and generated explanations are excluded. A model explanation claim requires provenance from a qualified model. |
| Team scoring, patch-delay penalties and gamification | Excluded | Device health and sustainability scoring remain device-level work. Staff monitoring, incentives, and patch deployment are excluded. |
| Refurbishment and disposal marketplace | Excluded | Evidence-backed lifecycle analysis remains in scope. Vendor recommendations, transactions and marketplace adapters are excluded. |
| External asset-system integration | Blocked | No vendor, adapter contract, fields, credentials, retention policy or acceptance run is selected. Internal inventory and authorized console views remain included. Release owner @jR4dh3y owns any later rebaseline for this block. |
| Independent network observation | Blocked | The source does not resolve the observer, provenance, permissions, trust boundary, retention or acceptance criteria. Existing endpoint measurements and mesh transport remain in scope. Release owner @jR4dh3y owns any later rebaseline for this block. |
| Blockchain audit and AI cybersecurity | Included / blocked / excluded | #47 selects Base Mainnet for blinded commitments. Release anchoring depends on deployment, signer and finality evidence in the chain work. Raw logs and device identifiers stay off-chain. Broad AI cybersecurity automation is excluded. |
| Retained handoff exclusions | Excluded | Jev, Shepherd configuration management, Nix build workers, MDM, package deployment, unrestricted shell agents and automatic remediation remain outside V1. |

Each blocked row remains unavailable for an applicable release claim. Closing
this reconciliation records the disposition. An unresolved source conflict
keeps the corresponding release gate blocked. The
[measured capability matrix](../requirements.md#measured-release-capability-matrix-cap01-58) supplies the separate
evidence-based release gate.

CAP02 selects no additional capability. A later selection requires the
release owner and the other developer to approve a written rebaseline before
implementation or a release claim. Record the exact boundary, source conflict
and rationale, named accountable owner, issue dependencies, acceptance
criteria, measured evidence required and effect on the fixed 12-week plan.
Update this matrix, the source register, the decisions log and the dependency
links in the reviewed change. Until then the exclusion or block applies.

## #14 acceptance and review

| Acceptance item | Evidence supplied by this decision PR |
| --- | --- |
| Windows-first OS/hardware and real machine | Exact Windows/laptop qualification target, baseline build, owner/access and linked physical-machine evidence |
| Each additional platform included or excluded | Explicit V1 exclusions, including other Windows targets and all other OS/device combinations; portability and hosting remain distinct |
| Collection permissions | Selected LocalService/per-service-SID model, default privilege boundary, explicit missing-source behavior and qualification owners |
| Asset integration and independent observation | Each blocked with rationale, resolution owner and a no-implicit-expansion rule |
| Source dependency | #72 is closed; its verified source register is retained and aligned with this matrix |

The decision implementation is ready for review. #14's definition of done still requires the other developer's review and a merged PR; it must not be manually marked Done from this unmerged document.

## Source provenance

The supplied 31-page source has SHA-256 `f06a9046a10b76495176303c228cdcfe8a0bbe560efe564782055908f8a0a771`; its verified inventory is in [the source map](../source/patent-map.md). Device examples are [0050], pp.9-10. Asset references are [0022], p.4, [00109], p.25 and FIG.2, p.31. Independent-observation references are mapped against [0051], p.10, [0074], p.18, [0078], p.19 and FIG.2, p.31. These establish traceability, not extra target selection or implementation/legal coverage.
