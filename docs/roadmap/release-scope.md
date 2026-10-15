# Release scope and platform qualification

This record addresses issue #14. It preserves the fixed 12-week, 150-issue release plan and makes no patent-conformance claim. The handoff marks Windows-first as a proposal, not a user-approved target. This record keeps proposals, selected requirements, and blocked qualification separate.

## Platform matrix

A release target needs an approved OS version, architecture, hardware class, permission model, and real test machine. A cross-build or fixture does not qualify hardware.

| Platform or class | Scope status | OS, version, architecture, and hardware | Permissions | Real-machine evidence |
| --- | --- | --- | --- | --- |
| Windows endpoint | Proposed first priority; final release matrix and qualification remain open | An available development target is Windows 11 Home Single Language 25H2 build 26200.9457, x64, on an HP Victus 15-fb0xxx laptop with Ryzen 5 5600H and 15.34 GiB OS-visible RAM. This does not approve a release OS/build range or all laptops. | Tested as a standard user without elevation. Read-only CIM/log metadata availability and denied thermal access are recorded; the production service account and required rights remain unselected. | @jR4dh3y made this laptop available on 14 October 2026. Native builds, tests and a fixture binary round trip are recorded in [Windows evidence](../validation/windows-2026-10-14.md). The earlier no-machine blocker is superseded; real collector/service qualification remains open. |
| Linux endpoint | Blocked; neither included nor excluded | The validation record names a Linux amd64 development host. It does not select a Linux distribution, OS version, hardware class, or release architecture. | No Linux collection permission model is selected. | None identified as a release target. The validation record does not name a host model, owner, access, or whether the host is physical or virtual. |
| macOS endpoint | Blocked; neither included nor excluded | No macOS version, architecture, or hardware class is approved. | No macOS collection permission model is selected. | None identified. The [validation record](../validation.md) records a macOS arm64 cross-build only. |
| Other operating systems and device classes | Blocked; neither included nor excluded | No Android, iOS, or other mobile OS is selected. The specification lists desktops, laptops, servers, thin clients, tablets, mobile devices, and edge units in paragraph [0050], pages 9-10, but does not select OS and hardware combinations for this release. | No collection permission model is selected. | None identified. Each approved OS and hardware combination needs its own real test machine. |

Read-only evidence collection is the planned boundary. The endpoint must report unavailable or denied measurements as missing with a reason. No target may run unrestricted shell commands or perform automatic remediation. The exact operating-system rights and service model remain open.

The [initial validation record](../validation.md) records a Linux amd64 local run and cross-builds. The later [Windows evidence](../validation/windows-2026-10-14.md) identifies a real development laptop, owner, access, OS build, hardware and native execution results. No macOS test machine is identified. No OS or hardware target is currently qualified for release.

## Conditional scope decisions

### Asset-system integration

**Status: blocked, not selected or excluded.** The supplied specification describes integration with existing IT asset-management systems for lifecycle tracking, inventory updates, and audit logging in paragraphs [0022], page 4, and [00109], page 25. Figure 2, page 31, also depicts an IT asset-management and security-compliance layer with integration into enterprise IT systems. These descriptions establish source material to reconcile. They do not select a product adapter or mean that an integration is implemented.

No asset platform, vendor, adapter contract, data fields, permissions, owner, or acceptance evidence is selected. Resolve the source requirement through dependency #72 (SRC05) and obtain an explicit product decision before selecting an adapter. If selected, add owned, dependency-linked work and approve a release rebaseline before implementation or a support claim. Do not treat an inventory field as an asset-system integration.

### Independent network observation

**Status: blocked, not selected or excluded.** Figure 2, page 31, depicts device agents collecting CPU, memory, disk, and network metrics, then a wider IT asset-management and security-compliance layer. It does not define a separate network observer or an independent source of device truth. The local agent in that flow is not an independent network probe. The supplied specification and current decisions do not define the observer, data source, permissions, trust boundary, retention, or acceptance evidence for independent observation.

Do not treat endpoint telemetry, a separate network identity, or chain integrity verification as independent observation. Resolve the source question through dependency #72 and obtain an explicit product decision. If the product selects this capability, define its boundary and owner, add dependency-linked work, and approve a rebaseline before implementation. This record does not add a network scanner or external observation service.

## Blockers and acceptance status

Issue #14's platform acceptance criterion is **partially met**: one real Windows development machine is identified and available, with native fixture execution evidence. The final release OS/hardware/permission matrix is not approved. No additional platform is finally included or excluded, so that part of the acceptance criterion remains unmet. Before any support claim, the product owner must approve the OS version, architecture, hardware class, and collection permissions, identify a real machine for every additional claimed target, and complete the implementation and qualification gates.

Dependency #72 (SRC05) must reconcile the supplied source before the project can close the asset and broader-embodiment questions. The product owner must separately select or exclude asset integration and independent observation. No asset system, independent observer, or platform target is selected here.

The release remains the full 12-week, 150-issue plan. This record does not remove or defer existing release work. Any approved scope expansion requires an owned, dependency-linked rebaseline; it is not implied by this backlog or by the specification's broader embodiments. Existing exclusions remain in force, including MDM, configuration management, package rollout, unrestricted shell agents, and automatic remediation.

## Source provenance

The supplied source is `/home/radhey/Downloads/patent.pdf`. It has SHA-256 `f06a9046a10b76495176303c228cdcfe8a0bbe560efe564782055908f8a0a771` and contains 31 PDF pages. The asset references above were checked against the supplied file. Paragraph [0078], page 19, and Figure 2, page 31, show broader enterprise integration and cybersecurity context. Figure 2 also depicts automatic tuning and self-repair; those broader examples do not override the project's existing exclusions.

These references record source text and illustrations, not legal coverage or a completed claim reconciliation. Dependency #72 remains outside this issue.
