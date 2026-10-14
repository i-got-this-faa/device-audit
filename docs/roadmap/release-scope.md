# Release scope and platform qualification

This record addresses issue #14. It preserves the fixed 12-week, 150-issue release plan and makes no patent-conformance claim. The handoff marks Windows-first as a proposal, not a user-approved target. This record keeps proposals, selected requirements, and blocked qualification separate.

## Platform matrix

A release target needs an approved OS version, architecture, hardware class, permission model, and real test machine. A cross-build or fixture does not qualify hardware.

| Platform or class | Scope status | OS, version, architecture, and hardware | Permissions | Real-machine evidence |
| --- | --- | --- | --- | --- |
| Windows endpoint | Proposed first priority, not approved; qualification blocked | Windows is the first collector direction in handoff 15 and [the backlog](../backlog.md). No Windows version or build, architecture, device class, or hardware model is approved. | The backlog calls for read-only sensor and log collection. The Windows account, service model, required rights, sensor access, and denied-access behavior are not selected. | None identified. The user confirmed on 14 October 2026 that no Windows machine is available. The [validation record](../validation.md) records a Windows amd64 cross-build on Linux, not a Windows runtime test. |
| Linux endpoint | Blocked; neither included nor excluded | The validation record names a Linux amd64 development host. It does not select a Linux distribution, OS version, hardware class, or release architecture. | No Linux collection permission model is selected. | None identified as a release target. The validation record does not name a host model, owner, access, or whether the host is physical or virtual. |
| macOS endpoint | Blocked; neither included nor excluded | No macOS version, architecture, or hardware class is approved. | No macOS collection permission model is selected. | None identified. The [validation record](../validation.md) records a macOS arm64 cross-build only. |
| Other operating systems and device classes | Blocked; neither included nor excluded | No Android, iOS, or other mobile OS is selected. The specification lists desktops, laptops, servers, thin clients, tablets, mobile devices, and edge units in paragraph [0050], pages 9-10, but does not select OS and hardware combinations for this release. | No collection permission model is selected. | None identified. Each approved OS and hardware combination needs its own real test machine. |

Read-only evidence collection is the planned boundary. The endpoint must report unavailable or denied measurements as missing with a reason. No target may run unrestricted shell commands or perform automatic remediation. The exact operating-system rights and service model remain open.

The [validation record](../validation.md) records a Linux amd64 local run, a Windows amd64 endpoint cross-build, and a macOS arm64 endpoint cross-build. It does not identify a real Windows or macOS test machine. The repository contains no machine inventory with hardware model, OS build, owner, and confirmed access. Do not infer those details from the Linux host or invent them. No OS or hardware target is currently qualified for release.

## Conditional scope decisions

### Asset-system integration

**Status: blocked, not selected or excluded.** The supplied specification describes integration with existing IT asset-management systems for lifecycle tracking, inventory updates, and audit logging in paragraphs [0022], page 4, and [00109], page 25. Figure 2, page 31, also depicts an IT asset-management and security-compliance layer with integration into enterprise IT systems. These descriptions establish source material to reconcile. They do not select a product adapter or mean that an integration is implemented.

No asset platform, vendor, adapter contract, data fields, permissions, owner, or acceptance evidence is selected. Resolve the source requirement through dependency #72 (SRC05) and obtain an explicit product decision before selecting an adapter. If selected, add owned, dependency-linked work and approve a release rebaseline before implementation or a support claim. Do not treat an inventory field as an asset-system integration.

### Independent network observation

**Status: blocked, not selected or excluded.** Figure 2, page 31, depicts device agents collecting CPU, memory, disk, and network metrics, then a wider IT asset-management and security-compliance layer. It does not define a separate network observer or an independent source of device truth. The local agent in that flow is not an independent network probe. The supplied specification and current decisions do not define the observer, data source, permissions, trust boundary, retention, or acceptance evidence for independent observation.

Do not treat endpoint telemetry, a separate network identity, or chain integrity verification as independent observation. Resolve the source question through dependency #72 and obtain an explicit product decision. If the product selects this capability, define its boundary and owner, add dependency-linked work, and approve a rebaseline before implementation. This record does not add a network scanner or external observation service.

## Blockers and acceptance status

Issue #14's real-machine acceptance criterion is **unmet**. No target OS and hardware matrix or real test machine is recorded. No additional platform is finally included or excluded, so that part of the acceptance criterion is also unmet. Before any support claim, the product owner must approve the OS version, architecture, hardware class, and collection permissions. The owner must identify a real machine for each target and confirm access.

Dependency #72 (SRC05) must reconcile the supplied source before the project can close the asset and broader-embodiment questions. The product owner must separately select or exclude asset integration and independent observation. No asset system, independent observer, or platform target is selected here.

The release remains the full 12-week, 150-issue plan. This record does not remove or defer existing release work. Any approved scope expansion requires an owned, dependency-linked rebaseline; it is not implied by this backlog or by the specification's broader embodiments. Existing exclusions remain in force, including MDM, configuration management, package rollout, unrestricted shell agents, and automatic remediation.

## Source provenance

The supplied source is `/home/radhey/Downloads/patent.pdf`. It has SHA-256 `f06a9046a10b76495176303c228cdcfe8a0bbe560efe564782055908f8a0a771` and contains 31 PDF pages. The asset references above were checked against the supplied file. Paragraph [0078], page 19, and Figure 2, page 31, show broader enterprise integration and cybersecurity context. Figure 2 also depicts automatic tuning and self-repair; those broader examples do not override the project's existing exclusions.

These references record source text and illustrations, not legal coverage or a completed claim reconciliation. Dependency #72 remains outside this issue.
