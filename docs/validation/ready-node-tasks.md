# Sequential node task completion record

Work branch: `feat/ready-node-tasks`. Base: `origin/main` at
`0a9f2069f312d820332e9cc950dd847e86f6faf5`. The original dirty checkout
is preserved. Implementation is by the primary agent; Luna scouting is read-only.
The user subsequently requested committing current work and putting further
work on hold until rebooting to Windows. A subsequent request authorized
publishing this branch and opening a PR; merge is not authorized.
#87 has read-only scouting only, with no allocator
implementation. Resume instructions are in `windows-resume-ready-tasks.md`.

## Hard constraints

- Preserve unrelated work; stage only task files if staging becomes necessary.
- No commit without a request and no push without permission.
- Use existing wire contracts before dependent features. Preserve nullable metrics and units.
- Keep mesh authentication, device signatures, and chain commitments separate.
- No raw logs or device identifiers on-chain. No unrestricted shell, MDM, package
  deployment, Shepherd configuration manager, Nix workers, or hosted Jev.
- Missing capabilities return explicit errors. Fixtures, cross-builds, and
  interfaces do not establish production, device, or patent qualification.
- Go changes require `make check` and `make cross-build`; Python changes require
  `make model-check`. Verify behavior at its actual boundary.

## Completion ledger

| Result | Source/runtime paths | Check | State | Evidence |
|---|---|---|---|---|
| #25 persisted admitted mesh | networking, controller, endpoint | restart/admission/application tests, full Go checks | proved locally | Real direct UDP + HTTP across process restarts; full TLS enrollment -> persisted endpoint -> fresh process -> Tailcat -> PostgreSQL evidence before/after restart |
| #47 chain policy | contracts/release-policy.md, contracts/release-policy.json, decisions | official Base/Ethereum sources; JSON parse; diff check | proved as local decision | Base Mainnet 8453, separate chain signer/2-of-3 admin, verified finalized-head policy; no deployed contract/funding claim |
| #85 permissions and overhead | tools/probes, telemetry | service/denied access on both physical targets | blocked | No linked Windows target; second target recorded unavailable. docs/validation/collector-budget-85.md records exact measurement gaps and resume matrix |
| #87 signed evidence allocation | endpoint, telemetry/contracts | forced process restart and canonical signature verification | open, on hold by user | Scouted only; no allocator or signing command implemented |

## #25 affected paths

| Surface | Applies | Required behavior | Check/state |
|---|---|---|---|
| Entry points | yes | Controller and endpoint mesh flags, explicit provisioning | Source inspected; integrated application path passed |
| Clients | yes | Windows endpoint identity; Linux developer evidence; Darwin portability | Linux runtime and both cross-builds passed; physical Windows remains unqualified |
| Provider | yes | Pinned Tailcat, explicit self-hosted DERP only | Direct runtime passed; public defaults and missing configuration rejected |
| Contracts | yes | Reuse admitted X25519 identity and CT04, document local config | Endpoint imported identity accepted by actual PostgreSQL admission |
| Reverse state | yes | Close/disconnect; unavailable or revoked admission denies requests | HTTP denials and PostgreSQL revoked/unknown binding tests passed |
| Connection modes | yes | Direct and restart; existing relay lab remains separate | Same-host direct plus both-process restart passed; WAN and physical devices unqualified |
| Tests | yes | Real transport and durable admission, negatives | make check, cross-build, database-check, targeted endpoint mesh integration passed |
| Documents | yes | Networking, operational commands, qualification limits | Adapter, top-level networking, endpoint and decisions updated |
| Browser / chain | no | No browser interaction or on-chain action in #25 | N/A |

## Evidence limits

#47 is a documentation/configuration spike. JSON parsing and diff checks passed.
Its source links were read live on 13 November 2026. Base's derivation, chain-ID,
block-query and fee documentation support the recorded protocol assumptions;
fee ceilings are chosen limits, not measurements. Runtime implementation, live
chain checks and a deployed address are intentionally absent and disabled.
It does not change CT09 wire contracts.

## #47 affected paths

| Surface | Applies | Evidence or disposition |
|---|---|---|
| Entry points / providers | yes | Release policy defines Base Mainnet and verifier/signer requirements; no running adapter exists |
| Contracts | yes | CT09 state/commitment semantics reused unchanged; deployment descriptor is disabled |
| Reverse state | yes | Writer revocation/rotation, reorg and outage policy recorded |
| Clients / connection modes | yes | Off-chain consumers retain evidence/anchor separation; RPC outage behavior recorded |
| Documents | yes | contracts, audit contract guide, README and decisions aligned |
| Runtime / browser / device tests | no | No runtime code is introduced by this decision; follow-on chain deployment evidence remains required |

#25 commands passed on 13 November 2026:

- `go test -count=1 -v ./networking/mesh`.
- `make PYTHON=/tmp/device-audit-validation/venv/bin/python check cross-build`.
- `TEST_DATABASE_URL=<local-disposable-PostgreSQL> make database-check`.
- `TEST_DATABASE_URL=<local-disposable-PostgreSQL> go test -race -count=1 -v -run '^TestEndpointEnrollmentPostgres$' ./apps/endpoint-agent`.
- `git diff --check`.

The initial check with host Python packages failed schema-format tests. The
repository-pinned `models/test-requirements.txt` environment passed all 32 model
tests. PostgreSQL 18.6 runs only on loopback in a disposable temporary directory;
no host service configuration was changed. Local command logs are under
`/tmp/device-audit-validation/`. No physical Windows, LocalService, WAN, deployed
DERP, browser or external IdP qualification is inferred.

Reviewed PR merge is part of the issues' definition of done. The user authorized
a local commit for Windows continuation, then publishing the branch and opening
a PR. No merge is authorized. Local implementation
is reported separately from GitHub issue completion. Original dirty checkout
remains untouched. Further implementation is on hold at the user's request.
