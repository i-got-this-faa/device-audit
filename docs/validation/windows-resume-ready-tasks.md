# Resume the ready node tasks from Windows

Paused at the user's request on 13 November 2026 to commit current work before
rebooting to native Windows. Branch: `feat/ready-node-tasks`, based on
`origin/main` at `0a9f2069f312d820332e9cc950dd847e86f6faf5`.
Linux worktree: `/home/radhey/code/device-audit-ready`.
The original `/home/radhey/code/device-audit` dirty checkout was left untouched.

## Completed and remaining work

- **#25 implemented locally.** Persisted admitted Tailcat client/server adapter,
  existing endpoint X25519 identity import, separate administrator/bootstrap
  HTTPS and signed-evidence application mesh. Direct process-restart, unknown
  peer, HTTP authorization and PostgreSQL tests passed. Full enrollment ->
  protected endpoint state -> fresh endpoint process -> Tailcat -> PostgreSQL
  evidence passed before and after both peer restarts. Physical Windows,
  LocalService, NAT/WAN and deployed service qualification remain open. See
  [adapter commands and limits](../../networking/mesh/README.md).
- **#47 decision recorded.** Base Mainnet 8453, dedicated writer, 2-of-3
  administrator, L1-derived finality and failure/cost policy. The deployment
  descriptor is disabled with no contract, account or credentials. No chain
  transaction or live deployment was attempted. See
  [release policy](../../contracts/release-policy.md).
- **#85 partially measured; qualification on hold.** Existing Windows probe code
  and earlier single-laptop measurements are merged through PRs #169/#181.
  A second physical target is still unavailable. LocalService versus actual
  denied-permission comparisons and controlled full-system overhead remain.
  See [measurement matrix](collector-budget-85.md).
- **#87 implemented in separate [PR #198](https://github.com/i-got-this-faa/device-audit/pull/198).**
  Its `ee5bd74` commit adds `--sign-evidence`, scope-bound `sequence.state`,
  durable reservation before signing and forced-process restart/golden-vector
  tests. Native Windows validation is recorded there; all reported CI checks
  passed when inspected. It is open and is not included in this branch. The
  earlier "scouted only" statement described this branch's contribution, not
  the current repository-wide status. Do not reimplement its allocator.

No issue was closed or marked complete on GitHub. Reviewed PR/merge gates remain.
The user subsequently requested a PR for this committed work, authorizing branch
publication. Fetch `feat/ready-node-tasks` from `origin` after its remote head is
verified. A portable Git bundle was also produced at the pause for offline
transfer; the published branch is the current source for later handoff updates.

## Bring the branch to Windows

In the existing Windows repository, inspect `git status --short --branch` and
preserve unrelated work. For the published branch:

```powershell
git fetch origin
git switch --track origin/feat/ready-node-tasks
```

If that local branch already exists, switch to it, inspect divergence with
`git rev-list --left-right --count HEAD...origin/feat/ready-node-tasks`, and
fast-forward with `git merge --ff-only origin/feat/ready-node-tasks` only when
local changes permit it. A divergent branch needs reconciliation, not a reset.
Use a separate worktree if local changes prevent switching safely.

Save the supplied `device-audit-ready.bundle` before rebooting if the Linux
filesystem will not be accessible. In the existing Windows repository, inspect
`git status --short --branch` first and preserve unrelated work. Then import
the bundle without changing the current checkout:

```powershell
git bundle verify C:/path/to/device-audit-ready.bundle
git fetch C:/path/to/device-audit-ready.bundle refs/heads/feat/ready-node-tasks:refs/heads/feat/ready-node-tasks
```

Switch to `feat/ready-node-tasks` only when local changes permit it, or create a
separate worktree for that branch. Do not reset the Windows checkout. Prefer
the published branch to the earlier bundle when GitHub is available.

## First Windows checks

Use PowerShell 7, the repository's Go 1.27.1 toolchain, a working race-compatible
GCC and Python with pinned test dependencies. Existing bootstrap credentials,
PSKs, identity files and raw reports must stay private and out of Git.

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r models/test-requirements.txt
./tools/check-windows.ps1 -Python .venv/Scripts/python.exe
```

This checks native tests/builds and the existing fixture demo. It does not
qualify service tokens or mesh delivery. Mesh **controller** persistence is
Unix-only; the Windows endpoint imports its existing DPAPI/ACL-protected
identity. Use a separately running Unix controller and explicit self-hosted
DERP for Windows endpoint transport qualification. Do not run the old lab's
Unix mode-0600 state check as proof of Windows endpoint support.

For #85, begin with the existing physical laptop/token/source matrix. Do not
claim two-machine completion, convert an interactive run to service evidence,
modify live source permissions to obtain success, or infer production cost from
the PowerShell prototype. Service-token setup and second-target access remain
explicit prerequisites.

## #87 review and integration

Fetch and inspect `origin/feat/issue-87-evidence-sequence` and PR #198's
`apps/endpoint-agent/evidence.go`, `evidence_test.go` and
`docs/validation/evidence-sequence-87.md`. The implementation reserves before
signing, initializes state during enrollment and rejects missing/corrupt,
scope-mismatched or exhausted sequence state. Its Windows tests exercise forced
exits before/after commit and kill signing loops after 1, 7 and 23 envelopes.
The RFC 8032 test seed reproduces CT04 golden bytes/signatures; altered payloads
and private-material leakage are checked. Windows native checks and contract
conformance are recorded in that PR, rather than independently rerun here.

PR #198 and #197 both modify endpoint entry points and documentation. Neither
contains the other's implementation. Reconcile those paths before claiming a
combined signer-to-mesh feature; run the actual newly signed envelope through
the admitted mesh and PostgreSQL. #198's Windows run skipped PostgreSQL because
no database was available. No merge or cross-PR integration was performed by
this status correction.

Power-loss durability, LocalService execution, old-install sequence-state
reconciliation and backup rollback remain explicit limits. Process termination
does not prove power-loss behavior. Durable signed-request spooling/retry and
signed acknowledgements remain separate follow-on tasks.

## Checks already passed on Linux

`make check cross-build` passed with the pinned Python virtualenv, including Go
vet/race/format checks, all 32 model tests, fake controller scenarios, Windows
amd64 and Darwin arm64 endpoint builds. `make database-check` passed using a
disposable local PostgreSQL 18.6. The targeted real endpoint mesh/PostgreSQL
restart test also passed with race instrumentation. Chain policy JSON parsing
and `git diff --check` passed. The initial host-Python attempt failed schema
format tests; rerunning with `models/test-requirements.txt` passed.

Linux logs were stored under `/tmp/device-audit-validation/`; temporary logs
are not required to resume and are not committed. Repeat native Windows checks
and report their actual results before making any Windows support claim.
