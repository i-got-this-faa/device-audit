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
- **#85 on hold.** The user can access the existing Windows laptop after reboot.
  A second physical target is still unavailable. Planned LocalService versus
  actual denied-permission comparisons and controlled full-system overhead
  measurements have not run. See [measurement matrix](collector-budget-85.md).
- **#87 not implemented.** Read-only Luna scouting is complete. The endpoint
  accepts a pre-signed envelope on stdin in mesh mode; it does not yet allocate
  sequence numbers or sign telemetry. Test-only manually assigned sequences
  are not an allocator. See the concrete next implementation steps below.

No issue was closed or marked complete on GitHub. Reviewed PR/merge gates remain.
The commit is local. Do not assume Windows can fetch it from GitHub until a push
has been explicitly authorized and verified. A portable Git bundle is produced
alongside the handoff for transfer without a push.

## Bring the local branch to Windows

Save the supplied `device-audit-ready.bundle` before rebooting if the Linux
filesystem will not be accessible. In the existing Windows repository, inspect
`git status --short --branch` first and preserve unrelated work. Then import
the bundle without changing the current checkout:

```powershell
git bundle verify C:/path/to/device-audit-ready.bundle
git fetch C:/path/to/device-audit-ready.bundle refs/heads/feat/ready-node-tasks:refs/heads/feat/ready-node-tasks
```

Switch to `feat/ready-node-tasks` only when local changes permit it, or create a
separate worktree for that branch. Do not reset the Windows checkout. If the
branch is later pushed with permission, fetch it from `origin` instead.

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

## #87 first implementation action

Read `apps/endpoint-agent/{identity.go,storage_windows.go,storage_unix.go}` and
`packages/contracts/{envelopes_v1.go,envelopes-v1.md}`. Preserve the existing
exclusive identity lock and stored admission binding. Enrollment reserves 1;
evidence starts at 2 and cannot exceed 9007199254740991. Gaps are allowed.

Implement a durable reservation before signing. A process killed after a
reservation must burn that number; a process killed after signing must recover
the exact persisted request or use a higher sequence. Never sign different
payloads at the same sequence. Missing/corrupt/mismatched state must fail closed
once admitted, never reset to 2. Windows replacement/flush semantics need native
review and forced-process evidence; Unix rename/directory-fsync assumptions do
not prove Windows durability. Backup rollback needs an external monotonic
authority or reconciliation and cannot be detected by a lone local counter.

Reuse CT04 `SigningBytes`, exact payload-byte SHA-256 and Ed25519 signature
rules. Bind deployment/device/signing ID to stored admission, preserve nullable
v2 metrics and units, and keep all signing material out of telemetry/logging.
Test kill-before-sign, kill-after-sign, restart, concurrent process exclusion,
corruption/missing state, scope mismatch, max sequence/exhaustion and altered
payload/golden-vector verification. Persist the signed request before first
send; bounded spool and signed receipt work remain separate #26/#89 tasks.

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
