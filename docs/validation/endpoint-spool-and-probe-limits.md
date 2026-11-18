# Endpoint spool and diagnostic limits

Validation on 18 November 2026 against main at `a708501`. The changes reuse
the CT04 evidence and acknowledgement formats and the CT06 diagnostic assignment
format. The endpoint README documents the local commands and installer settings.

| Issue | Behavior | Windows evidence |
| --- | --- | --- |
| #27 | Retain queued envelopes in sequence order at either configured limit | `TestSpoolRetentionAndCorruption` exercises the byte cap, record cap, byte-preserving import, acknowledgement correlation and corruption refusal. |
| #27 | Resume an interrupted append or dequeue | `TestSpoolProcessRecovery` starts a fresh process and forces an exit immediately before and after each filesystem commit. The recovered queue contains the expected records and the original signed bytes. |
| #27 | Read and retire only the oldest envelope | `TestSpoolCommandAcknowledgesOnlyVerifiedHead` reads both stored envelopes through the maintenance path, verifies pinned signed acknowledgements and confirms the queue is empty after retirement. |
| #108 | Enforce the signed target, expiry and output budget | `TestProbeRunnerSignedBudgetAndConcurrency` exercises rejection before worker start, cancellation and the one-worker limit. `TestAssignedProbeWindowsCommand` runs the built binary against an admitted test identity. The signed 1-byte cap is reported as exhausted and an edited cap fails signature validation. |
| #108 | Bound a blocked or resource-heavy worker | `TestProbeWorkerWindowsLimits` runs separate Windows processes with the production memory cap. It exercises a hung process, excessive output, CPU exhaustion, an allocation denied by the job's memory cap, and caller cancellation. A healthy process can run after exhaustion. The CPU test uses a shorter limit to keep the check fast. |
| #108 | Run a real allowlisted provider through the local CLI | An interactive `--run-probe` command read the System and Application event logs through the isolated worker. Direct worker invocation without the job was rejected. |

The repository's `tools/check-windows.ps1` suite passed on the native Windows
account. It ran Go vet, repository-wide race tests, 51 model tests, the
controller fixtures and demo, Windows amd64 and Darwin arm64 builds, and the
Windows probe checks. Focused endpoint and workflow tests cover the changed
paths. The updated service installer and qualification scripts parse in
PowerShell.

An elevated LocalService run with the disposable PostgreSQL enrollment harness
is still unverified for this change. The available token is unelevated and has
no configured test database. The crash tests cover process exits at commit
boundaries. Physical power loss, disk exhaustion, reconnect and authenticated
network draining have their own follow-up issues. Assignment deduplication and
signed result delivery remain part of the diagnostic workflow.

## Review follow-up

Focused Windows tests exercise batch migration across a restart, byte-preserving
expired archive, a torn legacy tail, and session acknowledgement of successive
heads. The Windows access-control test verifies the inherited OWNER RIGHTS
entry and rejects both a missing entry and a grant to rewrite the DACL.
Probe tests distinguish the hard memory ceiling from reporting an observed
memory budget termination. The updated qualification harness checks that the
service retains the exact spool contents at capacity and reports a fresh
rejection. Elevated execution of that harness remains unverified.

## Overflow and disk-full recovery, TEL10 #95

- `TestServiceSpoolOverflowMatchesSignedSequenceGap` runs the sampling
  pipeline against each configured limit. It checks two reported rejections,
  exact retention of the original records, and two missing sequences between
  the last retained envelope and the next one signed after space is released
  and the pipeline restarts.
- `TestSpoolDiskFullDuringWrite` writes a partial staging file before
  injecting a disk-full error. The failed spool refuses delivery and
  acknowledgement. Reopening it through the maintenance command discards the
  partial staging file and returns the original signed envelope byte for byte.
- `TestSpoolCommittedRecordRequiresNewline` verifies that a truncated
  committed file stays in place and the maintenance command returns an error
  with no evidence output.

The disk-full check uses an injected write error and real temporary files.
Volume exhaustion, physical power loss and the installed LocalService
token remain outside this run.
