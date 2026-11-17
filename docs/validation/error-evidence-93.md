# Structured Windows error evidence, TEL07 #93

Status on 17 November 2026: **the bounded error-evidence reader, persistent read
positions, failure-path tests and a real run on the HP Victus target are
recorded. The second physical target and service-token runs are not.**

## Selected sources

The System and Application logs, levels 1 (Critical) and 2 (Error), as
selected for evaluation in the [release scope](../roadmap/release-scope.md).
The Security log is not selected; the collector refuses any other log name.

## What was built

`packages/telemetry/events*.go` adds `ErrorCollector`. On Windows it calls
`wevtapi.dll` directly (`EvtOpenLog`/`EvtGetLogInfo`, `EvtQuery`/`EvtNext`,
`EvtRender` with a system render context, `EvtFormatMessage`). No PowerShell,
shell, WMI session or install is used.

One poll returns a `device-audit.error-evidence.v1` batch with
`provenance = endpoint_event_log`. Each log has an outcome, a continuity value,
its records, a skipped count, `more` and the next read position.

| Record field | Bound |
| --- | --- |
| `log`, `record_id` | source reference |
| `time_created` | event creation time, UTC, 100 ns precision |
| `provider` | at most 256 bytes |
| `event_id`, `level` | `level` is 1 or 2 |
| `message`, `message_status`, `message_bytes` | at most 2,048 bytes, cut at a rune boundary; `message_bytes` is the size before bounding |

At most 256 records per log per poll, matching the `system_errors.v1` ceiling.
The first poll of a log without a position reads the last 24 hours. The event's
computer name, user SID, process and thread IDs, event data and XML are not
copied. Records are local, off-chain evidence. Nothing is written to a chain.

### Read positions and repeated polling

A position is the last examined record ID of a log and that record's creation
time. Each poll checks the saved record against the log:

| Continuity | Condition | Read starts after |
| --- | --- | --- |
| `started` | no saved position | record 0, last 24 hours |
| `continued` | the saved record exists with the same creation time | the saved record |
| `rollover` | the saved ID is below the oldest record (overwritten) | the saved record; unread older errors may be lost |
| `reset` | the saved ID is above the newest record, the log is empty, or the ID now has a different time (cleared or replaced) | record 0 |

The query is `EventRecordID > position`, so a repeated poll cannot return an
already collected record. After a complete read the position moves to the
newest record seen by `EvtGetLogInfo`, so the anchor stays live even without
new errors. Records returned out of order fail the log instead of moving the
position backwards. A full batch sets `more`, and the next poll continues from
the last returned record.

`endpoint-agent --collect-errors --state-dir <dir>` writes one batch to
standard output and only then saves the new positions to
`error-positions.state` in the private state directory. The file is a SHA-256
checksum plus a versioned JSON body, written through the same
temp-file/flush/rename path as `sequence.state`. A failed output write saves
nothing, so the next poll returns the same records. A crash after the write
and before the save can repeat them; consumers deduplicate on `log` and
`record_id`. Damaged or unknown position state fails closed and is never reset.

### Bounded outcomes

| Case | Outcome |
| --- | --- |
| Log query denied (`ERROR_ACCESS_DENIED`) | log `permission_denied` / `event_log_access_denied`; saved position kept |
| Log absent (`ERROR_EVT_CHANNEL_NOT_FOUND`) | log `log_unavailable` / `event_log_absent`; position kept |
| Deadline expired, other API failure, out-of-order records | log `collection_error` / `timeout`, `event_..._failed` or `record_order_invalid`; position kept |
| System properties cannot be rendered within 64 KiB, or a field has the wrong type, no record ID, no time or a level other than 1 or 2 | not recorded; `skipped` incremented; the position still advances past it |
| Message longer than 2,048 bytes | `truncated` |
| Invalid UTF-16, invalid UTF-8 or control characters other than newline and tab | `malformed`; replaced with U+FFFD, then bounded |
| Message larger than the 32 Ki-character read buffer | `oversized`; message empty |
| No publisher metadata or message template | `unavailable`; message empty |

A failure on one log does not stop the next log.

## Tests

`packages/telemetry/events_test.go` runs on every OS against an in-memory log:

- `TestErrorCollectorRepeatedPollingDoesNotDuplicate`: polls across
  non-error records and new arrivals never return a collected record.
- `TestErrorCollectorBatchLimitContinues`: a limit of 2 over 5 errors returns
  each exactly once over three polls.
- `TestErrorCollectorRolloverAndReset`: overwritten records give `rollover`;
  a cleared log, a replaced log with the same IDs, and an empty log give
  `reset`. None skips or repeats a present record.
- `TestErrorCollectorFailuresAreBoundedPerLog`: permission denial, an absent
  log, a timeout, out-of-order records and cancellation. The denied log keeps
  its saved position and the other log is still read.
- `TestErrorCollectorMalformedAndOversized`: undecodable and timeless events
  are skipped and passed; truncated, malformed, oversized, unavailable and
  lone-surrogate messages and a 1,000-byte provider are bounded.
- `TestDecodeUTF16`, `TestBoundTextCutsAtRuneBoundary`.

`packages/telemetry/events_windows_test.go` uses the real Windows event log:
two polls of System and Application with no repeated record, and the Security
log under a standard token classifying as `permission_denied`.

`apps/endpoint-agent/errors_test.go`: positions survive a store reopen, a
failed output write commits nothing, a denied log keeps its saved position,
damaged state fails closed, and on Windows two real polls through the private
store return no repeated record.

## HP Victus run, 17 November 2026

Same machine and account as [telemetry-91.md](telemetry-91.md#hp-victus-run-17-november-2026):
interactive standard user, not elevated, private state directory created with
the agent's DACL.

```powershell
endpoint-agent --collect-errors --state-dir <private dir>   # twice
```

| Poll | Log | Outcome | Continuity | Records |
| --- | --- | --- | --- | ---: |
| 1 | System | `read` | `started` | 11 |
| 1 | Application | `read` | `started` | 0 |
| 2 | System | `read` | `continued` | 0 |
| 2 | Application | `read` | `continued` | 0 |

The 11 System record IDs were exactly those `Get-WinEvent` returned for System
levels 1–2 in the same 24 hours. Their providers were Service Control Manager
(7000, 7009, 7023), Microsoft-Windows-DistributedCOM (10005),
Microsoft-Windows-TPM-WMI (1040) and TPM (14, six times). Every message status
was `complete`. `Get-WinEvent` also found no Application error in the window.
An earlier test run on the same day saw one Application error; it was written
at 14:43 UTC on 16 November and had left the 24-hour window by the second run.

The real Security log returned `permission_denied` / `event_log_access_denied`
to this token. A nonexistent log returned `log_unavailable` /
`event_log_absent`. That is an observed OS denial, not a simulated status.

## Not done

- **Second physical target.** It is recorded as unavailable in the release
  scope. The acceptance item for both targets stays open.
- **Service tokens.** The LocalService and denied-account runs of #85 do not
  yet exercise `--collect-errors`. Whether LocalService can read System and
  Application by default is unmeasured.
- **Observed rollover, clear and oversized messages.** Covered by tests, not by
  an event on this laptop. Clearing a log needs administrator rights, which the
  collector does not use.
- **Delivery.** A batch is printed. Spooling, submission, a `log_references`
  entry in telemetry v2 and controller ingestion remain separate work.
