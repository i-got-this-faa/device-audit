# Diagnostic wire contracts v1, CT06 #76

`diagnostics_v1.go` and `diagnostics-v1.schema.json` publish two off-chain
namespaces. They do not implement scheduling, probe execution, authorization,
cancellation delivery, durable terminal state or evidence storage. All fixture
measurements, references, keys and times are synthetic or public test material.
Existing v1 workflow types and HTTP routes are unchanged.

## Assignment and limits

`device-audit.diagnostic-assignment.v1` uses #75's application signing header.
Here `signing_key_id` fingerprints a trusted controller key, and `device_id` is
exactly one target. Sequence is a monotonically increasing, durable stream per
controller/deployment/target, separate from the device evidence/result stream.
It is not a mesh identity or a browser administrator credential. Authorization
must bind the controller key to this deployment and target before execution.

Two read-only probes are provisionally allowlisted:

| Probe | Required arguments | Other argument values |
| --- | --- | --- |
| `storage_health.v1` | Opaque inventory `component_id` | `lookback_seconds` and `max_entries` null |
| `system_errors.v1` | `lookback_seconds` in 1..86400, `max_entries` in 1..256 | `component_id` null |

All argument keys are required. These probes reserve contracts; no OS collector
or permission capability is implied. Component IDs must resolve locally to an
eligible storage component, never an arbitrary path. Error evidence is structured
and bounded, with references to off-chain content, never an inline raw-log upload.
Unknown fields, including `command`, `shell`, script, executable and URL arguments,
are rejected at every object level. No generic executor is selected.

`budget.wall_seconds` is 1..300 and `max_output_bytes` is 1..1048576 across all
referenced result evidence. Assignment `expires_at` is the execution deadline,
strictly after issue and at most 24 hours later. The full wall budget must fit
inside that interval. `CanStart(now)` rejects pre-issue, expired or too-late
starts, including an insufficient remaining budget. A start whose budget ends
exactly at the deadline is allowed. Runtime must stop by the earlier of that
budget and deadline; success may finish exactly at the deadline. Output limits
apply while collecting, before storage/upload, not only at result validation.

## Terminal results and correlation

`device-audit.diagnostic-result.v1` is signed by the target device. It binds
assignment ID and SHA-256 of the assignment signing bytes plus raw signature,
using `EnvelopeRequestSHA256V1`. This digest identifies the authenticated signed
assignment rather than an arbitrary JSON serialization. `CheckAssignment`
checks deployment/device/assignment/digest, start/finish order, runtime and
aggregate output bounds. It does not verify signatures, resolve references or
consult durable state. Consumers must authenticate both objects separately.

`started_at` is null if execution never began. `finished_at` is the terminal
observation time, no later than result issue time. The result envelope has an
independent delivery expiry at most 24 hours after issue. `boot_id` identifies
the original execution boot, including when a later boot reports interruption.
Device result sequences share #75's durable evidence sequence space, starting
at 2, surviving reboot and key rotation. Freshness/replay checking for these new
namespaces is consumer work; #75's `FreshnessRejection` does not accept them.

| Terminal state | Required reason and evidence |
| --- | --- |
| `succeeded` | Non-null start, null reason, 1..8 evidence references |
| `failed` | Non-null start, `probe_error`, `budget_exhausted` or `permission_denied`; optional partial evidence |
| `cancelled` | `cancel_requested`, no evidence, nullable start |
| `expired` | `deadline_exceeded`, no evidence; terminal observation at/after deadline |
| `rebooted` | Non-null original start, `agent_restarted`, no evidence |
| `rejected` | Null start, `assignment_denied`, no evidence |

Each reference has an opaque local reference ID, lowercase SHA-256 and positive
size in bytes. Reference IDs are unique in a result. Resolver access control,
retention and byte/digest checks remain required. Missing evidence cannot become
a successful diagnostic merely because a signature verifies. Expiry and reboot
may be observed after the execution budget; this does not authorize continued
execution. A reboot never resumes or re-executes the original assignment.

Before execution, atomically persist assignment admission and original boot ID.
A cancellation request must itself arrive through an authenticated, authorized
channel bound to deployment/device/assignment; this PR does not define its
transport. First committed terminal result wins. Cancellation after success
returns the committed success; it cannot replace it. An exact retransmission of
the same signed result/digest is an idempotent duplicate even after its sequence
was consumed; authenticate it and return the stored receipt without rerunning.
A different result digest for the same assignment is a conflict, not a second
terminal transition. Persist result, receipt and sequence atomically. Replay or
recovery must never infer success from a consumed sequence alone. These are
consumer obligations, not an implemented state machine.

`duplicate_succeeded_same_envelope` repeats `succeeded` exactly. `cancelled`
illustrates a cancellation during execution; `rebooted` preserves the original
boot and start after restart. Fixtures also include expiry, denial, failures,
invalid budgets, unknown commands, mixed arguments and a tampered target.
Another owner's review of admission/reboot/duplicate semantics remains required
before a consumer implements this proposal.

## Signing and verification evidence

Use #75's Ed25519, lowercase key fingerprints and whole-second UTC timestamps.
Signing bytes start with `device-audit/signature/v1` and a NUL byte, then
big-endian uint32-length-prefixed UTF-8 strings. The schema version is the first
field and separates these namespaces from enrollment and evidence signatures.
The common fields, in order, are `schema_version`, `deployment_id`, `device_id`,
`signing_key_id`, decimal `sequence`, `issued_at`, `expires_at`.

Assignments append `assignment_id`, `probe_id`, argument `component_id`,
`lookback_seconds`, `max_entries`, then budget `wall_seconds`, `max_output_bytes`.
Results append `assignment_id`, `assignment_sha256`, `boot_id`, `started_at`,
`finished_at`, `state`, `reason`, evidence count, then each reference's
`reference_id`, `sha256`, `size_bytes` in array order. Null becomes an empty
string; present numbers use unsigned decimal without leading zeros. Empty
strings are invalid present values, so null encoding is unambiguous.
`SigningBytes` permits absent signature; completed messages must pass `Validate`
and `VerifySignature` with the correct externally trusted key.

Go rejects missing/null required values, unknown/duplicate keys and fractional
integer tokens, and checks semantic invariants and signatures. JSON Schema
checks shape/scalars and probe/state alternatives; time comparisons, lifetime,
unique reference IDs and assignment correlation require Go semantic checks.
Python checks every fixture's schema expectation and independently reconstructs
canonical bytes, without claiming signature authentication. All fields are
required, including explicit nulls. Input size/depth limits belong to the
receiving transport, before decoding.

```sh
go run packages/contracts/fixtures/diagnostics/generate.go
make check cross-build
```

No live endpoint, controller authorization, durable restart/replay, cancellation
race or evidence resolver is exercised by these contract tests. Network
admission, application signatures, administrator sessions and future chain
commitments remain separate. No raw logs or device identifiers go on-chain.
