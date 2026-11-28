# Endpoint identity storage, SEC02 #23

The endpoint can explicitly enroll separate Ed25519 application-signing and
X25519 network identities through the existing bootstrap v1 protocol. It saves
keys before sending proofs, pins their deployment/device scope, and saves a
public admission receipt only after a matching HTTP 201 response. Normal status
reads never provision keys. There is no default mode: unsigned synthetic
telemetry over loopback needs `--fixture`, which prints
`provenance=fixture` on standard error. Enrollment does not enable production
mesh or authenticated telemetry delivery.

## Enroll and inspect

Obtain a one-use bootstrap-token.v1 JSON document through the authorized
[administrator enrollment flow](../../infra/enrollment/README.md). Deliver its
bytes directly on standard input through an approved private channel. Do not
put its token in command arguments, environment variables, terminal history or
logs. The examples below contain no credential.

```sh
endpoint-agent --enroll --state-dir /private/parent/endpoint-identity \
  --enrollment-origin https://controller.example.org --ca-file /path/to/ca.pem
endpoint-agent --identity-status --state-dir /private/parent/endpoint-identity
```

`--ca-file` is optional when the controller uses the system trust store.
Specifying it replaces the trust roots for enrollment. There is no insecure TLS
option, redirect following, proxy environment lookup or plaintext enrollment.
Only a bare HTTPS origin is accepted. Treat selecting the correct origin and
CA as operator authorization. Responses and errors never echo server bodies,
bootstrap credentials, private keys or decrypted network proofs. Status prints
only the public receipt. It proves local retained admission, not current remote
authorization, revocation status or connectivity.

The parent directory must already exist and be protected against replacement
by unrelated users. The endpoint creates only its own final directory. The
state directory is exclusive to this installation and process account. Files
are size-bounded, regular, single-link files. Reparse points/symlinks for the
identity directory or state files are rejected. An OS lock prevents concurrent
operations and is released when the process exits. `identity.lock` persists as
an empty file; never delete it while any endpoint operation is running.

## Windows boundary

Windows stores the key bundle through user-scoped DPAPI with UI disabled.
The directory has a protected DACL granting full access to SYSTEM and the
enabled per-service SID. OWNER RIGHTS grants only READ_CONTROL to suppress the
owner's implicit WRITE_DAC, so another LocalService process does not obtain
access solely by sharing the owner SID. Files inherit this DACL. Each open
checks the owner, exact allowed ACL and file/link type. Unexpected grants or
unreadable ACLs fail without repairing permissions or replacing keys.

LocalService without an enabled per-service SID fails. Interactive development
uses the process user SID instead. Run provisioning and later reads under the
same account and service token. Interactive provisioning does not qualify or
initialize the LocalService installation. The service host below (#26)
enrolls under its own token; the release installer and operator walkthrough
remain #57/#64. Administrators and SYSTEM can
override filesystem protection; this does not defend against a compromised
administrator, the endpoint process or its authorized principal. DPAPI backup,
profile loss and account migration require an explicit recovery design.

## Unix development boundary

Linux and Darwin use current-owner directory mode 0700 and file mode 0600,
reject hard links, and flush files plus the directory. A SHA-256 checksum detects
accidental key-file corruption. This is access-controlled plaintext development
storage, not a keychain, TPM or encryption-at-rest claim. These platforms remain
outside the selected V1 endpoint support matrix. Windows cross-compilation does
not qualify DPAPI, DACL inheritance, disk durability or LocalService execution.

## Failure and recovery

Keys, pending scope and admission receipt are created exclusively and never
overwritten. Missing keys next to scope/receipt, partial creation, corruption,
bad permissions, mismatched scope, invalid challenge, wrong-key proofs and
mismatched receipts fail closed. A failed initial write can leave a partial file;
this deliberately blocks retries rather than replacing identity. Restart reuses
the same key bundle and receipt. A pending enrollment may retry its existing
tuple; an admitted installation returns its saved receipt without redemption.

A dropped admission response is uncertain. A consumed-token rejection cannot
establish whether a previous request committed. Keep the entire state directory,
stop retrying, and reconcile with an authorized operator. Do not delete keys,
reset permissions or issue a replacement identity as an automatic recovery step.
Receipt reconciliation, key rotation, revocation, backup/restore and deletion are
separate work. Local rollback of the public receipt is not remote de-admission.
The receipt is not a signed acknowledgement or blockchain evidence. No endpoint
identifier, raw telemetry or private material is written on-chain.

## Signed evidence and sequence allocation, SEC07 #87

An admitted installation signs CT04 `device-audit.evidence.v1` envelopes:

```sh
endpoint-agent --sign-evidence --state-dir /private/parent/endpoint-identity < telemetry-v2.json
```

Standard input is one exact `device-audit.telemetry.v2` payload (at most
262144 bytes) whose `device_id` matches the admission receipt. The payload is
validated before a sequence is consumed and is hashed as supplied, never
re-encoded. The envelope binds the receipt's deployment, device and signing key
ID, a one-hour submission validity window and a freshly reserved sequence. The
signer verifies its own signature before printing the envelope. Errors are
generic and never echo payload content or key material.

`sequence.state` holds the reservation high-water mark beside the receipt,
bound to the admitted scope and protected by a SHA-256 checksum. Enrollment
creates it at mark 1 before saving the receipt. Each signature first writes the
next mark to a private temporary file, flushes it, renames it over the state and
flushes the result (plus the directory on Unix) before signing. A crash before
the rename leaves the old mark, whose next value was never signed. A crash after
it leaves a gap, which v1 permits. Missing, corrupt, out-of-scope, below-receipt
or exhausted state fails closed; the endpoint never restarts from the receipt.
Admitted installations from before this change lack `sequence.state` and must be
reconciled by an operator rather than reset.

This produces and signs evidence only. An already signed envelope can be
submitted over the admitted mesh, as described below. Spooling the signed
request for retry remains separate work.
Restoring an older state directory can reopen used local sequences; the
controller's durable mark still rejects them as `replay`. The signature proves
integrity and key possession, not sensor truth.

## Feature preprocessing, ML07 #102

```sh
endpoint-agent --sample --device-id <admitted device ID> --sampling-duration 1m \
  | endpoint-agent --features --as-of 2026-11-23T12:00:00Z
```

`--features` reads one `device-audit.telemetry.v2` payload per line, as
`--sample` prints them, and prints the frozen `hdd-smart-7d.v1`
[feature vector](../../packages/contracts/features-v1.md) for the seven UTC days
ending at `--as-of`. It reads no collector, needs no state directory and signs
nothing. A line over 256 KiB, an invalid payload or an unknown field stops it
with no output.

Telemetry v2 carries no SMART counter and no endpoint collector reads one, so
the vector is always `incomplete` with `no_observation` on all six features. That
is the declared outcome, not an error; a model must not read it. The command
exists to run the endpoint pipeline on real output. It does not predict health.

## Endpoint telemetry, TEL05 #91

```sh
endpoint-agent --collect-telemetry --device-id <admitted device ID> > telemetry-v2.json
endpoint-agent --sign-evidence --state-dir /private/parent/endpoint-identity < telemetry-v2.json
```

`--collect-telemetry` reads every collector source once and prints one
validated `device-audit.telemetry.v2` payload with `source = endpoint`. It
needs no state directory and never reads a hardware identifier; `--device-id`
must be given explicitly. Signing rejects a payload whose `device_id` differs
from the admission receipt. Per-source providers, observation times and network
rates are not on the v2 wire. On non-Windows hosts no source is selected, so the
command fails rather than emitting nulls only. See
[telemetry-91.md](../../docs/validation/telemetry-91.md).

## Scheduled sampling, TEL08 #94

```sh
endpoint-agent --sample --device-id <admitted device ID> \
  --sampling-config sampling.json --sampling-duration 10m --sampling-report report.json
```

`--sample` runs every configured source on its own interval and prints one
validated `device-audit.telemetry.v2` payload per emit interval. The
configuration (`device-audit.sampling-config.v1`) is strict JSON. Without
`--sampling-config` the built-in default samples all eight sources at 15 s,
except the NVIDIA tool at 60 s, and emits every 60 s. This example is not the
default: it schedules only two sources, so the other six are not sampled.

```json
{
  "schema_version": "device-audit.sampling-config.v1",
  "emit_interval": "60s",
  "budget": {"max_cpu_percent_one_core": 2, "max_rss_bytes": 67108864},
  "sources": [
    {"source": "cpu", "interval": "15s", "deadline": "5s"},
    {"source": "gpu_vendor", "interval": "60s", "deadline": "5s"}
  ]
}
```

Unlisted sources are not sampled. Intervals are 5 s to 300 s; a deadline is
positive, at most 30 s and at most its interval. A provider still blocked from
its previous read is not started again; that tick is `collection_error` /
`provider_busy`. A result older than its interval plus deadline plus 1 s is
emitted as `stale_result`, never as a current value. The report records reads,
nulls by reason, busy skips, overruns and the process CPU and peak RSS against
the declared budget. The command exits 1 when the budget is exceeded. Process
CPU excludes child processes such as `nvidia-smi`. See
[sampling-94.md](../../docs/validation/sampling-94.md).

## Error evidence, TEL07 #93

```sh
endpoint-agent --collect-errors --state-dir /private/parent/endpoint-identity
```

Prints one `device-audit.error-evidence.v1` batch of new Critical and Error
records from the System and Application logs, then saves each log's read
position to `error-positions.state` in the state directory. The directory must
already exist with the private ACL; this mode does not create it or need an
admission receipt. Positions are saved only after the batch is written, so a
failed write repeats records on the next poll instead of losing them. Damaged
position state fails closed. See
[error-evidence-93.md](../../docs/validation/error-evidence-93.md).

## Read-only diagnostic probes, DIA01 #36

```sh
echo '{"probe_id":"storage_health.v1","arguments":{"component_id":"storage:disk-0","lookback_seconds":null,"max_entries":null},"budget":{"wall_seconds":30,"max_output_bytes":4096}}' \
  | endpoint-agent --run-probe
```

Runs one CT06 probe from the catalog in `packages/workflows` and prints a
`device-audit.probe-evidence.v1` document. Only `storage_health.v1`
(`component_id` `storage:disk-<n>`, an OS disk number) and `system_errors.v1`
(`lookback_seconds`, `max_entries` per log) exist. The request is strict JSON;
unknown keys, paths and other probe names are rejected with exit 2 before
anything runs. A probe that runs and fails prints a
`device-audit.probe-failure.v1` record with a CT06 reason and exits 1.
Error evidence carries message digests instead of message text. See
[probe-catalog-36.md](../../docs/validation/probe-catalog-36.md).

Probe commands require Windows and run in a worker process. The runner allows one active
worker per runner instance. A second request returns a concurrency failure
immediately. The worker has a 64 MiB hard committed-memory cap, a 56 MiB termination
threshold, five seconds of CPU time, below-normal priority and room for one process. The parent kills
and reaps it on cancellation or overrun. The output cap applies to evidence,
including any partial evidence. The small structured failure wrapper is
separate. Successful and partial evidence keep the existing schema.

Use the following command to execute a controller-signed CT06 assignment
with the same worker limits:

```powershell
Get-Content -Raw assignment.json | endpoint-agent --run-assigned-probe `
  --state-dir C:\private\identity --diagnostic-controller-key-file controller.pem
```

Use the `signed_assignment` object from the controller record or a single
assignment object from the poll response. Pin the diagnostic authority’s
Ed25519 public key on the endpoint through a trusted channel. The command validates the CT06 schema, signature, enrolled
deployment and device, and remaining wall budget. Execute assignments in
controller sequence order. The private identity directory holds claims by
assignment ID and a sequence high-water mark per diagnostic authority key.
The agent reserves a shared evidence sequence and commits the claim before
starting its worker. A second delivery is refused even after restarting the
command. Keep the claim and sequence state together with the admitted identity
during backup and restore.

The command prints one device-signed `device-audit.diagnostic-result.v1` JSON
document on stdout. Exit 0 indicates success and exit 1 indicates a signed
non-success outcome, or a failure writing stdout. Exit 2 indicates that no
result is available, such as for an invalid or duplicate assignment. Bounded
evidence referenced by a result is stored as `<reference_id>.evidence` in
the private identity directory. Retain the signed JSON separately if it needs
to be submitted or retried. If execution is interrupted after the claim is
committed, the assignment stays consumed.

Use an identity enrolled by the account running the command. The command
holds the identity lock for the duration of execution. For managed recovery,
configure the [diagnostic service outbox](#managed-diagnostic-recovery-dia06-110).
See [diagnostic-execution-38.md](../../docs/validation/diagnostic-execution-38.md)
for the standalone command's validation.

## Windows service host, TEL02 #26

```powershell
# elevated
tools/service/Install-EndpointService.ps1 -AgentPath bin/endpoint-agent.exe `
  -EnrollmentOrigin https://controller.example.org -CAFile ca.pem -BootstrapFile bootstrap.json
Start-Service DeviceAuditEndpoint
```

`--service --service-config <file>` runs only under the service control
manager. The installer creates `DeviceAuditEndpoint` as
`NT AUTHORITY\LocalService` with an unrestricted per-service SID, restricts its
token to `SeChangeNotifyPrivilege` (`sc.exe privs`), and restarts it on
failure, including a non-zero service exit code (`sc.exe failureflag 1`). At
start the service refuses LocalSystem, NetworkService, any other account, an
elevated token, a missing service SID and any privilege outside that set.

Under `%ProgramData%\DeviceAudit\Endpoint` the installer replaces every DACL
with SYSTEM and Administrators full access plus the service SID's own right. The
service SID gets read and create-folder access on the root, modify access on
`evidence` and `enrollment`, and read access on the config files. The service
requires an OWNER RIGHTS entry on evidence directories and files. This keeps
another LocalService process from changing their ACL through implicit owner
rights. When upgrading an installation that predates the entry, reinstall
with the updated script and keep the existing state. It creates `identity` itself
with the private DACL described above, so provisioning and every later read use
the same service token. On first start without an admission receipt, it
validates the TLS settings, then reads `enrollment\bootstrap.json` and enrolls.
The file is deleted once admission is confirmed, or at once when invalid or
expired; after a failed enrollment it stays in place for the SCM retry. A bootstrap file found beside an admitted identity is deleted
unused. No configured path may lie inside `state_dir`.

The pipeline is the `--sample` schedule (default, or `sampling_config`). Each
snapshot with a known metric becomes telemetry v2 for the admitted device ID
and is signed with the crash-safe sequence. The spool stores the signed bytes
in sequence order under the private evidence directory. Each clean stop writes
a sampling report. The service log records starts, failures and the number of
snapshots rejected by the spool. Before a new entry would push `service.log`
past 1 MiB, the service moves it to `service.log.previous`, replacing the
previous log. Stop and shutdown cancel the workers and wait
at most 25 s. A collector failure becomes a null with a reason and sampling
continues.

Exit codes: 1 configuration or evidence ACL, 2 refused account or privilege,
3 pipeline failure, 4 workers did not stop. `Uninstall-EndpointService.ps1`
keeps the state unless `-PurgeState` is given, and refuses to purge a
directory holding anything but the endpoint's own entries. This is a development install, not the
signed release installer (#57). See
[windows-service-26.md](../../docs/validation/windows-service-26.md).

## Signed evidence spool, TEL03 #27

The installer accepts `-MaxEvidenceBytes` (default 64 MiB) and
`-MaxEvidenceRecords` (default 4096, range 1–65536). Old configurations
without `max_evidence_records` use the default. When either limit is hit,
the service keeps all queued records, visibly rejects the new snapshot and
continues sampling. Each valid snapshot rejected at the configured limit has
already reserved a sequence. After the queue has room again, the next retained
envelope exposes those missing sequences. Sum the logged rejection counts from
all service runs that contributed to the gap. The summary's `last spool sequence`
is the highest sequence queued, acknowledged or archived. Interrupted writes
can also leave gaps. If a run has no recorded total, its sequence gap alone
cannot tell you how many snapshots the spool rejected. The queue uses one extra
record of scratch space for a transaction and retains the last acknowledged
envelope as its durable high-water mark.

A storage error, including a disk-full write, stops the pipeline. After space
is available, restart the service. Startup discards any uncommitted
`spool.pending` file and verifies the signatures of committed records. If a
committed record is truncated, startup reports corruption and leaves the file
in place for investigation.

Startup validates the committed records against the admitted public key and
reports corruption without advancing the queue. Complete records from the old
JSONL file are imported byte for byte in batches bounded by the configured
limits. While migration has more records to import, new snapshots are rejected
so they cannot pass the older records. Draining or archiving one batch lets the
next batch load. The original file stays in place until migration finishes and
can be used to resume after a crash. A bounded torn final line is saved in
`spool.legacy-tail` and reported. An oversized record or a corrupt complete
line stops migration and preserves the source for review.

For a development installation, stop its writer and run maintenance under
the same account that owns the admitted identity.

```text
endpoint-agent --spool-next --service-config <config>
endpoint-agent --spool-ack --service-config <config> --controller-ack-key-file <pinned-key.pem>
endpoint-agent --spool-session --service-config <config> --controller-ack-key-file <pinned-key.pem>
endpoint-agent --spool-drain --service-config <config>
endpoint-agent --spool-archive-expired --service-config <config>
```

`--spool-next` reads the head without dequeuing it. `--spool-ack` retires it
only after verifying a matching accepted acknowledgement from stdin. For
bulk maintenance, `--spool-session` validates the backlog once, then writes
one exact envelope line and waits for one newline-terminated signed
acknowledgement at a time. Ending input leaves the current head queued. The
session holds the storage locks until it exits.

`--spool-archive-expired` moves the expired head to a protected
`expired-<sequence>.json` file and prints its filename. This preserves its
original bytes and does not acknowledge it. The archive is capped separately
at 65,536 records and 1 GiB. If full, export older archived files to equally
protected storage while the writer is stopped. Keep the highest numbered
archive in place to prevent reimport after restart.

### Automatic delivery, TEL09 #96

Add a `delivery` object to the existing service configuration to send the
queue over the admitted mesh. Set `mesh_server_key` to the pinned controller
X25519 public key, `derp_region_file` to the DERP region JSON path, and
`controller_ack_key_file` to the pinned controller Ed25519 PKIX public key PEM
path. Both paths must be absolute and outside `state_dir`. Provision the
private `mesh-address` in the admitted identity directory using the mesh guide.
Omit `delivery` to keep the service in offline spool mode.

The service drains the backlog and wakes the delivery worker when sampling
adds records. `--spool-drain` uses the same settings, holds the storage locks
and exits when the backlog is empty. Ctrl+C interrupts a standalone drain
and leaves any unacknowledged head queued.

The worker submits the oldest envelope's exact signed bytes. It retries
connection errors, interrupted responses, HTTP 408, 429 and 5xx with jitter
between half and all of a delay that doubles from 1 second to a 1-minute cap.
Each verified acceptance resets that delay. Use an updated controller to
recover the original receipt after a reply is lost. It can reissue the same
signed acceptance for an exact request still in storage even after the
envelope expires. The endpoint checks the pinned acknowledgement signature
and the deployment, device, key, sequence and request digest before retiring
the head.

A signed rejection (including `revoked_key` or `replay`), HTTP 403 admission
denial, or an invalid acknowledgement stops delivery and keeps the queue.
The standalone command reports the failure and the service writes it to
`service.log`. The service continues to sample within the configured spool
limits. Investigate and restart the service to resume delivery. If a peer is
refused before HTTP, the endpoint sees a connection failure and retries the
head. It can report revocation specifically when it receives a verified
`revoked_key` response. An expired envelope that was never accepted can be
preserved with the explicit archive command.

See the [delivery validation](../../docs/validation/spool-drain-96.md).
Relay restart, controller restart and long-partition recovery, with
measured limits, are in [recovery-54.md](../../docs/validation/recovery-54.md)
(`make recovery-proof`).
## Verification

```sh
go test -race -count=1 ./apps/endpoint-agent
make check cross-build
```

The package tests exercise real TLS, canonical proofs, disk storage and a fresh
process reading the same identity. The TLS peer is explicitly a protocol fixture.
With `TEST_DATABASE_URL` set, `TestEndpointEnrollmentPostgres` additionally uses
the real controller enrollment handlers and PostgreSQL admission transaction.
`make database-check` includes this integration and creates a disposable database.
Windows-only tests exercise real DPAPI, overly broad and deny-read DACLs when run
on Windows. Existing Windows CI runs the package through `tools/check-windows.ps1`.
That interactive CI account does not prove the selected physical Windows laptop
or LocalService/per-service token. See the [completion evidence](../../docs/validation/endpoint-keys-23.md).

## Admitted mesh evidence submission

The [mesh guide](../../networking/mesh/README.md) documents private address
provisioning, a pinned controller public key and explicit DERP configuration.
`--transport mesh` reads an existing CT04 signed envelope from stdin, verifies
it against the stored admission/signing identity, and submits through the stored
X25519 network identity. It never emits unsigned fixture telemetry or creates
another network key. `--controller-ack-key-file` pins the controller's Ed25519
acknowledgement public key (PKIX PEM). The agent accepts a reply only after it
checks that signature and every request correlation field. It prints the
verified acknowledgement JSON after acceptance. Keep the envelope when a
rejection or interrupted response exits non-zero. Retrying an exact committed
request can recover its signed acceptance.

With `TEST_DATABASE_URL` set, `TestEndpointEnrollmentPostgres` exercises
TLS enrollment, a fresh endpoint process, a dropped reply, Tailcat reconnect,
and receipt recovery through PostgreSQL. The Windows CI job runs without
PostgreSQL. See the validation record for the platforms and paths exercised.

## Isolated inference worker, ML03 #34

Inference is opt-in in the Windows service's existing `service.json`. To
commission it, an administrator stages the four files below in a local directory
outside the service-writable evidence and identity directories. Give SYSTEM and
Administrators write access and the endpoint service SID read access. Use a
dedicated model-publisher Ed25519 public key in PKIX PEM form. Pin the SHA-256 of
an independently reviewed passing ML05 report in the protected service config.
Registry staging and endpoint activation are documented below.

```json
{
  "inference": {
    "manifest_file": "C:\\ProgramData\\DeviceAudit\\Models\\manifest.json",
    "artifact_file": "C:\\ProgramData\\DeviceAudit\\Models\\artifact.json",
    "publisher_key_file": "C:\\ProgramData\\DeviceAudit\\Models\\publisher.pem",
    "evaluation_file": "C:\\ProgramData\\DeviceAudit\\Models\\evaluation.json",
    "evaluation_sha256": "<SHA-256 of the approved report bytes>"
  }
}
```

Add the member to the existing config while the service is stopped. Omit it to
disable inference. The signed CT10 manifest must specify runtime
`device-audit-endpoint-go` version `1.0.0`, architecture `logistic-baseline.v1`,
the ordered `hdd-smart-7d.v1` features, seven parameters and the inference
purpose. The worker verifies the manifest against the configured trust root
and exact artifact bytes before scoring. It requires a passing 168-hour report
for that artifact under `ml05.v1` and uses the report's logit cutoffs. The
repository's ML02 logistic artifact failed ML05 and cannot be commissioned
with its recorded report.

The service derives the CT03 window from sampled telemetry and retains one
record per UTC day in memory. A restart rebuilds the window as samples arrive.
The collector has no SMART values in telemetry v2, so this path currently
reports `unknown` with `insufficient_evidence`. The checked-in end-to-end tests
use synthetic SMART history and a test-only report to exercise the scoring path.

The service launches at most one worker per hour from its own executable,
asynchronously after signed telemetry is queued. The worker has a two-second
deadline and bounded inputs and output. A crash, timeout or rejected model
reports `unknown` with `model_unavailable` and the next scheduled prediction
starts a fresh worker. Results are local prediction v2 records in the bounded
service log. The evidence reference identifies the signed telemetry snapshot
that triggered the inference. No prediction transport or model promotion is
introduced in this change. Issue #104 owns physical Windows LocalService
resource and interference measurements.

On Windows the worker is also restricted to 250 ms CPU and a 64 MiB working
set. The parent discards responses taking over 1 s and terminates the child
at the 2 s timeout. The [Windows budget harness](../../tools/inference/README.md)
records how to measure these limits alongside real 60-second sensor sampling.

## Offline local training, FED02 #42

Run the standalone trainer with a trusted round record exported by the
operator, a CT10 manifest signed by the pinned publisher for the `training`
purpose, and the exact base artifact named in the round.

```powershell
Get-Content -Raw .\local-training.json |
  .\endpoint-agent.exe --fit-local-candidate --training-publisher-key-file .\publisher.pem
```

The request is one local JSON object with `round`, absolute `manifest_file`
and `artifact_file` paths, and an `examples` array. Each example contains the
complete CT03 vector in `features` and the verified local Boolean outcome
`failure_within_7d`. Supply examples from one endpoint in ascending UTC-day
order, at most one per day, with a full seven-day observation horizon before
the round opens. The trainer requires 8–4,096 examples and both outcome
classes. A missing label or incomplete vector yields `insufficient_local_data`.
A different feature version yields `incompatible_features`.

`local-logistic-full-batch.v1` starts at the base intercept and coefficients
with the base's mean, scale and predictor clip. It applies eight full-batch
steps at learning rate 0.01, averaging the logistic residuals over every
example. It uses the order supplied after validation and draws no random
numbers. The local JSON result records the training configuration, base
digest, round and candidate IDs, feature version, sample and parameter counts,
canonical big-endian binary64 candidate weights in base order, and the SHA-256
of those bytes. Raw examples stay in the local request.

The offline command is for operator-run fitting and fixture verification.
Endpoint telemetry currently supplies neither the CT03 SMART counters nor
verified outcome labels. Authenticated round delivery and scheduled training
in the Windows service are still pending. Two-device qualification requires
two enrolled endpoints, reviewed local histories on each, and a shared
publisher-signed training artifact.

## Budgeted federated update staging, FED08 #113

Windows operators can run the same local request against an enrolled
endpoint's private identity directory.

```powershell
Get-Content -Raw .\local-training.json |
  .\endpoint-agent.exe --train-federated-update --state-dir C:\DeviceAudit\state --training-publisher-key-file .\publisher.pem
```

Supply a round record from the trusted operator. The enrollment deployment,
device and application signing key must match an eligible participant. The
worker verifies the publisher signature, artifact digest, training purpose,
runtime and CT03 compatibility. The parent records an attempt before starting
the worker, and permits another attempt at least 24 hours later, even after
an interruption. Use an open round.

The Windows job limits the worker to one logical processor and 256 MiB of
committed memory. It runs below normal priority, monitors peak working set,
and stops at 600 seconds or the round deadline, whichever comes first.
The parent checks AC power at launch, every 250 ms during work, and before
staging. If a battery is present, its charge must be known and at least 20%,
with neither the low nor critical flag set.

On success, the parent reserves the next shared evidence sequence and
atomically stages one `federated-update-<round-hash>.json` in the private
identity directory. The signed envelope carries the round and base metadata,
feature version, sample count and candidate weights and digest. The command
prints the staged filename, training configuration, sample count, and worker
runtime, CPU and memory counters.
Run failures leave no completed update. A restart can leave a private
temporary file or a sequence gap. The completed filename is the handoff
boundary. Its expiry is the earlier of one hour after signing and the round
deadline.

The Windows test exercises a fixture worker alongside the Windows sensor
scheduler and checks the signed update and cancellation separately. On an
HP Victus 15-fb0xxx with Windows build 26200 and Go 1.27.4, one fixture run
used 1.19 s wall time, 15.625 ms of CPU time and 62,595,072 bytes peak working
set. The scheduler delivered a valid telemetry snapshot.

This operator path requires exclusive access to the identity directory for attempt
reservation and staging, so it cannot use the live service's state
directory while the service holds it open. The command stages the envelope
locally. The controller has a signed-update admission route, and scheduled
endpoint delivery remains pending. The
[FED12 validation record](../../docs/validation/federated-minimization-117.md)
documents the captured request and log fields and what the controller can infer
from individual updates. A production-history soak and Windows LocalService
qualification remain pending.

## Stage an approved registry model, FED04 #44

Run the one-shot command under the principal that owns the enrolled private
state directory. The command takes the same exclusive state lock as the
service, so use it in a maintenance window when the service releases the lock.
The controller must have mesh transport and its model registry configured.

```sh
endpoint-agent --stage-approved-model --state-dir <absolute-private-state-directory> \
  --mesh-server-key <pinned-controller-x25519-key-hex> \
  --derp-region-file <self-hosted-region.json> \
  --model-publisher-key-file <absolute-publisher-public-key.pem>
```

The controller admits the enrolled network peer for each request and offers
only the deployment's current, promoted inference model. The agent checks
deployment, CT10 publisher signature, purpose, feature order and runtime
before it requests bytes. It then checks exact size, signed SHA-256 and the
logistic artifact layout before publishing `staged-model.json` under the
private state directory. The bundle contains the manifest, approval evaluation
digest and base64 artifact bytes. The pinned model publisher key is separate
from the enrolled device signing key and controller mesh key.

On a transfer failure, rerun the command to start again from current registry
metadata. A failed transfer preserves any earlier verified staging file, and
a retry replaces it only after verification. If a process dies during the
local commit, a `staged-model.json.tmp` file remains unpublished and the next
verified write removes it.

## Activate a staged model, FED11 #116

Add `staged_evaluation_file` to the existing `inference` object to enable
startup activation. Set it to the absolute path of the exact passing ML05
evaluation report used in the registry promotion. Give that file the same
administrator-write and service-read permissions as the other inference
inputs. Its bytes must match the evaluation SHA-256 in the staged metadata,
including whitespace. Keep the commissioned model and evaluation configured
for the first activation. The service uses the same configured publisher key
to verify both models.

Stop the service to run `--stage-approved-model` under the same private state
identity, provision the matching evaluation file, then start the service.
Startup activates the candidate on the inference goroutine while signed
sampling and delivery run. The isolated worker scores a synthetic, complete
SMART feature window and must return a valid result for the exact staged
artifact. This probe checks runtime readiness. The passing ML05 report
provides the model evaluation.

After the probe passes, one journal update under `state_dir` selects the
new active slot and preserves the previous working slot, including its
evaluation. Subsequent starts use the committed slot while activation remains
enabled. The staged evaluation file is only needed for a fresh candidate.
A failed probe leaves the previous version selected. If the process exits
before the journal commit, the next start reports an interrupted activation
and selects the previous version. Check the service log for
`endpoint model activated` or `endpoint model activation rejected` and its
reason. After correcting a rejection, run the staging command again to
request a new attempt. Leave the private journal and slot files in place.

See [validation for FED11](../../docs/validation/model-activation-116.md).

## Managed diagnostic recovery, DIA06 #110

On Windows, add `diagnostic_controller_key_file` to the service's `delivery`
object. Use the absolute path to the diagnostic authority's Ed25519 PKIX public
key PEM. Give the service SID read access to the file and keep it outside the
writable identity and evidence directories. Keep the existing mesh peer pin and
CT04 acknowledgement key settings. Start the service with a controller that
supports DIA06 reporting windows. Before changing the diagnostic key pin,
drain the active diagnostic job using the original pin.

The service polls over the admitted mesh and runs one signed assignment at a
time. It records the claim and start before invoking the bounded worker. While
the worker runs, polling can observe a cancellation after the connection returns.
An observed cancellation cancels the worker and spools `cancelled` with
`cancel_requested`. If a restart finds an unfinished job, the service polls
for cancellation before terminalizing it. It reports `cancelled` if the
controller reports a cancellation and `rebooted` with `agent_restarted` if
the job had started. A claim that never reached the start marker is reported
as `rejected` with `assignment_denied`. A process restart on the same OS
boot follows the same path. The result identifies the original boot.

The private `state_dir` holds the active job, its signed terminal envelope and
any referenced evidence. A terminal envelope commits after its evidence and
survives reconnects and restarts byte for byte, including its original
evidence references. A cancellation observed after that commit leaves the
outcome intact. Recovery of an unfinished job never launches a worker. A crash
between saving evidence and committing the terminal envelope can leave an
unreferenced local evidence file. Standalone commands from earlier versions
leave replay claims only and need their operator-retained results.

Diagnostics and telemetry share the enrolled device's sequence. The service
reports them in order and retires a diagnostic result after the pinned mesh
controller returns acceptance for that assignment, device, state and sequence.
A lost response triggers an exact retry and the controller returns the
original acceptance. Dispatch is limited to the lease. A dispatched job can
report for up to 24 hours past its signed assignment deadline, while its
result envelope remains valid. Exact retries of already accepted results
can recover their receipt after expiry.

For a permanent rejection, inspect the service log and controller job record
before resuming delivery. For an expired, unaccepted diagnostic at the head,
stop the service and use `--spool-archive-expired` with the same service config
to preserve it as `diagnostic-expired-<sequence>.json` in `state_dir`.
Restart the service to resume delivery. Claims and local evidence remain in
protected storage after result retirement. Standalone delivery commands defer
to the service while a managed job owns the sequence.

See [DIA06 validation](../../docs/validation/diagnostic-recovery-110.md).

For provenance verification and a clean Windows install, see the
[Windows package runbook](../../packaging/windows/README.md).
`--check-service-config --service-config <path>` performs the install-time
configuration and bundled model validation without starting the service.
