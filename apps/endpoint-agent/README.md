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
Error evidence carries message digests, never message text. This is a local
operator check: assignment signature, target and expiry checks are DIA03 #38.
See [probe-catalog-36.md](../../docs/validation/probe-catalog-36.md).

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
refuses evidence storage open to anyone else. It creates `identity` itself
with the private DACL described above, so provisioning and every later read use
the same service token. On first start without an admission receipt, it
validates the TLS settings, then reads `enrollment\bootstrap.json` and enrolls.
The file is deleted once admission is confirmed, or at once when invalid or
expired; after a failed enrollment it stays in place for the SCM retry. A bootstrap file found beside an admitted identity is deleted
unused. No configured path may lie inside `state_dir`.

The pipeline is the `--sample` schedule (default, or `sampling_config`). Each
snapshot with a known metric becomes telemetry v2 for the admitted device ID
and is signed with the crash-safe sequence. The signed envelopes are appended,
one per line and synced, to `evidence\signed-evidence.jsonl`. A crash can tear
the final line; the next start truncates it, leaving a sequence gap. When the
file would exceed `max_evidence_bytes` the service stops with an error instead
of dropping evidence. Delivery and a retrying spool are #27. Each clean stop
writes a `sampling-report-*.json`; `service.log` records starts, the token,
failures and budget summaries. Stop and shutdown cancel the workers and wait
at most 25 s. A collector failure becomes a null with a reason and sampling
continues.

Exit codes: 1 configuration or evidence ACL, 2 refused account or privilege,
3 pipeline failure, 4 workers did not stop. `Uninstall-EndpointService.ps1`
keeps the state unless `-PurgeState` is given, and refuses to purge a
directory holding anything but the endpoint's own entries. This is a development install, not the
signed release installer (#57). See
[windows-service-26.md](../../docs/validation/windows-service-26.md).

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
verified acknowledgement JSON. A signed rejection, such as `replay` after a lost
reply, exits non-zero. Keep the envelope: replay does not prove that this
payload was stored.
With `TEST_DATABASE_URL` set, `TestEndpointEnrollmentPostgres` continues through
a fresh endpoint process and an actual Tailcat application request before and
after mesh restart. After the restart it resends the first sequence and checks
the signed `replay` acknowledgement. The controller side of that test uses the Unix or Windows
mesh state store of the host running the test. The repository's Windows CI job
does not start PostgreSQL, so that combined path is a database-check result on
a host where the database is configured. Windows device/service execution on
the selected laptop remains unqualified.
