# Windows service host, TEL02 #26

Status on 18 November 2026: **the service host, its installer, failure-path
tests and two qualification runs as `NT AUTHORITY\LocalService` on the HP
Victus target are recorded. Delivery, a spool, a real collector failure inside
the service and the second physical target are not.**

## What was built

`endpoint-agent --service --service-config <file>` runs under the service
control manager (`golang.org/x/sys/windows/svc`). In order, it:

1. **Checks the token.** It requires `S-1-5-19` (LocalService). It checks
   privileges before elevation and refuses any privilege other than
   `SeChangeNotifyPrivilege`, an elevated token, and a missing or disabled
   per-service SID. It logs the account, the service SID and the privileges.
2. **Loads the admitted identity** from `identity`, which the service creates
   itself with the SEC02 DACL and user-scoped DPAPI under its own token. With no
   admission receipt, it reads the one-use `enrollment\bootstrap.json`, deletes
   it and enrolls over TLS. A bootstrap file found beside an admitted identity
   is deleted without being redeemed.
3. **Runs the pipeline.** It runs the TEL08 scheduler with the configured
   sampling config. Each snapshot becomes telemetry v2 for the admitted device
   ID, is signed with the SEC07 crash-safe sequence, and is appended to
   `evidence\signed-evidence.jsonl` with one synced line per envelope. On start,
   a torn final line from a crash is truncated, leaving a gap that CT04 allows.
   At `max_evidence_bytes` the service stops with an error rather than dropping
   evidence.
4. **Stops cleanly.** Stop or shutdown cancels the scheduler and waits at most
   25 s. Each clean stop writes a sampling report and a budget line in
   `service.log`.

Service exit codes: 1 configuration, 2 refused account or privilege, 3 pipeline
failure, 4 workers did not stop. `tools/service/Install-EndpointService.ps1`
configures these:

| Setting | Value |
| --- | --- |
| Account | `NT AUTHORITY\LocalService` |
| Service SID type | `unrestricted` (`NT SERVICE\DeviceAuditEndpoint`) |
| Required privileges | `SeChangeNotifyPrivilege` only |
| Recovery | restart after the configured delay, three times, reset after a day; `failureflag 1` so a service-specific exit code also counts |
| `%ProgramData%\DeviceAudit\Endpoint` | SYSTEM and Administrators full; service SID read + create-folder on the root only |
| `evidence`, `enrollment` | plus service SID modify |
| `service.json`, `sampling.json` | plus service SID read |
| `identity` | created by the service: SYSTEM and service SID full, OWNER RIGHTS read-control only, protected |

Interactive `--service`, `--service` mixed with another mode, and `--service`
on a non-Windows build all fail with a message. `Uninstall-EndpointService.ps1`
keeps state unless `-PurgeState` is given.

## Tests

`apps/endpoint-agent/service_test.go`, every OS:

- `TestServicePipelineRecoversAndRestarts`: a CPU provider fails at first, so
  the first signed snapshot has CPU null with a reason. The provider then
  recovers and a later snapshot carries the value, without a restart. After a
  cancelled run (clean stop, report written), a second run on the same state
  dir signs with the same identity and strictly higher sequences, and nothing
  re-enrolls.
- `TestServicePipelineStopsWithHungProvider`: a provider blocked forever,
  ignoring its context, does not hold the pipeline after cancellation.
- `TestServiceAdmission`: no identity and no enrollment fails. A missing
  bootstrap fails. A bootstrap enrolls against the TLS protocol fixture and is
  deleted. A second bootstrap beside the admitted identity is deleted without a
  request.
- `TestServiceConfigIsStrict`: unknown keys, wrong schema, relative paths,
  out-of-range cap and trailing data are rejected.
- `TestEvidenceSinkTornTailAndCap`: a torn final record is truncated, and the
  cap returns `errEvidenceFull` without writing.

`service_windows_test.go`: an interactive `runService` and an interactive
token are refused, and the real binary refuses `--service` outside the SCM,
without `--service-config`, and mixed with `--sample`.

`TestServiceQualificationHarness` runs only when its two variables are set. It
serves the real controller enrollment handlers from a disposable PostgreSQL
database, issues one bootstrap token at the repository boundary (no OIDC login),
waits for the elevated script, and then verifies every envelope against the
public key the controller committed. `TestEndpointEnrollmentPostgres` now shares
its database setup.

## HP Victus runs, 18 November 2026

HP Victus 15-fb0xxx, Windows 11 build 26200, AMD Ryzen 5 5600H, 16 GiB. Go
1.27.4. PostgreSQL 18.1 portable binaries on `127.0.0.1` with SCRAM
authentication; the test database was dropped afterwards.

```powershell
$env:TEST_DATABASE_URL = 'postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'  # password via PGPASSFILE
$env:DEVICE_AUDIT_SERVICE_QUALIFICATION_DIR = '<harness dir>'
go test -count=1 -timeout 60m -run TestServiceQualificationHarness -v ./apps/endpoint-agent
# second console, elevated, while the harness waits:
tools/service/Invoke-ServiceQualification.ps1 -AgentPath <endpoint-agent.exe> -HarnessDir '<harness dir>'
```

The script uses a 10 s emit interval and samples all eight sources (NVIDIA
every 30 s). It installs with a 5 s restart delay and `Manual` start, and
uninstalls and purges the test identity at the end.

### Run 2 (final code)

Artifacts: [windows-service-26/](windows-service-26/).

| Step | Result |
| --- | --- |
| Interactive `--service` | exit 1, "runs only under the Windows service control manager" |
| First start | enrolled through the real handlers, bootstrap file deleted, 9 snapshots in 90 s, stopped in 542 ms with exit code 0 |
| Token at every start | `account=LocalService elevated=false service_sid=S-1-5-80-4292395088-… privileges=SeChangeNotifyPrivilege(enabled)` |
| Restart | same signing key, no re-enrollment |
| `Stop-Process -Force` | SCM restarted a new process after 6,024 ms; same key; 3 more snapshots; clean stop, exit code 0 |
| Run as LocalSystem | refused, Win32 exit 1066, service exit 2, "refuses LocalSystem" |
| Add `SeImpersonatePrivilege` | refused, service exit 2, "holds SeImpersonatePrivilege outside the documented privileges" |
| Identity directory | `O:LS D:P(A;OICI;RC;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;<service SID>)`; the elevated administrator could not list it |

The harness verified all 15 envelopes with the controller-committed Ed25519
key. They are bound to `deployment:service-qualification` /
`device:service-qualification`, with sequences 2 to 16 across the stop, the
restart and the kill, no gaps, and a CPU value in every snapshot. The killed
process lost no committed envelope.

| Run phase | Snapshots | CPU (% of one core) | Peak RSS | Budget (2 %, 64 MiB) |
| --- | ---: | ---: | ---: | --- |
| First start, 91 s | 9 | 0.276 | 30.0 MB | within |
| After the SCM restart, 30 s | 3 | 1.362 | 26.0 MB | within |

The killed run wrote no report, as expected. The network source's two down
interfaces were `sensor_unavailable`; every other source had a value.

### Run 1

The same procedure with the earlier binary. Its artifacts have the `run1-`
prefix. Five of six steps passed and the harness verified 15 envelopes,
sequences 2 to 16. Two results:

- **Wrong refusal message.** The `SeImpersonatePrivilege` start was refused
  (service exit 2), but for "an elevated token": Windows marks a token holding
  that privilege as elevated, and the elevation check ran first. The privilege
  check now runs first; run 2 shows the specific message.
- **RSS over budget.** The first start peaked at 86.0 MB (OS peak equal),
  0.223 % CPU. The peak sample was 90.3 s in, just after a network read and
  just before the stop. It is close to the unattributed 85.1 MB in
  [sampling-94](sampling-94.md) run 1 and is also unattributed here. The
  service does not stop for a budget overrun; it reports it.

## Not done

- **Collector failure in the service.** No real source failed during the runs.
  Recovery after a provider error, and shutdown with a hung provider, are shown
  by the pipeline tests.
- **Delivery and spool.** Signed envelopes stay in a local file. Submission over
  the mesh and a retrying, bounded spool are #27/#95. Error evidence
  (`--collect-errors`) is not hosted by the service.
- **Release install.** `tools/service` is a development install. A signed,
  provenance-checked package, upgrade and the operator walkthrough are #57/#64.
  The real identity provider and the token issuance route were not used.
- **Power loss and reboot.** Not exercised. `Automatic` start after a reboot was
  not tested; the runs used `Manual`.
- **RSS spike.** Run 1's 86 MB peak is unexplained.
- **Second physical target.** It is recorded as unavailable in the release
  scope.
