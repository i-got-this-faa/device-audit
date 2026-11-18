# Windows service host, TEL02 #26

Status on 18 November 2026: **the service host, its installer, failure-path
tests and four qualification runs as `NT AUTHORITY\LocalService` on the HP
Victus target are recorded. Delivery, a spool, a real collector failure inside
the service, reboot and the second physical target are not.**

## What was built

`endpoint-agent --service --service-config <file>` runs under the service
control manager (`golang.org/x/sys/windows/svc`). In order, it:

1. **Checks the token.** It requires `S-1-5-19` (LocalService). It checks
   privileges before elevation and refuses any privilege other than
   `SeChangeNotifyPrivilege`, an elevated token, and a missing or disabled
   per-service SID. It logs the account, the service SID and the privileges.
2. **Checks evidence storage.** It refuses an evidence directory or evidence
   file whose DACL allows anyone but SYSTEM, Administrators and the service SID.
   Deny entries are accepted.
3. **Loads the admitted identity** from `identity`, which the service creates
   itself with the SEC02 DACL and user-scoped DPAPI under its own token. With no
   admission receipt, it first validates the enrollment TLS settings, then
   reads the one-use `enrollment\bootstrap.json`, deletes it and enrolls. A
   CA mistake therefore leaves the credential in place. A bootstrap file found
   beside a verified admission is deleted without being redeemed. The
   configuration rejects any bootstrap, CA, sampling or evidence path inside
   `state_dir`, compared case-insensitively on Windows.
4. **Runs the pipeline.** It runs the TEL08 scheduler with the configured
   sampling config. Each snapshot becomes telemetry v2 for the admitted device
   ID, is signed with the SEC07 crash-safe sequence, and is appended to
   `evidence\signed-evidence.jsonl` with one synced line per envelope. On start,
   a torn final line from a crash is truncated, leaving a gap that CT04 allows.
   At `max_evidence_bytes` the pipeline fails with exit code 3 rather than
   dropping evidence.
5. **Stops cleanly.** Stop or shutdown cancels the scheduler and waits at most
   25 s. Each clean stop writes a sampling report and a budget line in
   `service.log`. The stop-timeout path writes no log, because a stuck
   worker may hold the log lock. The SCM records exit code 4.

Service exit codes: 1 configuration or evidence ACL, 2 refused account or
privilege, 3 pipeline failure, 4 workers did not stop.
`tools/service/Install-EndpointService.ps1` checks every input file before it
registers the service. If a later step fails, it removes that registration
and keeps existing state. It configures:

| Setting | Value |
| --- | --- |
| Account | `NT AUTHORITY\LocalService` |
| Service SID type | `unrestricted` (`NT SERVICE\DeviceAuditEndpoint`) |
| Required privileges | `SeChangeNotifyPrivilege` only |
| Recovery | restart after the configured delay, three times, reset after a day; `failureflag 1` so a service-specific exit code also counts |
| `%ProgramData%\DeviceAudit\Endpoint` | exact protected DACL: SYSTEM and Administrators full; service SID read + create-folder on the root only (`0x1200ad`) |
| `evidence`, `enrollment` and their files | same, plus service SID modify |
| `service.json`, `sampling.json`, `ca.pem` | same, plus service SID read |
| `identity` | created by the service: SYSTEM and service SID full, OWNER RIGHTS read-control only, protected |

The installer replaces each DACL from SDDL instead of adding grants, so a
reused directory keeps no other principal's entry. Interactive `--service`,
`--service` mixed with another mode, and `--service` on a non-Windows build all
fail with a message. `Uninstall-EndpointService.ps1` keeps state unless
`-PurgeState` is given. It refuses to purge a directory that holds anything but
the endpoint's own entries.

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
- `TestServiceAdmission`:
  - with no identity and no enrollment, start fails;
  - with a missing bootstrap file, start fails;
  - a missing CA file fails without consuming the bootstrap file;
  - a bootstrap enrolls against the TLS protocol fixture and is deleted;
  - a second bootstrap beside the admitted identity is deleted without a request.
- `TestServiceConfigIsStrict`: rejects unknown keys, the wrong schema,
  relative paths, an out-of-range cap, trailing data, and a bootstrap or
  evidence path inside `state_dir` (including a different letter case on
  Windows).
- `TestBootstrapCleanupSparesIdentityAliases`: a bootstrap path that reaches
  `admission.json` through a directory junction (a symlink off Windows) passes
  the textual check. Cleanup compares the parent directory with `state_dir` by
  file identity and keeps the receipt. With that check removed, the test fails.
- `TestEvidenceSinkTornTailAndCap`: a torn final record is truncated, and the
  cap returns `errEvidenceFull` without writing.

`service_windows_test.go`:
- An interactive `runService` and an interactive token are refused.
- The evidence ACL check accepts a private directory with a deny entry. It
  refuses a file readable by Users and a directory readable by Everyone.
- The real binary refuses `--service` outside the SCM, without
  `--service-config`, and mixed with `--sample`.

`TestServiceQualificationHarness` runs only when its two variables are set. It
serves the real controller enrollment handlers from a disposable PostgreSQL
database and issues one bootstrap token at the repository boundary (no OIDC
login). It waits for the elevated script, reads the evidence file to its end,
and verifies every envelope against the public key the controller committed.
`TestEndpointEnrollmentPostgres` now shares its database setup, and it passed
against the same local PostgreSQL.

## HP Victus runs, 18 November 2026

HP Victus 15-fb0xxx, Windows 11 build 26200, AMD Ryzen 5 5600H, 16 GiB. Go
1.27.4. PostgreSQL 18.1 portable binaries on `127.0.0.1` with SCRAM
authentication; each test database was dropped afterwards.

```powershell
$env:TEST_DATABASE_URL = 'postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'  # password via PGPASSFILE
$env:DEVICE_AUDIT_SERVICE_QUALIFICATION_DIR = '<harness dir>'
go test -count=1 -timeout 60m -run TestServiceQualificationHarness -v ./apps/endpoint-agent
# second console, elevated, while the harness waits:
tools/service/Invoke-ServiceQualification.ps1 -AgentPath <endpoint-agent.exe> -HarnessDir '<harness dir>'
```

The script refuses to run if the service or its state directory already
exists. It uses a 10 s emit interval for all eight sources (NVIDIA every 30 s),
a 5 s restart delay, `Manual` start and a 1 MiB evidence cap. Whatever happens,
it copies the artifacts, then uninstalls and purges what it created. It exits 1
if any step failed.

### Run 4 (final code)

Artifacts: [windows-service-26/](windows-service-26/).

| Step | Result |
| --- | --- |
| Interactive `--service` | exit 1, "runs only under the Windows service control manager" |
| First start | enrolled through the real handlers; bootstrap file deleted; 9 envelopes in 90 s; stopped in 527 ms with exit code 0 |
| Token at every start | `account=LocalService elevated=false service_sid=S-1-5-80-4292395088-… privileges=SeChangeNotifyPrivilege(enabled)` |
| Restart | same signing key, no re-enrollment |
| `Stop-Process -Force` | SCM started a new process after 6,127 ms; the evidence file grew from 12 to 15 envelopes in the next 30 s; clean stop, exit code 0 |
| Evidence file filled to the cap | pipeline failed with "reached max_evidence_bytes", service exit code 3; SCM started a new process without a reboot (PIDs 18284 → 17688; run 3: 19780 → 24024, 5 s after the failure). Microsoft's `SERVICE_FAILURE_ACTIONS_FLAG` page says the flag takes effect at the next system start; on build 26200 it took effect immediately. Other builds are not measured |
| Run as LocalSystem | refused, Win32 exit 1066, service exit 2, "refuses LocalSystem" |
| Add `SeImpersonatePrivilege` | refused, service exit 2, "holds SeImpersonatePrivilege outside the documented privileges" |
| Root and evidence DACLs | `D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)` plus the service SID with `0x1200ad` on the root and `0x1301bf` (OICI) on `evidence` |
| Identity directory | `O:LS D:P(A;OICI;RC;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;<service SID>)`; the elevated administrator could not list it |

The padding added for the cap step was removed before the harness read the
file. The harness verified all 15 envelopes with the controller-committed
Ed25519 key. They are bound to `deployment:service-qualification` /
`device:service-qualification`, with sequences 2 to 16 across the stop, the
restart and the kill, no gaps, and a CPU value in every snapshot.

| Run phase | Snapshots | CPU (% of one core) | Peak RSS | Budget (2 %, 64 MiB) |
| --- | ---: | ---: | ---: | --- |
| First start, 90 s | 9 | 0.585 | 30.0 MB | within |
| After the SCM restart, 30 s | 3 | 0.855 | 27.5 MB | within |

The killed run writes no report, as expected. The network source's two down
interfaces were `sensor_unavailable`; every other source had a value.

### Runs 1 to 3

These used the code before review. Run 1's artifacts carry the `run1-` prefix.

- **Run 1.** Five of six steps passed and the harness verified 15 envelopes,
  sequences 2 to 16. Two results:
  - **Wrong refusal message.** The `SeImpersonatePrivilege` start was refused
    (service exit 2), but for "an elevated token": Windows marks a token
    holding that privilege as elevated, and the elevation check ran first. The
    privilege check now runs first.
  - **RSS over budget.** The first start peaked at 86.0 MB (OS peak equal) at
    0.223 % CPU. The peak sample came 90.3 s in, just after a network read and
    just before the stop. It is close to the unattributed 85.1 MB in
    [sampling-94](sampling-94.md) run 1, and it is unattributed here too. The
    service reports a budget overrun; it does not stop for one.
- **Run 2.** All six steps then defined passed, 15 envelopes verified, peak
  RSS 30.0 MB and 26.0 MB. Review then added the evidence ACL check, the
  admission ordering, the post-kill evidence requirement and the cap step.
- **Run 3.** All eight steps passed with those changes and 15 envelopes
  verified. A second review then made the installer move the bootstrap file
  last (and back on rollback) and made cleanup refuse a bootstrap path whose
  directory is identity storage under another name. Run 4 repeats every step
  with that code.

## Not done

- **Collector failure in the service.** No real source failed during the runs.
  Recovery after a provider error, and shutdown with a hung provider, are shown
  by the pipeline tests.
- **Delivery and spool.** Signed envelopes stay in a local file. Submission over
  the mesh and a retrying, bounded spool are #27/#95. At the cap the service
  fails and restarts repeatedly until evidence is moved; that is explicit but
  not a retention policy. Error evidence (`--collect-errors`) is not hosted by
  the service.
- **Release install.** `tools/service` is a development install, and its
  scripts are not run in CI because they need elevation. A signed,
  provenance-checked package, upgrade and the operator walkthrough are
  #57/#64. The real identity provider and the token issuance route were not
  used.
- **Power loss and reboot.** Not exercised. `Automatic` start after a reboot was
  not tested; the runs used `Manual`.
- **RSS spike.** Run 1's 86 MB peak is unexplained.
- **Second physical target.** It is recorded as unavailable in the release
  scope.
