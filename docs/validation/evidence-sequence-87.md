# SEC07 #87 implementation and evidence

Signed evidence with crash-safe monotonic sequence allocation, based on main
`0a9f206`. Signing, networking and chain identities remain separate; no wire
contract changed.

## Completion ledger

| Result | Source/runtime | Check | State | Evidence |
| --- | --- | --- | --- | --- |
| CT04 canonical envelopes bound to admitted identity | `apps/endpoint-agent/evidence.go` | signer output verified with the enrolled key and receipt scope | proved on Windows | `TestEvidenceSigningMonotonicAndBound` |
| Signer matches golden vectors; altered payloads fail | CT04 `fixtures/envelopes/v1-vectors.json` | RFC 8032 test seed reproduces golden signature and canonical bytes; altered payload (stale and recomputed digest) fails | proved | `TestEvidenceGoldenVectors` |
| Persistent monotonic sequence across processes | `sequence.state`, write/flush/rename/flush | fresh-process signing | proved on Windows | `TestEvidenceSequenceSurvivesForcedRestart` |
| Forced restart never reuses a signed sequence | injected exits before/after commit, plus `TerminateProcess` of a signing loop at 1, 7 and 23 envelopes | every observed sequence unique and strictly increasing; committed reservation skipped; uncommitted value reissued only because it was never signed | proved on Windows (process kill) | `TestEvidenceSequenceSurvivesForcedRestart` |
| Lost or damaged state fails closed | missing, bit flip, other scope, below receipt, exhausted, unknown field, unsafe temporary | no signature, state not repaired or recreated | proved | `TestEvidenceSequenceFailsClosed` |
| No signing material in telemetry or logs | envelope JSON, process stdout/stderr, error text | seed, private key and network key absent in hex, base64 and raw forms | proved for exercised paths | evidence tests; invalid payload markers never echoed |
| Enrollment creates sequence state before receipt | `enroll.go` | TLS enrollment fixture | proved on Windows | `TestEnrollmentAndProcessRestart` |
| Power-loss durability | NTFS/ext4 hardware | power cut during allocation | not tested | Process kill does not prove disk cache behavior |

## Validation

Passed on 13 November 2026, Windows 11 amd64, Go 1.27.4, GNU Make 4.4 and
WinLibs GCC (installed with winget for `-race`), Python 3.12 virtual
environment with `models/test-requirements.txt`:

- `make check cross-build` (vet, race suite, 32 Python tests, fixture scenarios,
  formatting, Windows and Darwin endpoint builds).
- `make contract-check`: 289 golden vectors, 71 wire cases, 25 reader versions.
- Linux amd64 and Darwin arm64 endpoint test binaries cross-compiled, not run.

`TestEndpointEnrollmentPostgres` was skipped: no `TEST_DATABASE_URL` on this host.

## Remaining

Transport and spooling of signed requests (#24/#25), LocalService execution and
real collectors (#26), backup/restore reconciliation of `sequence.state`, and
power-loss qualification remain open. A restored older state directory can
reissue local sequences; the controller's durable mark rejects them as `replay`.
