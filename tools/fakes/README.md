# Development fixtures

## Controller fake, TST01 #17

`controllerfake` is an independent, in-memory controller fixture for endpoint
development. It accepts the public signed envelopes from
`packages/contracts/fixtures/envelopes/v1-vectors.json`, verifies their Ed25519
signatures, applies the contract freshness rules, and returns a controller-signed
`device-audit.acknowledgement.v1`.

It is a fixture. It is not controller admission, durable sequence storage,
production key custody, enrollment authorization or evidence storage. Restarting
it loses every binding and sequence mark. Every response carries
`X-Device-Audit-Fixture: true` and the health route reports `"mode": "fixture"`.
The only keys are the public RFC 8032 test seeds used by the contract vectors.

### Start it for endpoint development

From the repository root:

```sh
go run ./tools/fakes/controllerfake
```

The default listener is `127.0.0.1:8081`; only literal loopback addresses are
accepted. Endpoint code posts an enrollment or evidence envelope to
`POST /v1/envelopes`. Use `--now 2026-10-15T12:00:00Z` to pin the fixture clock
for repeatable expiry and skew checks. `GET /healthz` reports the fixture mode.

```sh
curl -s http://127.0.0.1:8081/healthz
go run ./tools/fakes/controllerfake --scenario assignment
```

### Deterministic scenarios

`make fake-check` runs all scenarios in-process against the real HTTP handler and
verifies every returned acknowledgement signature and contract.

| Scenario | Evidence |
| --- | --- |
| `assignment` | Enrollment sequence 1 binds the fixture device key; evidence sequence 2 is accepted. |
| `expiry` | Evidence at the inclusive `expires_at` boundary is rejected as `expired` without advancing the mark. |
| `offline` | An unreachable controller fails closed with no acknowledgement. |
| `duplicate` | A second delivery of sequence 2 is rejected as `replay` with the unchanged mark. |

The command prints one machine-readable JSON report and exits non-zero when a
scenario fails. CI stores the report as the `controller-fixture` artifact.

```sh
go run ./tools/fakes/controllerfake --scenario all
go run ./tools/fakes/controllerfake --scenario duplicate
```

The suite covers named assignment, expiry, offline and duplicate behavior. It
does not prove durable restart behavior, concurrency, challenge issuance,
authorization, replay after process restart or production storage. Those remain
with #18, #19, #83 and #89.

## Replay endpoint fixtures against an HTTP boundary

This independent development client sends canonical signed fixture requests.
It does not run the endpoint process, collect sensors, enroll devices, or add
controller capabilities. Device application signing keys are unrelated to
Tailcat/WireGuard identity or blockchain commitments.

### Check the current controller

From the repository root, start the development controller:

```sh
go run ./apps/controller --listen 127.0.0.1:8080
```

In another terminal, replay every fixture family and scenario:

```sh
go run ./tools/fakes/endpoint-replay --controller http://127.0.0.1:8080 --profile scaffold --scenario all
```

A matched expectation is not an accepted request. The scaffold profile expects
HTTP 400 for signed telemetry envelopes and HTTP 404 for diagnostics and
federated submissions. The real controller accepts only unsigned telemetry v1.
It has no signed-envelope admission, sequence enforcement, diagnostic result
route, or federated update route. The replay client does not downgrade signed
telemetry into that legacy format.

Run the focused tests and an actual controller subprocess smoke with:

```sh
make replay-check
```

The command builds the controller and replay binaries. The HTTP contract fake
used by Go tests is explicitly test-only. Its accepted responses and in-memory
deduplication do not demonstrate controller ingestion or durable admission.
The separate subprocess smoke exercises the actual development controller's
unsupported responses.

### Configure another development boundary

Use `--controller` for the HTTP origin. Override `--telemetry-route`,
`--diagnostics-route`, and `--federated-route` to match your server. Route paths
may contain percent escapes; configured escapes are preserved in the request
URI, including escapes in an origin path prefix. Diagnostic and federated
default routes are fixture-only test URLs, not published controller APIs. Do
not send fixtures to a production environment.

Select `--scenario valid`, `--scenario malformed`, or `--scenario interrupted`
to run one scenario across the named families. Use `--scenario all` for all.
The `contract-fake` profile describes only the test fake's status expectations.
Override individual expectations with repeatable `--expect family.scenario=status`
flags when a configured boundary has a different contract. A response mismatch
or unexpected transport error fails the command. Run `--help` for route names
and timeout options. The `scaffold` defaults are 400 for telemetry and 404 for
diagnostics/federation in every scenario. The `contract-fake` defaults are 400
for malformed signatures and 202 otherwise, except for the telemetry duplicate
described below. For example, `--expect telemetry.valid=422` asserts HTTP 422
for that specific request without changing other expectations.

### Fixture and signing boundaries

- Telemetry uses `EvidenceEnvelopeV1` containing fixture-source telemetry v2.
- Diagnostics use the native signed assignment and terminal result contracts.
  The assignment is controller-signed fixture context. The endpoint submission
  is the device-signed result.
- Federation uses a validated round and native signed update. The round is
  unsigned context because the published contract does not define a round
  signature. No new signing format is introduced.

The client reuses the shared contracts' `SigningBytes`, validation, and
signature checks. Fixtures use deterministic development-only key material,
fixed time, fixture-prefixed identities, and deterministic sequences. They are
not enrollment credentials. Requests carry a fixture marker outside the
canonical signed body, and reports identify their fixture provenance. The
contracts for diagnostic and federated data do not gain invented source fields.

The embedded bundle is
[`packages/contracts/fixtures/replay/v1.json`](../../packages/contracts/fixtures/replay/v1.json).
A contract-aware development server must preload its public device/controller
keys, diagnostic assignment, and federated round. These contexts are not sent
to invented enrollment, assignment, or round-creation endpoints. Its receiver
clock must match `fixed_time`, `2026-10-19T12:30:00Z`, when checking freshness.
The CLI does not renew expired fixtures against the current wall clock.
Sequences are 2 for telemetry, 3 for the diagnostic result, and 4 for the
federated update. The controller-signed assignment uses its separate sequence 1.
The request header `X-Device-Audit-Fixture: true`, fixture-prefixed IDs, and
the report's `fixture: true` mark the test data. The telemetry payload also
uses its existing `source: fixture` field.

Regenerate the bundle with the public RFC 8032 test seeds by running:

```sh
go run packages/contracts/fixtures/replay/generate.go
```

Malformed scenarios deliberately corrupt a signed request. Interrupted CLI
scenarios cancel before submission, then submit the identical deterministic
request bytes. That proves client cancellation and resubmission only. Separate
contract-fake tests interrupt after an in-memory commit and assert telemetry
replay rejection and idempotent diagnostic/federated receipts without a second
commit. Neither establishes crash-safe production recovery. In the test fake,
`--scenario all` resubmits already accepted fixtures, so interrupted telemetry
expects HTTP 409. Standalone `--scenario interrupted` expects its first HTTP
submission to receive 202. Diagnostic/federated exact duplicates receive 202.

These fixtures do not satisfy real-device, Windows service, two-machine,
resource-budget, network relay, trained-model, federation, chain, privacy, or
patent-conformance gates. Existing real-device qualification remains required.
