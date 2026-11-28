# Federated training data minimization (FED12 #117)

## Captured request and controller logs

[`TestFederatedTrainingDataMinimization`](../../apps/endpoint-agent/federated_minimization_test.go)
fits the repository baseline against eight synthetic, labeled CT03 feature
windows through the Go endpoint fitter. It uses a fixture enrollment to stage
and sign the result with the normal FED08 code. The harness submits the exact
staged bytes to the real FED09 mesh HTTP handler, supplies a simulated mesh
peer through the server's connection hook and records the controller's
structured application logs. Its repository double records calls and checks
round compatibility.

| Capture | Observed result |
| --- | --- |
| Staged request body sent to `POST /v1/federated/updates` | Exactly 16 fields. The signing header carries `schema_version`, `deployment_id`, `device_id`, `signing_key_id`, `sequence`, `issued_at`, and `expires_at`. The update carries `round_id`, `base_model_version`, `base_model_sha256`, `candidate_id`, `feature_version`, `sample_count`, `weights_base64`, `update_sha256`, and `signature`. Individual feature windows, timestamps within the windows, outcome labels, raw logs, local paths, and private keys were absent. |
| Accepted response and application log | HTTP 201 and `Cache-Control: no-store`, with status, round/candidate/device IDs, sequence, acceptance time and creation flag. The fixture repository received one structurally valid, authenticated, round-compatible update with a sample count of eight. The handler emitted zero application log records for that request. |
| Rejected request and application log | Adding the local training rows under `examples` or a synthetic `raw_log` canary to the valid signed JSON yielded HTTP 400 and `invalid_payload`. Neither request reached the repository. Each warning contained only time, level, the fixed message `federated update rejected`, event `federated_update_rejected`, reason `invalid_payload`, and the fixture mesh peer. Neither output echoed the request body, decoder error, training data, weights, or signature. |

```sh
go test -race -count=1 -v -run '^TestFederatedTrainingDataMinimization$' ./apps/endpoint-agent
```

This captures the supported training-to-staging output at the HTTP handler
boundary. The test harness performs the POST. The endpoint command stages a
file, and scheduled delivery, retries from the endpoint and a two-device
training exchange over Tailcat are untested here. Native Windows training
worker limits and LocalService qualification were outside this run. The log
capture covers the federated handler's structured logger. It does not cover
host logging, proxies, diagnostic dumps, or other application routes such as
ordinary telemetry. The contract rejects undeclared JSON fields at the
controller, after they arrive. The endpoint's own serialization is the control
that keeps raw observations out of a supported submission.

## Privacy and poisoning limits

- The controller can link individual updates to devices through the enrolled
  peer, deployment and signing identity. The repository retains each accepted
  signed envelope and decoded weights off-chain. Sample count and participation
  timing are visible. Mesh authentication controls transport access, and the
  Ed25519 signature authenticates the update and binds its metadata to its
  digest. Neither hides the submitted values from the controller.
- The trainer sends a full fitted weight vector. A recipient with the base can
  derive the parameter change. Gradients are not directly sent, but fitted
  parameters and changes derived from them can reveal information about
  membership, labels or feature properties, particularly for small local
  datasets or when multiple rounds are observed. `TestLocalCandidate`
  demonstrates sensitivity by changing one fixture label and observing a
  different result. This did not measure how much information could be
  recovered or attempt membership inference or gradient reconstruction.
- FED09 checks identity, eligibility, round/base/feature compatibility, size,
  finiteness and replay state. A correctly signed but misleading update or
  inflated in-range sample count can still influence the average. The FED05
  regression test admitted a finite outlier claiming 90% of the total sample
  count. A separate synthetic held-out report triggered the promotion gate for
  that candidate. Colluding clients, hidden backdoors, rare-cohort degradation
  and forged evaluation evidence remain possible failure modes. See the
  [FED05 containment evidence](federated-containment-50.md).
- **Differential privacy and secure aggregation are neither implemented nor
  claimed.** The trainer has no privacy noise or privacy accounting, and the
  controller reads each participant's update before aggregation. Admission
  cannot establish how a compromised endpoint generated its weights or rule
  out deliberate encoding of data inside otherwise valid values. The training
  flow uses no chain submission.

## Tested versions and coverage

- Base revision `792361a21bd696db605577bc1168893ba501d012` plus the FED12
  test. Go `1.27.4-X:nodwarf5`, Linux amd64. Round and update contracts
  `device-audit.federated-round.v1` and `device-audit.federated-update.v1`.
  Training `local-logistic-full-batch.v1`, features `hdd-smart-7d.v1`,
  endpoint runtime `device-audit-endpoint-go` `1.0.0`, and fixture base
  `logistic-baseline.backblaze-2013.v1`. The FED05 rerun uses
  `sample-count-weighted.v1` and a publisher-signed synthetic evaluation.
- `make check` passed with a disposable PostgreSQL 18.7 cluster. Targeted
  FED09 and FED05 PostgreSQL tests passed under the race detector, including
  rejected updates, replay and retry, deadline closure without quorum, and a
  promotion rejected for reported regression. These repository tests use
  their own signed fixtures.
- `make model-check` passed 104 tests on Python 3.14.10 with the pinned test
  dependencies. `make contract-check` passed 367 golden vectors and 81 wire
  cases. `make cross-build` passed for Windows amd64 and macOS arm64, and the
  Windows endpoint test binary compiled.
- The Linux service tests passed for restart, hung provider shutdown, and
  continued signed sampling after model/inference failures. The console browser
  check passed on Chrome 158.0.8127.88. The Go chain policy tests passed. Live
  chain operations and a held-out report computed from an aggregated candidate
  were outside this run.
