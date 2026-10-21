# Federated contracts v1, CT07 #77

`federated_v1.go` and `federated-v1.schema.json` define off-chain round,
update and promotion records in separate namespaces. Existing v1 coordinator
interfaces and model aggregation code remain unchanged. These contracts provide
no local trainer, federated service, production model or privacy guarantee.

## Authorized rounds

`device-audit.federated-round.v1` records deployment/round/candidate IDs, a base
model version and artifact SHA-256, feature version, parameter count, opened time,
exclusive deadline, eligible quorum and participant/key eligibility snapshot.
The candidate ID reserves one aggregation attempt; a retry with a different base,
feature definition or participant selection needs a new round/candidate pair.
The base digest identifies an exact artifact, rather than trusting version text.
All identifiers use the repository's bounded opaque application-ID syntax.

Provisional bounds are 1..4096 model parameters, 2..128 participant records, quorum
of 2..128 eligible participants and a round lifetime greater than zero and at
most seven days. Device IDs are unique in the participant list. Eligibility is
`eligible` with null reason, or `ineligible` with `revoked`,
`incompatible_features`, `insufficient_local_data` or `not_authorized`.
At least the configured quorum must be eligible. Selection and enrollment/key
binding require the future authenticated coordinator, including revocation checks
at admission. A round is an authorized controller record; this contract does not
sign round or promotion records or trust them merely because they parse.

## Signed updates

`device-audit.federated-update.v1` binds #75's device application signing header
to round ID, base version/digest, candidate ID, feature version, positive local
sample count and update SHA-256. Counts are 1..1,000,000,000 and weight aggregation
must avoid overflow. Samples count local training examples under the declared
feature policy; no local rows, logs or identifiers are required or accepted.

`weights_base64` carries a model parameter vector, with each value encoded as an
IEEE754 binary64 in big-endian order. It is the complete candidate weight vector,
not a delta. Concatenate exactly 1..4096 eight-byte values and use canonical padded
standard base64. Reject NaN, either infinity, empty/misaligned bytes and oversized
vectors. Both signed zero encodings remain distinct and are hashed as supplied.
`update_sha256` is SHA-256 of those exact decoded bytes. Model architecture,
parameter ordering, normalization and training policy must be specified by the
base/feature manifests before training. This bounded encoding is a provisional
contract, not a selected model architecture or a large-model transport.

Use #75's Ed25519 fingerprints and length-prefixed signing format. Common fields
are `schema_version`, `deployment_id`, `device_id`, `signing_key_id`, decimal
`sequence`, `issued_at`, `expires_at`. Append `round_id`, `base_model_version`,
`base_model_sha256`, `candidate_id`, `feature_version`, decimal `sample_count`,
`update_sha256`. `weights_base64` is bound through its checked digest. Domain is
`device-audit/signature/v1` followed by NUL. Each UTF-8 field has its big-endian
uint32 byte length. Completed objects require structural validation and real
signature verification with the externally trusted enrolled device key.

Updates share the durable device/deployment evidence sequence space from #75,
starting at 2. Update envelope lifetime is at most 24 hours; the exclusive expiry
cannot exceed the round deadline. `CheckRound(round, now)` validates exact
round/base/candidate/feature/parameter compatibility, participant/key eligibility,
and both time windows with an explicit receiver clock. No future-issue tolerance
is granted here. At the deadline or update expiry an update is stale. A prior
round or other-device update cannot be retargeted by changing a header without
invalidating its signature.

The coordinator must atomically admit at most one update per round/device and
commit replay state with its receipt. The same signed envelope/digest retried is
an idempotent duplicate; a changed update from that participant is a conflict.
Do not count retransmissions toward quorum or sample totals. A single-update
contract check neither reads that state nor implements admission. Persist exact
accepted update digests and counts with aggregation provenance. An eligibility
snapshot cannot override a subsequent revocation.

## Promotion decisions

`device-audit.federated-promotion.v1` binds the same round/base/candidate/feature
identifiers, nullable candidate artifact version/digest and evaluation digest,
policy version, decision time, and unique accepted participant IDs. The artifact
version and digest are both present or both null. Evaluation evidence remains
off-chain and must identify held-out data, metrics, thresholds and outcome under
the selected policy; a digest does not assert those checks ran.

`promoted` requires a new version and artifact digest, evaluation evidence, null
reason, and at least the round quorum of eligible participants. Promotion occurs
at or after round closure. `rejected` requires `evaluation_failed`,
`insufficient_participants`, `aggregation_failed` or `cancelled`.
`evaluation_failed` retains the candidate and evaluation digest. Earlier failure
may have null artifact/evaluation, as shown by `no_quorum`. Rejection leaves the
active base artifact unchanged. The contract does not choose metric thresholds,
evaluate a candidate, switch an active model or implement rollback.

`CheckRound` checks correlation, closure/quorum for promotion, unique participants
and eligibility. The consumer must additionally prove each listed participant
has one durably accepted, authenticated update; fetch and validate the actual
candidate/evaluation; authorize the human or policy decision; and atomically
compare the active base before changing it. A concurrent promotion or changed
active base is a conflict, never permission to overwrite it. Persist a terminal
decision and audit its actor, evidence and outcome. Later retries return that
decision, not a second promotion. This PR implements none of that state.

## Contract evidence and limits

The shared fixtures include incompatible base version and digest, feature/count
mismatch, ineligible participation, nonfinite binary updates, duplicate participant
records and accepted IDs, raw-observation rejection, missed deadlines and failed
promotion. Go checks structure, semantics, context and Ed25519 signatures. Python
independently decodes finite binary values, hashes updates and reconstructs signed
bytes, and checks every fixture with Draft 2020-12 and date-time validation.
Schema validation alone cannot check finite binary contents, digests, signatures,
field equality, unique device IDs in participant objects, ordering or quorum.
Transport consumers must impose request size/depth bounds before decoding.

```sh
go run packages/contracts/fixtures/federated/generate.go
make check cross-build
```

Another owner's contract review remains required before consumers. The fixtures
use public test keys and synthetic models, and do not prove two-endpoint training,
authenticated admission, poisoning resistance, secure aggregation, differential
privacy or evaluated prediction. Model weights themselves may leak training
information. Network admission, device signatures, admin identity and future
chain commitments remain separate. All records and model bytes stay off-chain.
