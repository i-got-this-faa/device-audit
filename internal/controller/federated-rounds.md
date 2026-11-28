# Federated round lifecycle, FED01 #40

`PostgresRepository` implements `federated.Coordinator`
([migration 008](../../infra/database/migrations/008_federated_rounds.sql),
[migration 010](../../infra/database/migrations/010_federated_updates.sql), and
[migration 011](../../infra/database/migrations/011_federated_aggregation.sql)). It
stores the [round and update contracts](../../packages/contracts/federated-v1.md),
its round state, validated participant updates (`FED09 #114`) over both the
Go `Coordinator` (`AcceptUpdate`, `AcceptedUpdates`) and the admitted mesh
route `POST /v1/federated/updates`, and reproducible candidate aggregations
(`FED03 #43`: `AggregateRound`, `Aggregation`). FED02 #42 local endpoint
training and FED10 #115 evaluated promotion build around these boundaries.

## Lifecycle

```text
OpenRound ─▶ open ─ deadline reached ─▶ closed
               └──── CancelRound ─────▶ cancelled
```

`closed` and `cancelled` are final. Each change is one row in
`federated_round_events` with its time, reason (`opened`, `deadline`,
`cancelled`) and, except for `deadline`, the console actor. The deadline is
exclusive. The controller closes a round when the next call touches it
(`Round`, `AcceptParticipant`, `CancelRound`) or `CloseExpiredRounds` runs, and
records the closing once. A restart changes nothing; state is rows. A read
returns status, admissions and transitions from one snapshot.

## What each call checks

| Call | Refuses with | Repeat |
| --- | --- | --- |
| `OpenRound` | `ErrBaseNotRegistered` unless the base is the stored artifact with this digest, feature version and parameter count, declared for `training`. `ErrParticipantNotEligible` if a listed device is not enrolled with the snapshot key, or is revoked but listed `eligible`. `ErrRoundNotOpen` if the controller clock is outside `[opened_at, deadline)`. `ErrRoundConflict` if the round or candidate ID holds different content. | Identical content returns the stored round with `created=false`, at any later status. Participant order does not matter. |
| `AcceptParticipant` | `ErrParticipantNotEligible` for a device that is unlisted, listed `ineligible`, uses another key, or is revoked now. `ErrRoundNotOpen` for a closed or cancelled round or a passed deadline, including one reached while waiting on the enrollment lock. | A participant already admitted gets the stored admission, even after close. A repeat past the deadline also records the closing. |
| `CancelRound` | `ErrRoundNotOpen` once closed. | Cancelling a cancelled round returns it. |

Eligibility has two parts. The snapshot in the round fixes who may take part and
with which key. The enrollment is read again at admission under a share lock
that `RevokeDevice` waits on, so a revocation is ordered before or after an
admission and wins if it came first.

## What the database enforces

- A round row never changes except `status`, and only from `open`.
- A participant row is inserted without `accepted_at`, then gains it once, only
  if it is `eligible`, while its round is open and only at a time inside
  `[opened_at, deadline)`. Nothing is deleted. Events are append-only.
- A participant references one enrolled device and key; a base references one
  stored artifact and digest. A candidate ID names one round.

## Not done

- The controller does not choose participants. The caller supplies the snapshot.
- `FED03 #43` writes unapproved reproducible candidate artifacts to
  `model_artifacts` and `model_references.candidate`; held-out evaluation and
  promoting a candidate to `active` belong to downstream `FED10 #115`.
- Nothing calls `CloseExpiredRounds` on a schedule; a round past its deadline is
  closed when touched (including when `AggregateRound` closes an expired round).
- The base need not be approved or active. The round fixes its digest.
