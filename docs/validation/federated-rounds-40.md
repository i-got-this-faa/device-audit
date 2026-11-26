# Durable federated round state, FED01 #40, 26 November 2026

Migration 008, the [lifecycle notes](../../internal/controller/federated-rounds.md)
and `federated.Coordinator` store rounds, a participant snapshot, admissions and
transitions in PostgreSQL.

## Acceptance evidence

| Acceptance check | Evidence |
| --- | --- |
| Records round and base version, eligible participants, deadlines and transitions using registered artifact references | `OpenRound` stores the exact round, one row per participant and an `opened` event with the console actor. The base is a foreign key to a stored artifact and digest. Refused: an unstored version, another artifact's digest, a base without the `training` purpose, and a different parameter count or feature version. Each leaves no row (`TestFederatedRoundRefusesUnregisteredBaseAndUnenrolledParticipants`). |
| Duplicate round requests preserve one lifecycle | The same round with its participants in another order returns the stored record with `created=false`. Changing the deadline, or reusing the candidate ID under another round, is `ErrRoundConflict`. Row counts stay at 1 round, 3 participants, 1 event. Eight concurrent opens create one round; eight concurrent admissions of one device create one admission (`TestFederatedRoundDuplicatesAndRestartKeepOneLifecycle`, `TestFederatedRoundConcurrentRequestsCommitOnce`). |
| Coordinator restart preserves it | A second `PostgresRepository` over the same database returns a record equal to the first, and repeating the open creates nothing. |
| Ineligible participants cannot become accepted work | A device listed `ineligible`, one enrolled but not selected, an unknown device and another device's key are `ErrParticipantNotEligible`. A device revoked after the snapshot is refused. A revoked device cannot be listed `eligible` at open, but can be listed `ineligible`. No participant row gains `accepted_at` from a refusal. |
| Expired rounds cannot become accepted work | At the deadline `AcceptParticipant` is `ErrRoundNotOpen`, and the round is `closed` with one `deadline` transition and no actor. Three further attempts, a cancel, and reads add nothing. A sweep closes untouched rounds once each. A cancelled round stays `cancelled` after its deadline (`TestFederatedRoundDeadline`, `TestFederatedRoundCancel`). |
| The database holds the line if code does not | Direct SQL fails to reopen or re-close a round, move a deadline, delete a round or participant, rewrite or delete events, admit into a cancelled round, admit an ineligible device, admit twice, or add a participant that never enrolled (`TestFederatedRoundDatabaseRefusesInvalidTransitions`). |

## Fault checks

Each mutation was applied and reverted. The tests failed each time.

- `AcceptParticipant` skipped the deadline check.
- `AcceptParticipant` skipped the revocation check.

## Commands and results

With `TEST_DATABASE_URL` set to a local PostgreSQL 17.11: `make check`,
`make database-check`, `CGO_ENABLED=0 make cross-build` and
`make contract-check` passed. The existing schema-version assertions moved from
7 to 8.

## Not tested

- The restart is a new repository over the same database in one process, not a
  killed controller. The storage crash harness does not cover these tables.
- Revocation racing admission is ordered by the shared lock `RevokeDevice`
  already takes, as in SEC09 #90. This change has no test that pauses between
  them.
- No endpoint trains and no signed update is read. Admission is not an accepted
  update, quorum is not assessed, and nothing schedules `CloseExpiredRounds`.
- There is no HTTP route, so no console role or CSRF behavior is exercised.
- Migration 008 was run on empty databases only. Its refusal to drop
  non-empty candidate tables from migration 001 was not exercised.
