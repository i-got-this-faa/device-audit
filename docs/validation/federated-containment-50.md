# Federated round failure containment (FED05 #50)

The controller integration tests exercise signed update admission, PostgreSQL
round state, aggregation, console promotion, and the approved-model download
handler. The tests use fixture keys and a simulated mesh peer identity.

| Acceptance path | Evidence |
| --- | --- |
| Reject malformed, nonfinite, and incompatible updates | `TestFederatedRoundContainsRejectedUpdatesAndDropout` submits malformed base64, positive infinity with a matching payload digest, and a correctly signed update referencing a different registered base. The mesh HTTP handler and repository reject all three. The accepted update ledger and participant state retain only the valid submission. The next round accepts the previously rejected participant's unused sequence. |
| Close at the deadline and contain a round below quorum | The same test refuses early aggregation and a valid update arriving exactly at the deadline. The round records a deadline closure and a durable `insufficient_participants` aggregation with one accepted contribution. A fresh repository returns the same failure on retry. No candidate artifact is created, and the existing candidate reference stays in place. |
| Contain a candidate with a reported regression | `TestFederatedRoundRegressionCannotReachEndpointDownloads` aggregates two submissions with a third eligible participant silent. A signed finite outlier contributes 90% of the declared sample count and shifts the intercept from the honest submission's 0 to 900,000. The candidate cannot promote without a stored evaluation. A publisher-signed synthetic report bound to the aggregate passes ML05, but its average precision is 0.19 against the active model's 0.20. FED10 records `regression:active_average_precision`. Direct activation is refused before and after the decision. The rejected artifact returns 404 on the endpoint download route while the active artifact remains available byte for byte. |

## Residual poisoning cases

- The tested finite outlier passes admission. Signatures authenticate the
  submitting device, and shape and finiteness checks constrain the payload.
  The protocol trusts the submitted sample count within its allowed range.
  A compromised enrolled client can inflate its influence within that range.
- Multiple eligible clients can collude or withhold contributions. The
  aggregation policy uses sample-count-weighted averaging. The minimum
  participant count only sets the quorum.
- A backdoor or degradation on a rare device cohort can evade the promotion
  gate when the held-out examples or reported metrics miss the affected
  behavior. A compromised publisher key can also authenticate false evaluation
  evidence. These scenarios were not exercised.

## Checks and limits

- Targeted Go integration tests passed with `-race` against a disposable
  PostgreSQL 18.7 cluster. Run them with
  `TEST_DATABASE_URL=<test database URL> go test -race -count=1 -v -run '^TestFederatedRound(Contains|Regression)' ./internal/controller`.
- `make check` passed with `TEST_DATABASE_URL` set, including the Go race
  suite against PostgreSQL. `make model-check` passed 104 tests with the pinned Python dependencies.
  `make contract-check` passed 367 golden vectors and 81 wire cases. These
  scenarios reuse the existing contracts and add test-local fixture values.
- Windows AMD64 and Darwin ARM64 cross-builds passed, and the Windows endpoint
  test binary compiled. The browser suite passed with Chrome 158. The Go chain
  policy suite passed.
- The existing Linux endpoint staging, activation, crash recovery, and signed
  service sampling tests passed. Live two-device training and download over
  Tailcat, a held-out run computed from the aggregated artifact, native Windows
  LocalService activation, and live chain operations were untested. The
  synthetic report establishes how the promotion gate handles a reported
  regression.
