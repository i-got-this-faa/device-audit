# Atomic staged model activation, FED11 #116

The endpoint tests use a private lab state directory, a test-only publisher,
a synthetic passing evaluation and simulated telemetry sources. The checks
exercise real file replacement, signed spooling and subprocess exit.

| Acceptance path | Evidence |
| --- | --- |
| Activate a verified candidate | `TestActivateStagedModel` scores the selected candidate, repeats the switch and scores the retained last-working slot. Re-staging the same active artifact and report preserves both slots. |
| Reject incompatible or unhealthy inputs | The test rejects a different deployment, tampered artifact bytes, an unapproved evaluation digest and a health reply naming the wrong model. A fresh storage open selects the last committed model and skips the failed attempt. The existing FED04 tests also cover signature, runtime and feature compatibility. |
| Recover from a process exit | `TestModelActivationCrashRecovery` exits a subprocess immediately before or after the final journal replacement. Recovery before replacement reports an interrupted rejection and selects the old active model. Recovery after replacement selects the new model with the previous one retained. |
| Continue signed telemetry during rollback | `TestServiceSamplingContinuesThroughActivationRejection` holds the probe open across sampling ticks. It verifies signed spool records while the probe is pending and additional signed records after rejection. The inference worker then uses the retained model. |

`make check`, `make model-check` and `make contract-check` passed with the
pinned Python test dependencies. The model suite ran 104 tests. Contract
conformance covered 367 golden vectors and 81 wire cases. `make cross-build`
passed for Windows AMD64 and Darwin ARM64, and the Windows endpoint test
binary compiled. The console browser suite passed with Chrome 158. The Go
chain policy tests passed locally.

Native Windows LocalService activation, a live mesh download followed by
activation, physical power loss, real SMART collection and live chain
operations were untested.
