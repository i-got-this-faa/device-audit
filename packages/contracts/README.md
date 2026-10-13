# Versioned application contracts

`types.go` owns the initial `device-audit.v1` types. `telemetry.schema.json`
describes the telemetry JSON accepted by the development controller. Shared
vectors in `fixtures/telemetry/vectors.json` are checked by Go's strict JSON
decoder plus `Telemetry.Validate()`, and by Python's Draft 2020-12 validator
with date-time format checking (`make telemetry-check`). Other types reserve
implementation boundaries and are not exposed by HTTP endpoints yet.

Percent metrics use 0–100; latency uses milliseconds; temperature uses Celsius.
Unavailable sensors are omitted/null rather than fabricated as zero. At least
one known metric is required. `source` is a producer label, not attestation.
Device IDs are opaque application IDs, not network credentials.

The vectors cover telemetry wire shape and scalar validation only. JSON Schema
validates date-time syntax but does not exclude every timestamp that Go parses
as its zero instant; Go's `Telemetry.Validate()` rejects that instant, with a
Go-only regression test for equivalent spellings. These checks do not cover
signatures, replay protection, inventory, transport identity, or production
sensor collection. The fixture source label is provenance metadata, not
attestation. The original patent PDF has not been supplied, so this conformance
work is not a patent implementation or verification claim.

The demo digest is SHA-256 of `json.Marshal(Telemetry)` after validation. It is
specific to this Go representation. Define a cross-language canonical encoding,
domain separator, policy/schema/model version binding, signature and replay
protocol before using a digest in security decisions or smart contracts.
