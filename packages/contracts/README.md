# Versioned application contracts

`types.go` owns the initial `device-audit.v1` types. `telemetry.schema.json`
describes the telemetry JSON accepted by the development controller; Go input
validation is authoritative for the runnable scaffold. Other types reserve
implementation boundaries and are not exposed by HTTP endpoints yet.

Percent metrics use 0–100; latency uses milliseconds; temperature uses Celsius.
Unavailable sensors are omitted/null rather than fabricated as zero. At least
one known metric is required. `source` is a producer label, not attestation.
Device IDs are opaque application IDs, not network credentials.

The demo digest is SHA-256 of `json.Marshal(Telemetry)` after validation. It is
specific to this Go representation. Define a cross-language canonical encoding,
domain separator, policy/schema/model version binding, signature and replay
protocol before using a digest in security decisions or smart contracts.
