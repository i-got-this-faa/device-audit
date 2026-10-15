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
attestation. The supplied PDF's provenance is indexed in
[`docs/source/patent-map.md`](../../docs/source/patent-map.md); claim-to-scope
reconciliation remains #72. This conformance work makes no patent claim.

The demo digest is SHA-256 of `json.Marshal(Telemetry)` after validation. It is
specific to this Go representation. Define a cross-language canonical encoding,
domain separator, policy/schema/model version binding, signature and replay
protocol before using a digest in security decisions or smart contracts.

## Provisional telemetry and inventory v2

`TelemetryV2` and `telemetry-v2.schema.json` define a separate proposed wire
namespace, `device-audit.telemetry.v2`; v1 remains unchanged. The original
patent PDF is indexed, while claim-to-scope reconciliation (#72) and release
platform/hardware scope (#14) remain unresolved. These fields are a platform-neutral contract proposal,
not a claim of patent compliance or production collection.

Each selected metric carries `{value, unit}`. A null value requires one of
`sensor_unavailable`, `not_applicable`, `permission_denied`, or
`collection_error`; known values cannot carry a missing reason. CPU/GPU
utilization and memory/disk/battery usage use `percent` (0–100), temperature
uses `celsius`, and latency uses `milliseconds` (nonnegative). At least one
metric must be known. Inventory metadata uses opaque application IDs and
supports optional group/network-segment IDs and at most 64 components. A
telemetry record may contain at most 8 log references; each reference carries
an opaque reference ID, SHA-256 digest, byte size capped at 10 MiB, and time
window. Raw logs are never carried inline. These bounds and missing reasons are
provisional contract decisions and do not define collection policy.

The shared v2 vectors are checked by Go strict decoding plus
`TelemetryV2.Validate()` and Python's Draft 2020-12 validator. Go also enforces
that a log window ends at or after it starts; the selected JSON Schema draft
has no portable date-time ordering keyword, so this semantic check has a Go-only
regression. Fixture and endpoint are provenance labels only. Inventory/device
IDs are application identifiers; this schema says
nothing about network authentication, device signatures, or chain identity,
and no device identifier or raw log belongs on-chain.

## Provisional prediction v2

`PredictionV2` and `prediction-v2.schema.json` define a separately versioned
proposal; the existing v1 types and fixture demo remain available. Known health
states (`healthy`, `degraded`, `critical`) carry probability in the explicit
`probability` unit and a positive horizon in hours, and require a model artifact
reference and telemetry evidence reference. Unknown health carries null risk
and horizon with an explicit reason, and has no fault forecasts. Every payload
requires evidence bound to `device-audit.telemetry.v2`; model reference is
nullable for unknown output, including required null when the reason is
`model_unavailable`.

At most eight fault forecasts can use the provisional categories
`cpu`, `gpu`, `memory`, `storage`, `battery`, `thermal`, and `network`. Each
forecast carries an independent probability and positive horizon. No thresholds,
calibration, relation between health and fault probabilities, or sum-to-one
rule is defined. `IsStale(now)` returns true at and after `expires_at`; callers
supply the clock. Go validation also rejects zero timestamps and expiry that is
not after generation, semantic checks not expressible portably in this JSON
Schema. Shared vectors are checked by Go strict decoding/validation and Python
Draft 2020-12 validation. The shape and categories remain provisional pending
#14/#72 and endpoint model qualification. #22 selected a historical HDD dataset
study, not an endpoint predictor; this contract does not imply a trained or
production prediction capability.
