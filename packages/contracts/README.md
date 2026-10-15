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

## Provisional lifecycle and component trends v2

Issue #78 adds `LifecycleV2`, `lifecycle-v2.schema.json`, and shared vectors in
`fixtures/lifecycle/v2-vectors.json`. This is an off-chain report contract;
the lifecycle evaluator, longevity model, evidence resolver, and fleet
aggregation service remain unimplemented. All fixture values are synthetic,
including recommendations. Existing contracts and interfaces are unchanged.

Provenance binds an opaque cohort ID and size, baseline/current observation
windows, and a nullable SHA-256 evidence-manifest digest. Windows are
start-inclusive/end-exclusive, positive in duration, ordered, non-overlapping,
and end by report generation. The off-chain manifest must record cohort
membership/selection, input sources, aggregation rules, cost quote dates,
prediction/model references, carbon factors, and scenario assumptions. Digests
declare references; validation does not fetch them or prove their truth.

Up to 64 recommendations identify batches by unique opaque batch ID and affected
device count within the cohort. Batches must have common cost/age and scenario
assumptions; heterogeneous batches must be split. Costs are per device in major
units of the declared three-uppercase-letter currency code; age is months since
entry into service. Validation checks currency code shape, not a currency registry
or conversion rate. Repair, upgrade, replacement costs and age are independently
nullable. `repair`, `upgrade`, `replace`, and `retain` require all those inputs,
cohort evidence, and telemetry/prediction digests bound to their v2 schema versions.
`insufficient_evidence` permits partial inputs and forces all analysis outputs to
that state. A future evaluator must resolve and validate evidence, including
prediction availability, before recommending an action. This validator does not
choose actions or implement cost optimization.

Sustainability supports only the provisional `carbon-reduction.v1` methodology,
including for insufficient-evidence payloads. Its baseline is replacement of the
batch, compared with the recommended scenario over the same positive
`assessment_horizon_months`. Carbon and e-waste inputs are totals for the affected
batch over that horizon, in kilograms CO2 equivalent and kilograms respectively.
The manifest records lifecycle boundaries and factors used for both scenarios.
Complete output requires all quantities and positive baseline carbon, plus the
recommendation prerequisites. The arithmetic is:

- `carbon_avoided_kg_co2e = baseline_carbon_kg_co2e - scenario_carbon_kg_co2e`
- `e_waste_avoided_kg = baseline_e_waste_kg - scenario_e_waste_kg`
- `score_percent = max(0, carbon_avoided_kg_co2e / baseline_carbon_kg_co2e * 100)`

The score measures carbon reduction only; it is not a validated overall
environmental rating. Negative avoided quantities preserve scenario increases.
A zero-carbon baseline cannot produce a complete score. This methodology is a
contract proposal, not an approved lifecycle assessment standard.

Longevity carries remaining, lower-bound, and upper-bound months plus an explicit
confidence probability in `(0, 1]`. Complete estimates require the recommendation
prerequisites and an ordered interval containing the estimate. The manifest must
identify the estimator, its uncertainty method, and the population to which the
interval applies. No interval calibration or remaining-life estimator is supplied.

Up to eight component trends compare observed fault rates for the same cohort and
component category across the provenance windows. Sample counts are eligible
component observations, not cohort device counts; repeat observations follow the
manifest's sampling/deduplication rule. Rates use percent and the signed change
uses percentage points, current minus baseline. Complete trends require evidence,
a nonempty cohort, and positive sample counts in both windows. Aggregation and
sampling are future work.

All fields are required. Unknown quantities use explicit null, never invented
zero. Sustainability, longevity, and trends use `complete` or
`insufficient_evidence`; the latter requires every output quantity to be null.
Known recommendations may still carry insufficient sustainability or longevity.
Go strict decoding/`Validate()` and Python Draft 2020-12 validation share the wire
fixtures. Go additionally checks window ordering, batch/cohort count relationships
and unique batch IDs, uncertainty ordering, and derived arithmetic with
relative/absolute tolerance `1e-9`; JSON Schema cannot portably express those
cross-field rules. Python schema validation alone is not semantic report validation.

The full report and manifest remain off-chain. Raw logs and device identifiers
are excluded from this report; cohort and batch IDs are application metadata, not
chain payloads or network credentials. Future chain adapters need a separate
commitment format. Nothing here authenticates a network peer, verifies a device
signature, implements anchoring, or establishes patent compliance. The original
patent PDF remains unavailable.
