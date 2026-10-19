# Decisions retained from the handoff

The user explicitly requested a new organization repository and selected reuse
of Shepherd networking. The attached `chat_handoff_full_transcript.md` ends with
Turns 15ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“17 describing the current direction. Earlier security and fleet-manager
discussion can drift and does not automatically become product scope.

| Decision | Evidence | Treatment |
| --- | --- | --- |
| New repository under i-got-this-faa | Current user request, handoff 15ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“17 | Dedicated `device-audit`; Shepherd remains separate |
| Go controller | Handoff 15/17 | Selected |
| Go endpoint agent | Handoff 17 | Selected |
| Tailcat / userspace WireGuard / DERP | Current request, handoff 15/17, Shepherd spec 14 | Preserve design and package boundary; adapter absent upstream |
| Bespoke prediction model, no Jev | Explicit user statement in handoff 17 | Selected; architecture and endpoint qualification open. #22 selects only a historical HDD study. |
| Local training + central aggregation | Handoff 15ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“17; supplied claims 1/4/8, pp.26-28; [0059]-[0061], pp.13-14 | Core product capability; source references are mapped in SRC05 #72. Two-endpoint training, validated aggregation and evaluated forecast generation remain implementation work. |
| Smart contracts + cryptographic verification | Explicit user statement in handoff 17; description [0078], p.19 and FIG.2, p.31 | Selected direction; chain and contract implementation open. Claims 1-10 do not expressly specify blockchain or smart contracts. |
| Python + PyTorch | Assistant marked proposed in handoff 17 | Python interfaces included; no PyTorch dependency or model architecture selected |
| PostgreSQL | Proposed in handoff; provisional decision in #73 below | Selected provisionally for durable storage; schema remains a candidate with no runtime DB binding |
| Windows-first | On 19 October 2026 the owner explicitly requested completion of #14 and confirmed only the existing Windows laptop is available | Select Windows 11 Home Single Language 25H2 x64, build family 26200 with initial baseline 26200.9711, on the available HP Victus 15-fb0xxx/Ryzen 5 5600H/16 GB/AMD plus RTX 3050 laptop configuration. Select LocalService with a per-service state SID and default privileges for service implementation. This engineering decision takes effect through review/merge of the #14 decision PR; it is not prior owner approval of every detail or release qualification. Exact boundaries, evidence and remaining gates are in [release scope](roadmap/release-scope.md). |
| Additional endpoint platforms | #14 decision task, 19 October 2026; no additional real endpoint is available | Exclude other Windows editions/versions/architectures/hardware, Linux, macOS, Android, iOS/iPadOS, ChromeOS, BSD and all other OS/device combinations from V1 endpoint support claims. Keep portability checks and Linux development/controller/relay hosting separate. No planned task is removed. See the exhaustive [platform matrix](roadmap/release-scope.md#endpoint-platform-matrix). |
| Asset-system integration | Supplied specification [0022] page 4, [00109] page 25, and Figure 2 page 31; explicit blocked disposition recorded by #14 | Blocked because no external system/vendor, adapter contract, fields, credentials, retention or acceptance evidence is selected. Internal inventory remains a subset. #138 owns resolution; selection requires an approved owned, dependency-linked rebaseline. See [release scope](roadmap/release-scope.md#conditional-scope-decisions). |
| Independent network observation | SRC05 finds no defined observer/source/trust boundary in [0051], p.10, [0074], p.18, [0078], p.19 or FIG.2, p.31; #14 records an explicit block | Blocked because the source, permissions, trust boundary, retention and acceptance evidence are unselected. Endpoint telemetry, network identity and chain verification imply no independent observer. #138 owns resolution and any approved rebaseline. See [release scope](roadmap/release-scope.md#conditional-scope-decisions). |
| ML01 dataset/labels/partitions (#22) | Pinned Backblaze 2013 source, custom publisher terms and reproducible manifest | Select a historical HDD recorded-event study with a seven-day horizon, disjoint device cohorts and purged chronological evidence intervals. CPU/GPU/other component labels and matching endpoint SMART telemetry are absent; endpoint failure-prediction claims remain blocked. See the [decision and reproduction commands](../models/datasets/backblaze-2013/README.md). |
| Frontend | Provisional SRC04 #74 decision below | Go HTML templates, embedded static assets and progressive enhancement; no implemented console yet |
| LLM explanations | Optional in handoff | Future optional component; prediction and aggregation do not depend on it |

Scaffold choices made here: private repository by default, stdlib-only local
demo, Go 1.27.1 aligned with Shepherd/Tailcat, an ephemeral bounded sample store,
strict versioned inputs, and explicit errors for unavailable mesh transport.
These choices do not settle production hosting, tenancy, identity, model
runtime, chain, frontend or collector cadence.

## Provisional hosting, persistence and tenancy, #73

[Issue #73](https://github.com/i-got-this-faa/device-audit/issues/73) requires
hosting and access boundaries. As of 2026-10-15, its dependency
[#14](https://github.com/i-got-this-faa/device-audit/issues/14) remains open
without a recorded release-platform decision. The following choices are
provisional and reversible, made here for implementation planning rather than
inherited as approved handoff decisions.

- Use one organization per deployment, with a dedicated controller, database,
  mesh identities and secrets. Shared multi-tenant hosting is deferred. The
  candidate schema has no tenant boundary, so request-supplied organization IDs
  cannot authorize access or turn this into a shared service.
- Start with one controller service and one PostgreSQL service on a private
  host, with a persistent database volume. Put the self-hosted DERP service on
  a separate public host without database access or application credentials.
  Expose authenticated bootstrap and administrator access through an HTTPS
  proxy to the private controller. Steady-state device traffic uses the mesh.
- Select PostgreSQL provisionally for durable controller records because a
  relational schema candidate already exists. A controller restart must retain
  committed records, enrollment and revocation state. Database unavailability
  must fail writes rather than acknowledge volatile storage. Restart and backup
  assumptions are in [the database plan](../infra/database/README.md).
- The deployment operator owns server configuration, TLS, database and backup
  secrets. Endpoints own their local private keys. Mesh credentials, device
  signing keys and any future chain signer remain separate. Exposure and
  allowed/denied request cases are in [the networking plan](../infra/networking/README.md).

The current loopback fixture still loses samples on restart. Database binding,
authentication, enrollment, relay deployment and these access rules are not
implemented. No production capability or patent verification is established.
SRC05 #72 has reconciled the supplied PDF and recorded its provenance in
[the source map](source/patent-map.md). This does not establish implementation
or patent coverage.

The later [#14 decision](roadmap/release-scope.md) defines one Windows endpoint
qualification target and excludes additional endpoint support claims. Its Linux
endpoint exclusion does not exclude Linux controller or relay hosting. Asset
integration and independent observation have explicit blocked dispositions for
#138. Those blocks do not create a reverse dependency from #14 to #138.
Provider, deployment host OS, sizing, availability and recovery objectives remain
open in the hosting work. Source reconciliation #72 does not settle those choices.
Acceptance evidence still needs database
restart/restore results, authenticated access denials, secret rotation/revocation
checks and direct/relay connectivity on the selected release machines.

## Provisional telemetry/inventory contract v2

Task #15 adds a separately named `device-audit.telemetry.v2` proposal alongside
v1. The metric set and explicit units are CPU/GPU utilization, memory/disk/
battery percent, Celsius temperature, and millisecond network latency. Null
metrics require one of `sensor_unavailable`, `not_applicable`,
`permission_denied`, or `collection_error`; known metrics cannot include a
missing reason, and at least one metric must be known. Inventory supports
opaque group/network-segment IDs and up to 64 component records. Telemetry
supports up to 8 bounded log references with opaque IDs, SHA-256, at most 10
MiB per reference, and a time window; raw logs are excluded. These choices are
provisional and platform-neutral; #14's [target matrix](roadmap/release-scope.md)
does not settle provider/feature definitions (#21/#32/#85). SRC05 #72 records metric gaps:
disk space, battery charge and latency cannot stand in for disk health/I/O,
battery health/life and throughput. PDF provenance and claim reconciliation are in
[the source inventory](source/patent-map.md). They do not settle enrollment,
network identity, signature, or chain policies.

## Provisional prediction contract v2

Task #16 proposes a separate `device-audit.prediction.v2` contract and leaves
v1 types and fixture behavior intact. Predictions bind an opaque device ID,
model version plus artifact SHA-256 when a model is available, evidence digest,
telemetry schema version, generated/expiry timestamps, health state, and bounded
fault forecasts. Evidence must reference `device-audit.telemetry.v2` in this
proposal. `healthy`, `degraded`, and `critical` states carry a numeric probability
from 0 through 1, the explicit `probability` unit, and a positive horizon in
hours; they also require model and evidence references. `unknown` carries null
probability and horizon plus `insufficient_evidence`, `model_unavailable`, or
`stale_evidence`; a null model reference is required for `model_unavailable`.
Unknown predictions may not carry fault forecasts. Other unknown reasons may
retain a selected model reference as provenance.

Forecasts are limited to eight entries from the provisional set
`cpu`, `gpu`, `memory`, `storage`, `battery`, `thermal`, and `network`. Each has
its own probability unit and positive horizon; a category may recur at
different horizons. These fields do not claim
calibration: no health thresholds, probability relationships, or sum-to-one
constraint are selected. Expiry is stale at the exact `expires_at` instant;
`IsStale(now)` takes its clock explicitly. Timestamp ordering and Go's zero-time
instant check are semantic Go validation rules because JSON Schema checks only
date-time syntax. Shared prediction vectors are validated by Go and Python.
These are provisional contracts; #14's target selection does not establish endpoint model qualification.
SRC05 #72 records the source's warning/degraded terminology difference and
assigns the versioned health policy to #86/#35. #22 selected a historical HDD
dataset study; the source PDF and claim reconciliation are indexed. These contracts provide neither patent
compliance evidence nor a production model capability.

## Provisional diagnostic contracts v1, #76

[The diagnostic contract](../packages/contracts/diagnostics-v1.md) selects two
read-only probe names, explicit typed arguments and bounded wall/output budgets.
Controller-signed single-device assignments and device-signed terminal results
reuse #75's framing with separate version namespaces. SHA-256 correlation binds
the exact signed assignment. Durable first-terminal-wins, duplicate receipts,
reboot interruption and cancellation authority are consumer requirements, not
implemented state. All examples are synthetic; execution, authorization and
restart/race qualification remain future work.

## Provisional lifecycle contract v2

Issue #78 adds a separate `device-audit.lifecycle.v2` report proposal without
changing v1 or the lifecycle evaluator interface. It binds batch recommendations
and component fault-rate comparisons to cohort, baseline/current windows, and
off-chain evidence. Actionable recommendations require v2 telemetry/prediction
references, age in months, and per-device repair/upgrade/replacement costs in a
declared currency's major units. Missing inputs remain explicit null and force
`insufficient_evidence`; independent analyses can also remain unavailable.

The only supported sustainability proposal is `carbon-reduction.v1`: compare
replacement-baseline and recommended-scenario batch totals over a declared
month horizon, subtract carbon in kg CO2e and e-waste in kg, and score the
nonnegative percent reduction in baseline carbon. It makes no overall
environmental-quality claim. Zero baseline carbon cannot yield a complete score.
Longevity uses months and a confidence probability with ordered bounds.
Component fault rates use percent and changes use percentage points. The
contract README defines the assumptions and semantic validation boundaries.

These are provisional contract choices for review, not a production evaluator,
validated sustainability methodology, calibrated longevity model, fleet trend
service, or patent verification. No raw logs or device IDs are chain payloads;
network identity, device signatures, and future commitments remain separate.
## Provisional enrollment, evidence and acknowledgements, #75

[The envelope specification](../packages/contracts/envelopes-v1.md) builds on
#73's single-organization deployment boundary and #15's telemetry v2 proposal.
Enrollment, evidence and controller acknowledgements have separate v1 namespaces.
Pure Ed25519 from Go's standard library and SHA-256 key fingerprints are selected
provisionally, with a fixed application domain separator and length-prefixed
signing fields. Evidence binds the digest of exact telemetry JSON bytes, avoiding
an unselected cross-language JSON number canonicalization scheme.
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) and
[Go's Ed25519 documentation](https://pkg.go.dev/crypto/ed25519) support the
algorithm choice; neither establishes a patent requirement, production key
storage, release-machine suitability, or an approved organizational policy.

Sequences are scoped to deployment/device across restarts and keys. Enrollment
starts at 1, evidence at 2, gaps are allowed, and accepted responses require an
atomic durable commit with the high-water mark. Rejection never advances it.
A lost response can produce a replay rejection; that is not proof of receipt
of the pending payload. Recovery and authenticated receipt lookup remain open.
`enrollment_conflict` provisionally describes a binding admission conflict;
`replay` describes a consumed sequence at freshness checking. The pure helpers
cannot decide admission or challenge state, and the schemas only carry outcomes.
Whole-second UTC timestamps, a five-minute future-skew allowance and maximum
lifetimes of ten minutes for enrollment and 24 hours for evidence are provisional
contract bounds. Nullable telemetry values and their explicit units are retained.

Application signing keys, mesh/network credentials, bootstrap authorization and
future chain signing remain separate. No secret bootstrap or mesh credential is
placed in the envelopes. Another owner must review sequence, lost-response,
restart and restore semantics before consumer implementation. Durable storage,
challenge issuance, authorization, rotation/revocation, protected key storage and
real restart/restore tests remain unimplemented. #17 and the in-progress #80
harness are not implemented or changed by #75. #14's target selection does not
qualify enrollment, service permissions or endpoint runtime; SRC05 #72
records source reconciliation without establishing implementation or legal coverage.


## Source reconciliation and retained scope, SRC05 #72

The [claim map and disposition register](source/patent-map.md) separate all ten
printed claims from broader description and figure material. Current product
work maps read-only health-specific diagnostics, local training, evaluated
aggregation/forecast workflows, recommendations and methodology-based lifecycle
analysis. This mapping is engineering traceability, not proof of implementation
or legal coverage. It uses the handoff decisions recorded above; the original
transcript was not reread in the Windows source review.

OS tuning, CPU throttling and self-repair in [0062], p.14, [0077], p.19 and FIG.2
stage 208, p.31 conflict with the retained read-only/no-remediation boundary.
That exclusion remains in force. General executable-agent replacement,
hierarchical controllers, gamification, vendor marketplaces and particular
ML/XAI algorithms have unmatched or unselected details. SRC02 #14/CAP02 #138
must explicitly disposition any proposed expansion and approve owned,
dependency-linked rebaseline work. No existing release task is removed here.


## Console and administrator identity, SRC04 #74

Select server-rendered Go `html/template` pages, plain CSS and small JavaScript
ES modules for progressive enhancement. Embed templates and static files with
`go:embed` in the controller binary. Fleet tables, filters, evidence detail and
report downloads must work as ordinary authenticated page requests; charts may
add JavaScript while retaining accessible tabular values. This fits the existing
Go service and avoids a second runtime or asset package manager for the initial
console. A separate React application would add client state management
and a Node build without a demonstrated interaction requirement. Revisit that
choice if measured console needs justify it. Templates are trusted source;
evidence strings are untrusted data and must retain contextual escaping. See
[Go's template security model](https://go.dev/pkg/html/template/#hdr-Security_Model).

Target the latest and immediately previous stable desktop Chrome, Edge and
Firefox releases on supported vendor OSes at release qualification. Record exact
versions when tested. Safari, mobile browsers and Internet Explorer are outside
this initial console test target; this does not select endpoint OS support.
Keyboard operation, visible focus, 200% zoom and a 1280-pixel viewport are required
qualification cases. No browser is qualified by this documentation change.

Use one operator-configured OpenID Connect issuer and confidential client per
organization deployment. Select Authorization Code flow with PKCE S256 and a
server-side callback, exact HTTPS redirect URI, state and nonce checks. Validate
issuer, audience, signature, expiry and nonce using a maintained OIDC library
selected during implementation. Never discover an issuer from a request, email
suffix or tenant header. Identify people by the pair of issuer and subject;
operator-managed local role bindings authorize them. Email and IdP group claims
do not automatically grant roles. The operator preprovisions the first admin's
binding in deployment configuration, without a public first-user signup route.
Require MFA at the IdP and reject login if configured MFA policy is not met;
provider-specific `acr`/`amr` mapping must be qualified before deployment.
These are application choices based on
[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth),
not implemented authentication.

The controller keeps tokens and session state server-side, in the deployment's
durable store. The browser receives only a random 256-bit opaque session cookie,
`__Host-device-audit-session`, with `Secure`, `HttpOnly`, `Path=/`, no Domain and
`SameSite=Lax` for the top-level OIDC return. Store a digest of the session ID;
never log the cookie, authorization code, tokens or PKCE verifier. Use a separate
one-use login transaction with five-minute expiry. Rotate the session after
login and privilege changes. Enforce a 15-minute idle timeout and eight-hour
absolute lifetime on every request using the server clock; expiry is inclusive.
No silent refresh extends those limits. Revoked users and removed role bindings
lose access on their next request. An unavailable session/authorization store
fails closed with 503, never with fixture or in-memory fallback. These bounds are
provisional policy choices. The
[OWASP session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
explains server-side expiry and cookie protections.

`POST /auth/logout` requires CSRF validation, invalidates the local session and
clears the cookie. GET cannot log out or mutate application state. Local logout
does not promise IdP single logout; another sign-in may reuse the IdP session.
Require explicit IdP reauthentication with `max_age=0` and validated `auth_time`
within five minutes for role changes, enrollment authorization, key revocation
and model promotion. Every state-changing browser request requires an
unpredictable session-bound CSRF token and an allowed Origin. SameSite alone is
insufficient. Login return targets are allowlisted local paths. Protected HTML,
JSON and exports use `Cache-Control: no-store`; expired pages must not reveal
cached evidence through back navigation. No bearer tokens in browser storage.

The single-organization deployment from #73 is the authorization boundary.
`viewer` may inspect device/fleet health, findings, provenance and receipts, and
request bounded report exports. `admin` additionally authorizes enrollment,
revokes devices, creates/cancels allowlisted diagnostic assignments, manages
federated rounds and approves evaluated model promotion, and manages console
role bindings. Admin inherits viewer access. All actions require server-side
resource and action authorization and an audit event; hiding a control is not
authorization. Nobody may request shell execution, remediation or package rollout.
Operator-only infrastructure secrets, issuer configuration and chain signer
custody are outside browser roles. Device signing, mesh admission and future
chain credentials cannot create console sessions or grant administrator access.

The [console plan](../apps/web-console/README.md) records local build steps and
the required denied-request matrix. No routes, OIDC adapter, sessions, dashboard
or durable role store are delivered by this decision. Follow-up console and
security implementation must run that matrix against the real configured IdP
and store before exposing access. This choice is provisional and reversible;
it does not approve unresolved release scope under #14.
