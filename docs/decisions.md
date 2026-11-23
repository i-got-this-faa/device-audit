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
| Tailcat / userspace WireGuard / DERP | Current request, handoff 15/17, Shepherd spec 14 | Pinned admitted application adapter; deployed qualification remains open |
| Bespoke prediction model, no Jev | Explicit user statement in handoff 17 | Selected. #33 packages a standard-library L2 logistic baseline on the ML01 study. A larger architecture and endpoint qualification remain open. The artifact is not an ML05 pass. |
| Local training + central aggregation | Handoff 15ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Å“17; supplied claims 1/4/8, pp.26-28; [0059]-[0061], pp.13-14 | Core product capability; source references are mapped in SRC05 #72. Two-endpoint training, validated aggregation and evaluated forecast generation remain implementation work. |
| Smart contracts + cryptographic verification | Explicit user statement in handoff 17; description [0078], p.19 and FIG.2, p.31 | Base Mainnet policy selected under #47; contract/deployment implementation open. Claims 1-10 do not expressly specify blockchain or smart contracts. |
| Python + PyTorch | Assistant marked proposed in handoff 17 | Python standard library only. #33 selects a logistic baseline and does not add PyTorch. |
| PostgreSQL | Proposed in handoff; provisional decision in #73 below | Selected provisionally for durable storage; pgx connection and migrations implemented in #19; #83 adds a separate transactional signed-device repository, with HTTP integration pending |
| Windows-first | On 19 October 2026 the owner explicitly requested completion of #14 and confirmed only the existing Windows laptop is available | Select Windows 11 Home Single Language 25H2 x64, build family 26200 with initial baseline 26200.9711, on the available HP Victus 15-fb0xxx/Ryzen 5 5600H/16 GB/AMD plus RTX 3050 laptop configuration. Select LocalService with a per-service state SID and default privileges for service implementation. This engineering decision takes effect through review/merge of the #14 decision PR; it is not prior owner approval of every detail or release qualification. Exact boundaries, evidence and remaining gates are in [release scope](roadmap/release-scope.md). |
| Additional endpoint platforms | #14 decision task, 19 October 2026; no additional real endpoint is available | Exclude other Windows editions/versions/architectures/hardware, Linux, macOS, Android, iOS/iPadOS, ChromeOS, BSD and all other OS/device combinations from V1 endpoint support claims. Keep portability checks and Linux development/controller/relay hosting separate. No planned task is removed. See the exhaustive [platform matrix](roadmap/release-scope.md#endpoint-platform-matrix). |
| Asset-system integration | Supplied specification [0022] page 4, [00109] page 25, and Figure 2 page 31; explicit blocked disposition recorded by #14 | Blocked because no external system/vendor, adapter contract, fields, credentials, retention or acceptance evidence is selected. Internal inventory remains a subset. #138 owns resolution; selection requires an approved owned, dependency-linked rebaseline. See [release scope](roadmap/release-scope.md#conditional-scope-decisions). |
| Independent network observation | SRC05 finds no defined observer/source/trust boundary in [0051], p.10, [0074], p.18, [0078], p.19 or FIG.2, p.31; #14 records an explicit block | Blocked because the source, permissions, trust boundary, retention and acceptance evidence are unselected. Endpoint telemetry, network identity and chain verification imply no independent observer. #138 owns resolution and any approved rebaseline. See [release scope](roadmap/release-scope.md#conditional-scope-decisions). |
| ML01 dataset/labels/partitions (#22) | Pinned Backblaze 2013 source, custom publisher terms and reproducible manifest | Select a historical HDD recorded-event study with a seven-day horizon, disjoint device cohorts and purged chronological evidence intervals. CPU/GPU/other component labels and matching endpoint SMART telemetry are absent; endpoint failure-prediction claims remain blocked. See the [decision and reproduction commands](../models/datasets/backblaze-2013/README.md). |
| ML05 evaluation and resource thresholds (#86) | Declared 17 November 2026 before any fit; pins the ML01 policy and manifest | Numerical baseline, false-positive, calibration and horizon gates, a once-only device-clustered held-out procedure, and endpoint inference/training budgets tied to the measured laptop. Missing labels or measurements block rather than relax a threshold. See [ML05 thresholds](../models/evaluation/README.md). |
| Frontend | Provisional SRC04 #74 decision below | Go HTML templates, embedded static assets and progressive enhancement; a minimal console/auth surface is implemented, dashboard pages are not |
| LLM explanations | Optional in handoff | Future optional component; prediction and aggregation do not depend on it |

Scaffold choices made here: private repository by default, stdlib-only local
demo, Go 1.27.1 aligned with Shepherd/Tailcat, an ephemeral bounded sample store,
strict versioned inputs, and explicit errors for unavailable mesh transport.
These choices do not settle production hosting, tenancy, identity, model
runtime, chain or collector cadence.

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

The current loopback fixture still loses samples on restart. The controller can
connect to PostgreSQL, apply the #19 migrations and host the #82 administrative
OIDC/session surface. #83 adds signed enrollment/evidence repository operations,
and #18 now adds TLS bootstrap admission. Signed telemetry HTTP integration,
relay deployment and the remaining access rules are not implemented. No
production capability or patent verification is established.
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

## Durable database binding and migrations, DB01 #19

The controller now binds the provisional PostgreSQL decision with
`github.com/jackc/pgx/v5` through `database/sql`. `DEVICE_AUDIT_DATABASE_URL` or
`--database-url` selects the database. Startup pings the database, applies
embedded forward-only migrations and reports the applied `schema_version` from
`/healthz`; a connection or migration failure aborts before the HTTP listener
binds. An empty URL keeps the explicit memory development mode and reports
`database=not_configured`.

`schema_migrations` records each applied version. One PostgreSQL advisory lock
serializes concurrent controllers, each migration runs in its own transaction,
and a failed migration leaves the previous version without dropping or
recreating tables. These are implementation choices under #19, not a retention,
backup, recovery-objective, TLS, least-privilege or production-schema decision.
The candidate `001_initial.sql` and `002_console_auth.sql` tables are applied.
Console role bindings, login transactions and sessions are durable. #83 adds
a separate durable signed-device repository, described below. The fixture API
continues to use memory. #18, #24 and #89 now provide authorized admission,
evidence verification and signed acknowledgements; #90 adds revocation authority. #14 still bounds the deployment
target; no production persistence is claimed.

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

## Provisional federated contracts v1, #77

[The federated contract](../packages/contracts/federated-v1.md) binds rounds to
exact base artifacts, features and participant/key eligibility. Complete bounded
binary64 model weights, sample counts and digests are device-signed with #75's
framing; local observations are excluded. Explicit promotion/rejection records
retain candidate/evaluation/policy provenance. Quorum, finite values and exact
compatibility are contract checks, not a training or promotion service. Durable
admission, evaluated aggregation and privacy defenses remain future work.

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

## Typed read-only probe catalog, DIA01 #36

On 18 November 2026 `packages/workflows` gained the endpoint catalog for the
two CT06 probes. One exported check, `DiagnosticArgumentsV1.ValidateFor`, now
serves both assignment validation and the catalog, so the allowlist cannot
drift. There is no generic executor: each probe ID maps to one Go function.

`storage_health.v1` resolves `component_id` only in the form
`storage:disk-<n>`, the OS disk number from 0 to 63. It does not use a serial
number or path. The disk is opened with no access rights and read through
`IOCTL_STORAGE_QUERY_PROPERTY`, including the NVMe health log page. That works
for a standard user, so no privilege is requested. Removable, USB, SD/MMC and
virtual disks are not eligible. A non-NVMe disk reports `not_applicable`
instead of guessing at SMART. Mapping inventory component IDs (#97) to these
local IDs is not done.

`system_errors.v1` reuses the TEL07 reader with the assignment's lookback and
per-log entry limit. It never moves the `--collect-errors` read positions.
Event messages are reduced to a SHA-256 digest. Any process can log under an
arbitrary unregistered source name, so a provider name is kept only when its
publisher is registered and the name is publisher-shaped. Otherwise it is reduced
to its digest. A denied log or disk is a `permission_denied` failure without
retry, elevation or state change. Each OS call is abandoned at the wall budget,
and any outcome observed after it is `budget_exhausted`. Evidence larger than
`max_output_bytes` is never returned. Assignment signature and target checks
and signed results remain DIA03 #38. Evidence is in
[probe-catalog-36.md](validation/probe-catalog-36.md).

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
A replay rejection provides no proof of receipt. TEL09 #96 adds exact-request
receipt recovery in the mesh controller without changing this wire contract.
`enrollment_conflict` provisionally describes a binding admission conflict;
`replay` describes a consumed sequence at freshness checking. The pure helpers
cannot decide admission or challenge state, and the schemas only carry outcomes.
Whole-second UTC timestamps, a five-minute future-skew allowance and maximum
lifetimes of ten minutes for enrollment and 24 hours for evidence are provisional
contract bounds. Nullable telemetry values and their explicit units are retained.

Application signing keys, mesh/network credentials, bootstrap authorization and
future chain signing remain separate. No secret bootstrap or mesh credential is
placed in the envelopes. Another owner must review sequence, lost-response,
restart and restore semantics before consumer implementation. #83 now implements
durable challenge storage, atomic consumption and signed
identity/evidence persistence with isolated crash/restart tests. The later #18
implementation below adds authorized challenge issuance and bootstrap admission.
Rotation/revocation authority, protected endpoint key storage and backup-restore
qualification remain open. #17 is not changed by #75.
The #80 shared conformance command below now runs the envelope fixtures.
#14's target selection does not qualify enrollment, service permissions or
endpoint runtime; SRC05 #72
records source reconciliation without establishing implementation or legal coverage.


## Provisional audit commitment contracts v1, #79

[The audit format](../packages/contracts/audit-v1.md) keeps signed evidence and
lifecycle manifest references off-chain. Only a random opaque ID and blinded
SHA-256 commitment are public, under a separate version namespace. Policy,
application signing identity and nonce remain inside the signed private manifest.
Receipt finality and evidence integrity are separate states; missing/expired
evidence differs from digest mismatch. This selects an encoding, not a chain,
finality threshold, resolver, production key store or anchoring implementation.

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
[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth).
The #82 implementation below records the currently delivered subset.

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
the required denied-request matrix. SEC06 #82 now delivers the minimal console,
OIDC adapter, PostgreSQL sessions, role store and protected admin routes
described below. Fleet pages, exports and most administrator actions remain
absent, and the matrix has not been run against a real configured IdP or a
browser. This choice is provisional and reversible; it does not approve
unresolved release scope under #14.

## Administrative authentication implementation, SEC06 #82

[Issue #82](https://github.com/i-got-this-faa/device-audit/issues/82) implements
the minimal console identity boundary selected by #74. It is an application
scaffold, not production identity federation.

- The controller accepts one operator-configured OIDC issuer and confidential
  client. Authorization Code flow uses PKCE S256, state, nonce, an exact
  callback URL and `github.com/coreos/go-oidc/v3` plus `golang.org/x/oauth2`.
  Issuer, audience, signature, expiry and nonce are verified. The issuer is
  never taken from a request, email suffix, tenant header or proxy header.
- Discovery is lazy. An IdP outage fails new logins closed while existing local
  sessions remain usable until expiry or revocation. There is no development
  login bypass.
- A one-use login transaction is stored server-side with five-minute expiry.
  The browser-bound login cookie carries a digest of the state. The callback
  consumes the transaction before exchanging the code, then verifies the
  returned ID token and configured MFA `amr` value. The default required value
  is `mfa`; an empty value relies on the issuer policy. Provider-specific
  `amr`/`acr` mapping is not qualified.
- PostgreSQL `002_console_auth.sql` stores role bindings, login transactions
  and server-side sessions. Sessions use a random opaque cookie
  (`__Host-device-audit-session`), store only the SHA-256 digest, use `Secure`,
  `HttpOnly`, `Path=/`, no `Domain` and `SameSite=Lax`, and enforce 15-minute
  idle and eight-hour absolute expiry with exact boundaries. Session and login
  store failures return 503 rather than using memory fallback.
- Role bindings are keyed by the configured issuer and subject. `viewer` may
  read the minimal console; `admin` may also list and change role bindings.
  Admin inherits viewer. There is no public signup and no role inferred from
  email, group or tenant claims. `--bootstrap-admin` creates a missing first
  admin binding; it never overwrites an existing role. The PostgreSQL store and
  the in-memory test store reject a role change that would leave no admin.
- Changing a binding to a different role revokes the subject's existing local
  sessions. An existing session whose stored role differs from the current
  binding is also denied and revoked, so a failed or incomplete revocation
  cannot grant new authority. Removing a binding or revoking a session denies
  the next request. A previously issued cookie cannot retain removed authority.
- `/console`, `/auth/session`, `POST /auth/logout` and
  `/admin/role-bindings` are protected. Anonymous safe GETs for HTML redirect
  to login; anonymous JSON and mutations return 401 without protected data.
  Unsafe browser requests require an exact `Origin` match and a session-bound
  CSRF token. Wrong-scope requests return 403. Protected responses use
  `Cache-Control: no-store` plus content, referrer and frame protections; console
  pages add a restrictive content security policy.
- Login, logout, allowed requests, denied requests and role changes emit
  metadata-only logs. Cookies, authorization codes, tokens, PKCE verifiers and
  client secrets are not logged. Provider exchange errors are reduced to their
  error type before logging.
- The existing `/v1/telemetry` and `/v1/devices/{id}` fixture routes are not
  administrator surfaces and remain unauthenticated loopback development
  routes. A deployment proxy must not expose them as a substitute for protected
  console or enrollment routes.

Tests use a temporary TLS OIDC issuer and temporary PostgreSQL databases. They
cover login, PKCE exchange, state/nonce rejection, one-use and expired login
transactions, MFA rejection, unknown identities, forged headers, role scope,
CSRF and Origin rejection, logout replay, idle and absolute expiry, role-change
revocation, last-admin rejection, store outage, IdP outage and secret-free logs.
The PostgreSQL lifecycle test covers bindings, login consumption, session touch
and revocation, subject-session revocation and closed-store failure.

Every login requests `max_age=0` and validates signed `auth_time` against the
login transaction and a five-minute window. Role changes require that verified
authentication to be no older than five minutes, plus admin scope and CSRF.
Role updates and session revocation commit in one transaction.

Important gaps remain. Audit events are process logs, not durable records.
A real IdP, provider-specific MFA mapping, browser matrix, IdP single logout or
back-channel revocation, login rate limiting, expired-row cleanup, session
rotation on privilege change by re-login, and production secret custody remain
unimplemented or unqualified. The fixture API still has no device
authentication. This section does not claim production admission, release
qualification, durable telemetry or patent conformance.

## Shared contract conformance, CT05 #80

[The conformance catalogue](../packages/contracts/conformance-v1.md) unifies
existing fixture readers under `make contract-check`. JSON Schema shape,
Go semantic/signature checks and the test-only Python readers have separately
declared expectations. Exact raw-wire cases pin incompatible schema, null,
canonicalization and pure replay/expiry outcomes. Python does not authenticate
signatures, and schema validity cannot establish semantic validity. Hashes and
classifications are retained as CI artifacts. Both owners' fixture review remains
required before dependent implementations merge; no runtime capability is added.

## Transactional device repository, DB02 #83

The owner confirmed repository-only scope on 23 October 2026, including durable
challenge storage/consumption and writer-kill plus PostgreSQL-restart evidence.
Migration 003 adds a database deployment binding and separate trusted signed
identity/evidence tables. Candidate device rows remain unchanged and gain no
trust. Signing enrollment requires no mesh key.

The [repository boundary](../internal/controller/repository.md) verifies existing
v1 envelopes, preserves exact v2 telemetry bytes and signed provenance, and
atomically commits challenge consumption/initial sequence or evidence/updated
sequence. PostgreSQL row locks serialize concurrent writers per device. The
stored mark is independent of sample retention and must be shared by future
diagnostic/federated consumers. Transaction-local synchronous commit overrides
an asynchronous session default; host durability remains a deployment concern.

[PR validation evidence](https://github.com/i-got-this-faa/device-audit/pull/186#issuecomment-6359146745) records real PostgreSQL 17.11
integration, rollback, contention, writer termination and abrupt database
recovery checks. The controller's unsigned fixture route remains in memory.
The later #18 implementation below adds authorized bootstrap admission. Signed
responses, revocation authority/races, authenticated reconciliation, retention and backup-restore qualification remain
follow-on work. No new wire contract, production capability or chain payload is
claimed. Both owners' contract/integration review and a reviewed PR remain
required before merging dependent work.

## One-use bootstrap admission, SEC01 #18

The owner requested completion of #18 on 24 October 2026 after its dependencies
#73, #80, #82 and #83 closed. [Bootstrap admission v1](../packages/contracts/bootstrap-v1.md)
adds a separate wrapper around unchanged signing enrollment v1. Token issuance
requires the existing administrator session, Origin/CSRF checks and verified
OIDC authentication within five minutes. The fresh-admin middleware is shared
with role changes.

Tokens contain 256 random bits, authorize one device in the configured deployment
and expire after ten minutes. Only their SHA-256 digests and issuance provenance
are stored. Challenge creation binds one signing/network key tuple to the token.
A NaCl anonymous sealed box encrypts a fresh 32-byte proof to the endpoint's
canonical X25519 public key. The endpoint signs its recovered proof, network key
and original enrollment fingerprint using the separate Ed25519 key. This proves
possession of both keys without importing Tailcat into the application module.
The implementation uses pinned `golang.org/x/crypto/nacl/box` v0.58.0. Its
required `x/sys`, `x/sync` and `x/text` module versions are recorded in go.mod.

Migration 004 adds bootstrap-token, network-challenge and network-binding tables.
Final admission locks token then challenge and atomically commits both consumed
marks, the signing identity, initial sequence and unique network binding. The
internal signing-only repository path remains separate and grants no network
admission. Both token and envelope expiry are rechecked after possible lock waits.
Network proof plaintext is never persisted; the binding retains public metadata
and the complete signed request fingerprint. Lost COMMIT responses remain
uncertain and retries never fabricate success.

Enrollment is enabled only with a configured deployment ID, PostgreSQL,
administrator authentication, TLS certificate/key files and HTTPS public origin.
The loopback listener uses TLS 1.3 and public proxies must verify TLS upstream.
Forwarded scheme/identity headers cannot bypass these checks. HTTP 201 returns
a TLS-authenticated admission result after commit, not a signed evidence receipt.
The [operator guide](../infra/enrollment/README.md) records configuration,
credential delivery, route exposure and reproduction commands.

Real PostgreSQL/TLS tests cover authorization denials, proof mismatch, expiry,
concurrent start and redemption across independent repositories, key conflicts,
every admission-write rollback and deferred COMMIT failure. An isolated abrupt
PostgreSQL restart preserves both bindings and token/challenge consumption.
These checks use synthetic endpoint keys and precreated local sessions. They do
not qualify a real IdP, browser flow, deployed proxy, physical endpoint, mesh
transport or endpoint key storage. Early bootstrap-token revocation, rate limits,
cleanup, device revocation, key rotation/recovery, authenticated receipt lookup
and off-host backup restore remain separate work. Shared contract/integration
owner review and reviewed PR merges remain required to close #18.

## Inventory assertions, API03 #97

The 27 October 2026 implementation reuses telemetry v2's component/group/segment
shape in separately versioned administrator assertions. Schema version 5 stores
complete inventory revisions tied to signed enrollment, with source references,
observation/recording times and session-derived issuer/subject provenance.
Updates require fresh administrator authentication and optimistic revision
checks; viewer reads support latest and exact historical revisions. Unknown
component identities remain absent, and omitted memberships remain unknown.
This adds neither automatic cohorts nor network authorization. See the
[contract](../packages/contracts/inventory-v1.md) and
[API/storage boundary](../internal/controller/inventory.md).

## Device list and latest state, API01 #28

The controller serves a keyset-paginated, viewer-scoped device list and detail
over the durable repository. Latest state is the evidence row at the device's
committed `last_sequence`, so nothing is cached and a restart changes nothing.
The tenant is the single configured deployment; the client must name it and a
mismatch fails with 403 rather than returning an empty page. Page size is
capped at 100 and an excess is rejected. Sensor availability distinguishes a
reported null (`missing`) from an omitted metric (`not_reported`). See the
[contract](../packages/contracts/device-state-v1.md) and
[API boundary](../internal/controller/inventory.md). Not covered: filtering,
sorting other than device ID, health verdicts, and the web console device view.

## Telemetry and evidence history, API02 #98

History is a per-device, time-windowed read of `device_evidence`, ordered by
`(collected_at, sequence)` with a keyset cursor so equal timestamps page
deterministically. Both window ends are required, the window is capped at 31 days
and the page at 100; excess is rejected rather than clamped. Samples return their
source, receive time, request digest, unit-bearing nullable metrics and
`log_references` (digests only). No new table, so history survives restarts and
the reads reuse the #28 deployment scope. See the
[contract](../packages/contracts/telemetry-history-v1.md) and
[API boundary](../internal/controller/inventory.md). Not covered: retention,
aggregation, export and the web console history view.

## Protected console navigation, WEB01 #29

The 27 October 2026 implementation keeps the SRC04 template/ES-module choice.
`apps/web-console` now owns embedded templates and assets. The existing auth
service authorizes the workspace, device/workflow destinations and administrator
access listing before rendering. Device browsing and workflow execution remain
explicitly unavailable; the shell displays no fixture fleet or fabricated health.

Anonymous navigation preserves only exact allowlisted destinations through OIDC.
Role denials and auth-store outages render public pages without protected account
content. The shell adds responsive navigation, keyboard focus, a skip link and
CSRF-protected form logout that also works without JavaScript. Optional JavaScript
conceals background/history content until the server revalidates the session and
ends the local view at its conservative per-page expiry. Server expiry remains
authoritative. No token is stored in browser storage.

Browser testing found that `no-referrer` caused Chromium logout forms to send
`Origin: null`. Rendered pages now use `strict-origin`, preserving the real
Origin while omitting paths and queries. Authentication and CSRF checks are
unchanged. The [console guide](../apps/web-console/README.md) records the
repeatable browser target, test dependency, evidence and qualification limits.


## Fixture device browsing, WEB06 #99

The console renders named local fixture scenarios through the existing protected
viewer routes. List and detail views share one catalogue under
`apps/web-console/fixtures`, including the unchanged TST02 replay telemetry
payload. Existing telemetry v2 types retain nullable values, missing reasons and
explicit units. No new wire contract, fixture endpoint, database integration or
signing claim is introduced. Shared contract-owner review remains a merge gate
if a later change touches shared fixtures or contracts.

Live and offline are scripted example states under a displayed fixed clock.
Every device page identifies its data as synthetic. Loading and error examples
are explicit previews; authentication failures still fail closed before fixture
rendering. See the [console guide](../apps/web-console/README.md#device-fixtures)
and [local validation](validation/console-fixtures-99.md). Production device reads,
real telemetry freshness rules and health assessments remain separate work.

## Enrolled device freshness in the console, WEB02 #30

`/console/devices` now reads enrolled devices from the durable repository that
serves the device state API. Fixtures moved behind an explicit `?fixture=`
selector, so an unconfigured or failing inventory is never replaced by
synthetic devices. The console receives the repository through `auth.Config`
as a narrow `DeviceReader` interface. The controller maps repository not-found
and invalid-query errors to the console's errors.

Freshness is console display policy, not a wire field. It classifies the
latest sample's observed time against the controller clock: stale at three
minutes, offline at fifteen. Both thresholds are inclusive. Receipt time is
not used, because a drained spool backlog would otherwise look current. The
thresholds are provisional and sized for the 60-second default emit interval;
qualifying them against physical endpoints and per-device cadence remains open.
The device state v1 contract is unchanged.

## Console telemetry and error history, WEB07 #100

`/console/devices/{id}/history` renders the #98 history read through the same
`DeviceReader` seam as the inventory, so it needs no new endpoint or table. The
default window is the last 24 hours; a next-page link pins both window ends
because a cursor is only valid for the window that produced it. Failure classes
map to distinct statuses and copy: empty window (200), store failure (503),
unknown device (404), invalid window, cursor or parameter (400). A
`permission_denied` metric is shown as denied collection, never as zero. Error
evidence is shown only as the sample's digest, size and window. Not covered:
retention, aggregation, charts, export and filtering by error type.

## Admitted mesh application transport, NET02 #25

The 13 November 2026 implementation promotes the NET01 Tailcat pin into the
application module. The independent lab remains separately versioned. Endpoints
import their existing protected, admitted X25519 key. The controller provisions
persistent node/PSK state and startup never generates replacement identities.
An explicit local self-hosted DERP region and a separately delivered server key
pin replace public relay discovery defaults. PSK-bearing addresses use private
files, and unsafe address-debug logging is rejected.

On 16 November 2026 the controller store gained a Windows ACL path beside the
Unix owner/mode path. Both use the same JSON node and PSK fields. Windows
protection is a protected DACL for the current user or an enabled per-service
SID, plus an exclusive lock and reparse/link rejection. It is the permission
equivalent of mode 0700/0600, not DPAPI encryption of controller mesh state.
LocalService without a per-service SID fails closed. A GitHub-hosted Windows
test account can exercise that store; that account is not the selected physical
laptop and is not a LocalService qualification. Power-loss durability remains
unclaimed. Unix still fsyncs the state file and its directory; Windows flushes
the state file and has no directory fsync.

New connections resolve the actual tunnel peer against committed, active
PostgreSQL admission. Each evidence request rechecks admission and scope before
the existing repository independently verifies CT04 signatures, sequence,
freshness and revocation in its transaction. Only signed evidence ingestion is
on the application mesh. Bootstrap, OIDC, inventory and administrator APIs stay
on their separate HTTPS boundary. Unsigned fixture routes are excluded there
when mesh mode is selected. No device key is reused as a chain signing key.

#89 replaced the empty HTTP 204 response with signed acknowledgements; see the
SEC08 decision below. Uncertain commits never become success; callers retain
their original signed envelope. See
the [adapter guide](../networking/mesh/README.md) for commands, failure handling,
restart/direct test scope and unqualified physical/deployed paths. Local
implementation does not complete reviewer/merge or release qualification gates.

## Signed evidence acknowledgements and replay, SEC08 #89

The mesh evidence handler answers with controller-signed CT04 acknowledgements.
A separate PKCS#8 Ed25519 key from `--ack-key-file` signs them. Endpoints pin
its public half with `--controller-ack-key-file`, just as they pin the mesh
server key. We chose operator pinning over adding the key to the bootstrap
response. Operator pinning needs no wire change and keeps the receipt key
separate from the mesh, TLS, device and chain keys. Key rotation is not
implemented.

SEC08 signs `accepted` with the stored receive time after COMMIT. The
PostgreSQL device row lock serializes writers and the mark survives a
controller restart. Signed rejections are limited to correlatable requests
that name the admitted peer's own device. A failed or uncertain COMMIT returns
an unsigned 503. See the [SEC08 validation](validation/replay-acknowledgements-89.md).

## Authenticated spool drain, TEL09 #96

Recover a lost receipt through the same mesh POST. Under the device row lock,
after peer authorization, revocation and signature checks, an exact match
against the stored request digest returns the original receive time. The
controller regenerates the original signed `accepted` with the same pinned
key. This works after expiry and a later commit while the original row is
retained. A different request digest or an absent row at a consumed sequence
stays rejected. A replay rejection cannot authorize retirement. This needs
the existing CT04 acknowledgement and PostgreSQL columns only.

The opt-in service worker retries only the queue head and keeps sampling
during outages. It retires the head through the spool's existing durable
acknowledgement operation. A signed rejection, invalid acknowledgement or
HTTP admission denial logs a stopped delivery state without retiring the
head. Confirmed revocation depends on an authenticated rejection reaching
the endpoint. See the [TEL09 validation](validation/spool-drain-96.md).

## Device revocation authority, SEC09 #90

A fresh console administrator revokes a device with
`POST /console/api/devices/{id}/revocation` and a
`device-audit.device-revocation-request.v1` body. The body carries an opaque
`reason_reference`, never free text. The controller answers with the stored
`device-audit.device-revocation.v1` record: 201 when it revoked the device, or
200 with the original record when the device was already revoked. Actor,
deployment, receive time and enrollment digest come from the server.

We chose to reuse `device_enrollments.revoked_at` as the only admission flag,
because tunnel admission, per-request peer checks and locked ingestion already
read it. Migration 006 adds `device_revocation_events` as the durable audit
record. It holds one row per enrollment and is written in the same transaction
as the flag. Revocation is permanent. Reinstating a device would need a new
enrollment and key rotation (#130), which this work does not add.

Revocation takes the device row lock that `AcceptEvidence` takes. We rely on
that lock rather than an application mutex or a stricter isolation level. A
sample already holding the lock is admitted before the revocation. A sample
waiting behind it is rejected. An established tunnel is not cut when the
revocation commits. Its next request fails the peer check and is disconnected.
That request gets an unsigned 403, as an unknown peer does. A sample already
queued on the lock gets a signed `revoked_key`.

Unauthorized attempts are denied by the existing session middleware and logged
as security events. They are not written to the audit table. The relay
admission file stays static, so a revoked peer can still reach the relay until
an operator edits it. The controller still denies that peer. Evidence and
remaining gaps are in [device-revocation-90](validation/device-revocation-90.md).

## Release chain and writer policy, CHAIN01 #47

On 13 November 2026, select Base Mainnet, EVM chain ID 8453, for asynchronous
CT09 blinded audit commitments. Base Sepolia is development-only. Prefer its
expected rollup write-cost advantage over direct Ethereum L1 execution while
accepting sequencer, rollup governance/derivation and Ethereum consensus risk.
This expected cost advantage is an inference, not a measured contract quote.

Use a non-upgradeable registry, a dedicated limited chain writer and a 2-of-3
hardware-backed administrator multisig. Controller audit/device/mesh/OIDC keys
remain separate. A dedicated non-exportable signer service has no plaintext
fallback. Pin network, contract/code, roles and deployment history through a
reviewed descriptor; the committed example is disabled with absent addresses.

Require verified canonical inclusion at or below Base's L1-derived finalized
head, independently cross-checked. Inclusion, `safe`, elapsed time and fixed L2
confirmation counts cannot grant finality. Preserve pending/finalized/reverted
CT09 observations and clear current finality after a proven reorg. Outages or
inconsistent sources make current verification unavailable, not successful or
proven reverted. Keep signed manifests durably off-chain and expose anchoring
as pending/unverified. The [policy](../contracts/release-policy.md) records exact
role limits, fee ceilings, nonce reconciliation, retry and incident behavior,
official protocol sources and follow-on runtime/release gates. No funds, chain
accounts, contract or signer service have been provisioned by this decision.

On 16 November 2026 the same decision gained machine-checked descriptor and
observation fixtures. `contracts/policy` accepts the disabled Base Mainnet
descriptor and rejects incomplete enabled descriptors, zero addresses, null
`enabled`, and local descriptors that use chain IDs 1, 8453, or 84532. Parse,
not the JSON Schema wei pattern, rejects raised fee ceilings. Reference checks
reject listed key and device-identity words and do not prove a name contains
no secret. Observation fixtures require one
finality claim, preserve history, and keep outages and source disagreement
distinct from reverts. Draft 2020-12 schema validation covers the same
descriptor vectors. `ReleaseDeploymentObserved` stays false. No RPC query,
transaction, deployment, measured gas quote, or signer-custody check was added.
The legacy Anchorer interface remains unimplemented.

## Collector permission and cadence harness, TEL04 #85

On 16 November 2026 the telemetry package gained a planning permission catalog,
a 15-second and 60-second cadence scheduler, and an in-process sampler. The
catalog is the minimum read set for the selected sources. It rejects
administrator, LocalSystem, SeDebug, a broad event-log group, WMI ACL changes
and Security-log access. Planning and denied profiles are unattested capability
sets. Native token attestation returns an error, including on Windows, until a
measured LocalService token and a separately provisioned denied token exist.

The sampler preserves nulls on denial, timeout and collection failure, continues
to later sources, and does not insert catch-up sweeps. Its report schema is
`device-audit.collector-budget.harness.v1`. It is not telemetry v1 or v2 and it
carries no device identifier. Process CPU and RSS describe the sampler process
only. The 16 November Linux measurements and the exact remaining physical
Windows steps are in [collector-budget-85.md](validation/collector-budget-85.md).
Those measurements do not approve a production cadence, memory budget or
service-permission claim. The production collector interface still returns
`ErrNotImplemented`.

`AttestNativeToken` still returns an error. A separate manual workflow,
`service-budget.yml`, can install the probe and synthetic harness as Windows
services on a GitHub-hosted `windows-2025` runner under `NT AUTHORITY\LocalService`
and a distinct low-privilege account. Its attestation schema is
`device-audit.service-token-attestation.v1`. That runner is a hosted VM. It
does not satisfy the two-physical-machine gate, and the workflow does not
change sensor, WMI or event-log ACLs or grant administrator rights. The 16
November 2026 run 43859814735 recorded both tokens and the 15s/60s measurements;
the numbers are in [collector-budget-85.md](validation/collector-budget-85.md).
They do not approve a production budget.

## Nullable battery, thermal and GPU collectors, TEL06 #92

On 17 November 2026 `packages/telemetry` gained a `SensorCollector` with four
independently bounded sources: `battery`, `thermal`, `gpu_engine` and
`gpu_vendor`. On Windows they call `GetSystemPowerStatus`, the PDH
`\Thermal Zone Information(*)\Temperature` and `\GPU Engine(*)\Utilization
Percentage` counters, and the already-installed System32 `nvidia-smi.exe` with
fixed arguments. No PowerShell, COM/WMI session, shell, PATH search, driver or
tool install is used. These Go providers replace the probe's CIM classes for
the collector only; the PowerShell probe and the #85 planning catalog are
unchanged, and each source still maps to one catalog capability.

Every reading carries metric, unit, provider and a source-local index label.
Nulls use exactly the telemetry v2 reasons plus a fixed detail word: no system
battery is `not_applicable`; an absent thermal object, no thermal zones or an
unreadable Kelvin value is `sensor_unavailable`; a PDH or vendor access denial
is `permission_denied`; timeouts, panics and unknown errors are
`collection_error`. Provider error text is never exported. Zero GPU engine
instances are `sensor_unavailable`, not `not_applicable`, because the hosted
denied service account in #85 saw zero instances on a VM with an adapter. A
failing source never stops later sources.

`SensorSample.MetricsV2` fills the existing v2 fields without a contract
change: `battery_percent` is the system charge, `temperature_c` is the highest
ACPI zone, and `gpu_utilization` is the highest adapter or NVIDIA utilization.
The NVIDIA GPU temperature never fills `temperature_c`. These aggregations are
provisional and are not health inputs. Provider names stay in the collector and
availability report because v2 has no provider field; adding one needs a
separate contract PR. The endpoint agent's `Collector` still returns
`ErrNotImplemented` until #91 lands CPU, memory, disk and network. Linux and
macOS sources return `sensor_unavailable` (`platform_not_selected`); #14
selects no non-Windows endpoint. Evidence and the remaining two-physical-target
gate are in [sensors-92.md](validation/sensors-92.md).

## CPU, memory, disk and network collectors, TEL05 #91

On 17 November 2026 `SensorCollector` gained `cpu`, `memory`, `disk` and
`network` sources instead of a second collector, so they share the #92
per-source deadline, panic isolation, v2 missing reasons, observation time and
`endpoint_sensor` provenance. On Windows they call `GetSystemTimes`,
`GlobalMemoryStatusEx`, `GetDiskSpaceInformationW` (volume-wide units, so a disk quota cannot skew usage) for each fixed volume and
`GetIfTable2Ex` for hardware, non-filter interfaces. CPU and network rates come
from two counter reads 250 ms apart inside one source read. A counter that moved
backwards is `collection_error` / `counter_reset`; a down, removed or absent
interface is `sensor_unavailable`; a denied volume is `permission_denied` for
that volume only. No rate is negative and no unavailable value becomes zero.

`MetricsV2` now fills `cpu_utilization`, `memory_percent` and
`disk_used_percent` (the fullest fixed volume) without a contract change. v2 has
no network-rate field, so rates stay in the collector sample and availability
report until a separate contract PR. `EndpointTelemetryV2` and
`endpoint-agent --collect-telemetry --device-id` produce a validated
`source = endpoint` payload that `--sign-evidence` accepts for the admitted
device. This replaces the `ErrNotImplemented` collector boundary noted in the
#85 and #92 entries; `UnimplementedCollector` had no caller and was removed.
The HP Victus run, the open second-target and service-token gates are in
[telemetry-91.md](validation/telemetry-91.md).

## Structured Windows error evidence, TEL07 #93

On 17 November 2026 `packages/telemetry` gained `ErrorCollector` for Critical
and Error events (levels 1 and 2) of the System and Application logs only. It
calls `wevtapi.dll` directly. Each record keeps log, record ID, provider, event
ID, level, creation time and a message bounded to 2,048 bytes with an explicit
status (`complete`, `truncated`, `malformed`, `oversized`, `unavailable`). At
most 256 records per log per poll are returned. Computer name, user SID, event
data and XML are not copied. Records are off-chain.

A read position is the last examined record ID plus its creation time. Each poll
classifies the saved record as `continued`, `rollover` (overwritten) or `reset`
(cleared or replaced) and queries `EventRecordID` above the position, so a
repeated poll cannot return a collected record. The endpoint agent saves the
positions in its private state directory with a checksum, and only after the
batch is written; damaged state fails closed. Delivery is at least once: a crash
between output and save can repeat records. Consumers deduplicate on log, record
ID and creation time, because a cleared or replaced log restarts record IDs.
Permission denial, an absent log and timeouts are per-log
outcomes that keep the saved position. Evidence, including an observed Security
log denial on the Victus, is in [error-evidence-93.md](validation/error-evidence-93.md).

## Bounded configurable sampling, TEL08 #94

On 17 November 2026 `packages/telemetry` gained a `Scheduler` driven by a strict
`device-audit.sampling-config.v1` document. Each listed source has its own
start-to-start interval (5–300 s) and deadline (at most 30 s and at most its
interval); unlisted sources are not sampled. Every source runs on its own
goroutine without catch-up. A provider still blocked from its previous read is
not started again, so a hung provider holds one goroutine and records
`collection_error` / `provider_busy` instead of delaying other sources. Emitted
snapshots use each source's latest result; a missing or stale result is a null
(`not_yet_sampled`, `stale_result`), never a reused value. Missing reasons from
providers pass through unchanged.

The configuration declares a sampling budget: process CPU as percent of one
core over the run and peak RSS. The built-in default samples every source at the
15-second TEL04 candidate, the NVIDIA tool at 60 seconds, emits every 60 seconds
and declares 2 % of one core and 64 MiB. The run report compares measured cost
with that declaration; `endpoint-agent --sample` exits non-zero when it is
exceeded. Process CPU excludes child processes such as `nvidia-smi`. The
declaration is the configured ceiling for this measurement, not an approved
production budget.

Synthetic telemetry is no longer the agent's default. The loopback fixture
needs `--fixture` and prints `provenance=fixture`; with no mode the agent
exits with an error. Measurements are in [sampling-94.md](validation/sampling-94.md).

## Predeclared evaluation and resource thresholds, ML05 #86

On 17 November 2026, before any model was fitted, `models/evaluation/ml05-policy.json`
fixed the evaluation gates for the ML01 Backblaze 2013 study. It pins the
partition policy's canonical SHA-256 and the exact `partitions.json` bytes, and
it keeps the 168-hour horizon. Any change to those inputs or to a threshold
changes the policy digest and blocks earlier reports.

The model trains on `train` only. Validation has four positive events, which is
below the 30-event minimum, so only validation negative scores set the 0.5%
(`degraded`) and 0.1% (`critical`) false-positive operating points. Test is
scored once per candidate with no subsampling. Uncertainty comes from a
2,000-replicate device-clustered bootstrap with seed 86. Pass needs average
precision above both the prevalence and SMART-rule baselines at the lower
bound, ROC AUC lower bound ≥ 0.70, test window FPR upper bounds ≤ 1% and ≤ 0.2%,
≤ 10% of never-positive devices alerted, positive Brier skill, observed/expected
0.67–1.5, calibration slope 0.7–1.3, event recall ≥ 0.30 (lower bound ≥ 0.15)
and a median first-alert lead time ≥ 2 days. Fewer than 30 test events or any
other missing count, label class or metric gives `blocked`, never a relaxed
pass.

`degraded` is the interpretation of the source's "warning" health term. Model
health applies only after a pass. Otherwise the result is `unknown`. #35 still
owns combining this with fault history.

Endpoint inference on the selected HP Victus (Ryzen 5 5600H, 12 logical
processors, 15.34 GiB visible, build family 26200) is limited to a 16 MiB
artifact, a 64 MiB working set, p95 200 ms and max 1 s latency, a 2 s timeout,
250 ms CPU per prediction, one prediction per hour and at most 1 s delay to a
concurrent 60 s telemetry sweep. Endpoint training is limited to 256 MiB, one
logical processor, 600 s, once a day, on AC power. Central training is limited
to 30 minutes, 4 GiB and four cores on the hosted Ubuntu runner. A resource
report from a VM or another CPU is blocked. These are budgets, not
measurements of a model. #103, #33 and #104 must produce the reports. The
[ML05 record](../models/evaluation/README.md) and
[validation notes](validation/model-thresholds-86.md) list the commands and
limits.

## Scoped relay and production fallback settings, NET05 #88

On 17 November 2026 the pinned upstream DERP server became a deployable relay,
`apps/relay`, rather than a lab-only handler. Each organization runs one relay
host (#73). The operator chooses a DNS hostname, a certificate chain that must
cover it, a TCP port (443 by convention), a persisted relay key and an
admission file of admitted mesh network keys. STUN, the HTTP/ACME listener,
debug pages and mesh forwarding are off. Certificate issuance and renewal stay
outside the process; a renewed certificate needs a restart.

Relay admission is defense in depth. It sits beside controller admission and
does not replace it. Relay access never grants controller access, and device
signatures and chain keys are not involved. The pinned server supports
admission only through a URL, so the relay serves its allowlist on a loopback
listener with fail-open disabled and re-reads the file for every client. The
file is static until a controller export exists. Revocation is enforced first
by controller admission.

The mesh region file stays the only source of relay configuration.
`relay --print-region` writes a region that the adapter accepts. Production nodes
never use `InsecureForTests`. They may pin the dial IPv4 address and the
certificate (`CertName`, including `sha256-raw:`). Because Tailcat discovers the
controller through the relay, `mesh.CheckRelay` runs before a session starts.
The endpoint refuses to send evidence when that check fails. The controller logs
the failure and keeps its HTTPS boundary running. Neither falls back to public
relays, plaintext or weaker TLS. Evidence and remaining gaps are in
[relay-fallback-88.md](validation/relay-fallback-88.md).

## Windows service host, TEL02 #26

On 18 November 2026 the endpoint gained `--service`, hosted by the Windows
service control manager as `NT AUTHORITY\LocalService` with an unrestricted
per-service SID (`NT SERVICE\DeviceAuditEndpoint`). The installer restricts
the token to `SeChangeNotifyPrivilege`. The service itself refuses any other
account or privilege, an elevated token or a missing service SID, so a
misconfigured install fails with a reason instead of running wider. A
LocalService token alone is not accepted: SEC02 storage binds keys to the
service SID.

SEC02 keys are bound to the service SID and the LocalService DPAPI profile, so
they cannot be provisioned interactively and handed over. The service enrolls
under its own token on first start. The administrator places a one-use
`bootstrap.json` in a directory that only SYSTEM, Administrators and the
service SID can reach. The service deletes it once admission is confirmed, or at
once when it is invalid or expired. After a failed enrollment, such as an
unreachable controller, it stays for the SCM retry; the controller rejects a
consumed token and the token expires in ten minutes. A bootstrap file left beside
an admitted identity is deleted unused. The TLS settings are validated before the
credential is read.

The hosted pipeline is the TEL08 scheduler. Every snapshot with a known metric
is signed with the SEC07 sequence and appended to a synced, size-capped local
file. That file is local evidence, not a spool. On start, a torn final line is
truncated, leaving a sequence gap. At the cap the service stops with an error;
it does not rotate or drop evidence. Delivery and the bounded retrying spool
stay with #27/#95. A non-zero service exit code triggers the SCM recovery
actions (`failureflag 1`). The installer replaces each state DACL instead of adding grants. The service refuses evidence storage open to anyone but SYSTEM, Administrators and itself, because signed telemetry is private device data. Run 3 showed that a non-zero exit is restarted without a reboot. `tools/service` is a development install, not the
#57 package. Evidence is in
[windows-service-26.md](validation/windows-service-26.md).

## Frozen feature version, CT03 #32

On 18 November 2026 the [feature contract](../packages/contracts/features-v1.md)
froze `hdd-smart-7d.v1`, the only feature version. It takes three ML01 SMART
counters, `smart_5_raw`, `smart_9_raw` and `smart_197_raw`, in that order.
`smart_187_raw` and `smart_198_raw` are left out because every one of the
5,091,501 Backblaze 2013 rows has them null. Telemetry v2 metrics and error
events are left out because the selected study has no labels for them, so no
model could be fitted or judged against ML05 on them.

The window is the seven UTC days ending on the `as_of` day. Samples after
`as_of` or before the window are ignored. Each day's value is that counter's
latest non-null reading of the day; no other noise filter, clip or fitted
scaler exists. A counter needs a value on all seven days, otherwise both of its
features are null with `no_observation` or `incomplete_history` and the vector
is `incomplete`. Only a `complete` vector may reach a model. Each counter
yields `log1p(final)` and the signed `log1p` of `final − first`; decreases stay
negative.

Go and Python reference implementations agree within `1e-12` absolute plus
`1e-12` relative on 41 shared vectors, which `make contract-check` runs.
Readers reject any other feature version as `unsupported_feature_version`.

No endpoint collector reads SMART counters, so the endpoint and controller
produce `incomplete` vectors and `unknown` predictions under this version.
This is a planning gap: #102 and #105 can implement the pipeline, but a known
endpoint prediction needs a SMART collector, its Windows permission model and
a decision on NVMe drives, none of which has an issue. The
[validation notes](validation/features-32.md) record the checks.

## Real-device acceptance deferred for #31, #54 and #32 (23 November 2026)

The project owner descoped the items that need hardware or a second approver so
that #31, #54 and #32 can close. This is a scope decision, not a result.

- **Deferred, not met:** two Windows machines enrolling over direct and
  forced-DERP paths (#31); real target-machine LAN/WAN and forced-DERP timings
  (#54); other-owner approval of the shared feature vectors (#32). These need a
  second physical machine, a deployed relay and controller (#73), and a second
  reviewer. None exists.
- **What stands:** same-host Linux evidence in
  [integration-gate-31.md](validation/integration-gate-31.md),
  [recovery-54.md](validation/recovery-54.md) and
  [features-32.md](validation/features-32.md). It does not qualify Windows.
- **Consequence:** the first two target-window gates stay open. No production,
  patent, prediction or privacy claim follows. Anyone merging #101, #102 or #105
  must get the shared-vector approval first.

## Feature preprocessing pipelines, ML07 #102 (23 November 2026)

Training and endpoint preprocessing now build the CT03 input window from their
own data and call the frozen references. They add no rule and no fitted state.

- **Training:** `training_features.training_vectors` gives each ML01 example its
  vector. A Backblaze daily row is one sample at 00:00:00Z. ML01 requires seven
  daily rows but not non-null counters, so a kept example can still be
  `incomplete`; `model_input` refuses it. The policy history must equal the
  seven-day feature window or the stream stops.
- **Endpoint:** `health.Preprocess` keeps each counter's latest reading per UTC
  day before it builds the window. A 15 s sampler yields 40,320 readings a week
  against the contract's 10,080-sample cap, and the reduction is exactly the
  daily value rule, so the vector is unchanged. Readings after `as_of` are never
  read, at sub-second resolution. `endpoint-agent --features` runs it over
  `--sample` output.
- **Shared cases:** nine daily-row cases with hand-written expected vectors cover
  a sparse window, a null sensor, a null first day, a counter reset, a remapped
  SMART 197, rows after the anchor and rows before the window. Go and Python
  match them within `1e-12`.

The endpoint still reads no SMART counter, so every endpoint vector is
`incomplete` with `no_observation` and no known prediction follows. A SMART
collector, its Windows permission model and the NVMe mapping have no issue. The
Backblaze archive was not downloaded; the training stream ran on artificial
frames in its column layout. The [validation notes](validation/preprocessing-102.md)
record the checks. Another owner's review of the shared vectors is still required
before #105 merges.
## Model artifact manifest v1, CT10 #101 (23 November 2026)

[`device-audit.model-manifest.v1`](../packages/contracts/model-manifest-v1.md)
freezes what a model artifact declares and what an activating process checks
before it loads the artifact for inference or as a training base. One publisher
Ed25519 signature binds the artifact SHA-256, architecture, parameter count,
exact runtime name and version, the frozen feature version with its feature
order, and the inference/training purposes. The publisher key is configured on
the activating process; it is separate from device, network and chain keys.

Runtime match is exact, with no range or fallback. The feature list is checked
against the order the feature version freezes, not trusted from the manifest.
An unknown manifest version, an unsupported feature version, an unsupported
architecture, a runtime mismatch, a missing purpose and a digest mismatch each
refuse with their own code before anything is loaded. Go and Python read the
same 25 signed vectors. Python checks everything except the signature, because
`models` has no cryptography dependency.

The manifest contract leaves architecture an opaque ID. Its fixture artifact is
synthetic, and no active-manifest, rollback, expiry or revocation state exists.
The [validation notes](validation/model-manifest-101.md) record the checks.
Another owner's review of the vectors is still required before a consumer
merges. #33's logistic baseline is a separate unsigned artifact; it is not one
of these fixtures and it cannot activate through this manifest.

## Logistic baseline artifact, ML02 #33 (23 November 2026)

Central training fits one L2-regularized logistic regression on the frozen
`hdd-smart-7d.v1` features. The declared spec is
[`models/baseline/training-spec.json`](../models/baseline/training-spec.json):
15 Newton steps from a zero start, L2 of 1 on the standardized weights only,
balanced class weights, population standard deviation from the fit rows, and
no negative subsampling. The seed is 33. The optimizer draws no random numbers;
example order is the ML01 anchor-then-device order. These choices were written
down before the fit and were not revised after seeing coefficients. Validation
and test rows are refused. There is no split argument that can select them.

The learned parameters are the artifact. Provenance stores the dataset digest,
the three split digests, the seed, the feature version, the spec and the
artifact digest. A rerun must match the artifact bytes or stay inside absolute
tolerance `1e-8` and relative tolerance `1e-7`. The run uses the pinned
Backblaze 2013 archive, not a synthetic substitute and not Jev. It does not
sign a CT10 manifest, assign health, pass ML05, or write anything to a chain.
Endpoint qualification and a larger architecture stay open. Details and the
reproduction command are in the [baseline note](../models/baseline/README.md).
