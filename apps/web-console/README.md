# Console implementation

SRC04 [#74](https://github.com/i-got-this-faa/device-audit/issues/74) selects
Go `html/template`, embedded CSS and JavaScript ES modules, with progressive
enhancement. WEB01 [#29](https://github.com/i-got-this-faa/device-audit/issues/29) adds the
responsive console shell to SEC06 [#82](https://github.com/i-got-this-faa/device-audit/issues/82)
authentication. Templates and assets are embedded in the Go binary. Node is
required only for browser tests. Device browsing, evidence views, workflow
execution and exports remain separate tasks.

Implemented routes:

- `GET /auth/login` starts OIDC Authorization Code + PKCE S256 login for the
  configured issuer. The one-use state transaction expires after five minutes.
- `GET /auth/callback` consumes the transaction, verifies the ID token and MFA
  `amr` value, checks the local issuer/subject role binding and creates a
  server-side session.
- `GET /auth/session` returns the signed-in subject, current role and CSRF
  token. `POST /auth/logout` requires CSRF and Origin checks, revokes the
  session and clears the cookie.
- `GET /console` is the protected workspace. `GET /console/devices` and
  `GET /console/workflows` are protected navigation destinations with explicit
  unavailable states until those product features are implemented.
- `GET /console/access` lists role bindings for administrators. Viewers receive
  a public 403 page with no bindings or account details.
- `GET /console/assets/console.css|console.js` serves public embedded assets.
  These files contain no session or device data.
- `GET|POST /admin/role-bindings` lists bindings and changes a subject's
  `viewer`/`admin` role. Admin-only.
- `GET /signed-out` is the public post-logout page.
- With #18 enrollment configured, `POST /admin/bootstrap-tokens` issues a
  device-scoped ten-minute credential. It requires TLS, admin scope, CSRF,
  exact Origin and authentication within five minutes. See the
  [enrollment guide](../../infra/enrollment/README.md).

Sessions use the tables introduced in PostgreSQL schema version 2; the current
controller migrates to schema version 5. The session browser state
is the opaque `__Host-device-audit-session` cookie: `Secure`, `HttpOnly`,
`Path=/`, no `Domain`, `SameSite=Lax`; the short-lived login transaction uses a
second `__Host-` cookie. Idle expiry is 15 minutes and absolute expiry is
eight hours. The controller does not create accounts, infer roles from email or
group claims, or provide a public signup or password bypass. The operator
preprovisions the first admin with `--bootstrap-admin` or
`DEVICE_AUDIT_BOOTSTRAP_ADMIN`.

The loopback fixture API (`POST /v1/telemetry` and `GET /v1/devices/{id}`) is
separate. It has no administrator authentication and must not be exposed by the
public proxy as a console substitute.

## Configure authentication

All of these are required when auth is enabled, except the AMR and bootstrap
values:

```sh
DEVICE_AUDIT_DATABASE_URL='postgres://user@127.0.0.1:5432/device_audit?sslmode=disable' \
DEVICE_AUDIT_OIDC_ISSUER='https://id.example.test' \
DEVICE_AUDIT_OIDC_CLIENT_ID='device-audit-console' \
DEVICE_AUDIT_OIDC_CLIENT_SECRET='OPERATOR_SUPPLIED_SECRET' \
DEVICE_AUDIT_OIDC_REDIRECT_URL='https://audit.example.test/auth/callback' \
DEVICE_AUDIT_PUBLIC_ORIGIN='https://audit.example.test' \
DEVICE_AUDIT_BOOTSTRAP_ADMIN='subject-from-the-idp' \
go run ./apps/controller
```

`DEVICE_AUDIT_OIDC_REQUIRED_AMR` defaults to `mfa`; set it to an empty value
only when the issuer enforces MFA policy itself. The bootstrap flag creates a
missing binding only and never overwrites an existing role. Remove it after the
first administrator is provisioned. Prefer environment variables over the
matching flags because command-line arguments are visible in process listings.
The issuer and public origin must match the deployed HTTPS values; the
controller trusts no forwarded identity headers.

## Reproduce the local build

Use the exact Go toolchain declared by `go.mod`, currently 1.27.1. From a clean
checkout, install the pinned Python schema-test dependencies in an isolated
environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r models/test-requirements.txt
go version
go mod verify
make check cross-build
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/controller ./apps/controller
TEST_DATABASE_URL='postgres://user@127.0.0.1:5432/device_audit_test?sslmode=disable' make database-check
```

The auth HTTP tests use a temporary TLS OIDC issuer, not a real provider. The
database test creates isolated databases. These commands do not assert
bit-identical builds or a hosted CI result.

## Acceptance matrix status

The proxy must expose the intended console routes, embedded assets and auth
routes. Enrollment and the [inventory API](../../internal/controller/inventory.md)
need their own explicit exposure policy. Keep the unsigned fixture API private.
This table records local evidence; it does not qualify a production IdP.

| Request or state | Status |
| --- | --- |
| Anonymous `GET /console` or protected HTML | Implemented: redirect to `/auth/login` with allowlisted return path |
| Anonymous JSON, export or mutation | Implemented for current JSON/admin routes: 401 without protected data |
| `/auth/login` | Implemented with bounded one-use state/nonce/PKCE transaction |
| Valid callback with viewer/admin and MFA | Implemented against fake TLS issuer; real IdP not run |
| Missing, expired or reused state, mismatched nonce, invalid token signature, issuer, audience or expiry | Rejected by library/service paths; not every case has a separate browser test |
| Unknown identity, wrong issuer or missing local binding | Implemented: 403, no account creation |
| Forged email, group, organization, proxy identity or device header | Implemented: no header is read for roles; forged-header test passes |
| Viewer reads fleet/device/findings/exports | Device/workflow destinations implemented as unavailable states; fleet data, findings and exports remain absent |
| Viewer performs admin action | Implemented for role bindings: 403 with no mutation |
| Admin performs an allowlisted action | Role-binding management requires authentication within five minutes; durable audit events are not implemented |
| Missing/invalid CSRF, foreign Origin or mutation over GET | Implemented and tested |
| Exactly 15 minutes idle or eight hours since login | Implemented in memory-store HTTP tests; server, not cookie, controls it |
| Role removed or identity revoked | Implemented: next request denied; server-side session is not authority |
| Session/role store unavailable | Implemented: 503 with a public recovery page, no memory fallback |
| Valid CSRF-protected `POST /auth/logout` | Implemented: server session revoked, cookie expired |
| Replayed cookie after logout or expired session | Implemented in tests; server state rejects reuse |
| Browser Back or shared-cache replay after logout | Chromium test passes: protected responses send `no-store`; Back revalidates and shows no cached account data after logout |
| Device signing, mesh or chain credential as admin identity | Not an accepted admin path; no end-to-end test |
| IdP unavailable | New login fails closed; existing local sessions remain until expiry/revocation |

## Run the browser checks

The test-only dependency is pinned `playwright-core` 1.64.1, Apache-2.0, with no
transitive packages or installation scripts. It provides browser actions and
assertions without adding a frontend runtime or downloading a browser during
`npm ci`. The [Playwright launch reference](https://playwright.dev/docs/api/class-browsertype#browser-type-launch)
describes the explicit executable path used by these tests.

```sh
npm ci --prefix apps/web-console --ignore-scripts
BROWSER_PATH=/absolute/path/to/chromium make browser-check
```

The Go test starts the actual auth service and embedded console against a
synthetic TLS OIDC issuer and in-memory test sessions. Test control routes exist
only in `_test.go`, and no authentication bypass is compiled into the controller.
The browser ignores certificates only for this disposable loopback test. CI
installs Chromium selected by the pinned Playwright package and runs this target.
The local validation used system Chromium 155.0.8059.84 instead. Remote CI has not
been observed in this change.

The suite covers anonymous direct navigation, allowlisted return paths, the
OIDC/PKCE callback, viewer denial, admin navigation, logout with the browser's
actual Origin, expired sessions, browser Back after logout, auth-store outages,
keyboard focus, the skip link, 320-pixel navigation, horizontal overflow and
login/navigation/logout without JavaScript. Screenshots are written to
`artifacts/console/` and uploaded by CI. These are test screenshots, not real
fleet data or physical-device evidence.

With JavaScript enabled, the shell conceals content on page exit or when the tab
is hidden. A restored or newly visible tab reloads through session middleware.
A conservative per-page timer also conceals content at that page's session
expiry. Activity in another tab may extend the server session; reload to
revalidate. Without JavaScript, navigation and logout still work, and the server
checks every protected request. The additional concealment and local timer
require JavaScript. No service worker or browser storage contains protected data.

Rendered HTML uses `Referrer-Policy: strict-origin`: paths and queries are
omitted, while same-origin form POSTs retain the Origin needed by CSRF checks.
`no-referrer` caused real Chromium logout forms to send `Origin: null` and fail
closed. CSP permits only same-origin styles/scripts and form actions; inline
scripts, framing and base URL changes are denied.

For a manual synthetic preview, set `CONSOLE_PREVIEW_FILE` to a temporary file
and run the preview test:

```sh
CONSOLE_PREVIEW_FILE=/tmp/device-audit-preview-url \
  go test -count=1 -v -timeout=12m -run '^TestConsolePreview$' ./internal/controller/auth
```

The test writes its loopback HTTPS URL, stays alive
for ten minutes and then exits. The issuer automatically signs in the synthetic
viewer. Use a disposable browser profile that trusts the test certificate.

## Remaining qualification work

- Run the matrix against the selected real IdP, including issuer discovery,
  client authentication method and provider-specific `amr`/`acr` claims.
- Apply the fresh-authentication rule to future sensitive administrator actions.
- Add durable audit events, login rate limiting and expired session/login-row
  cleanup; qualify IdP single logout or back-channel revocation if required.
- Build the fleet/device/evidence pages and bounded exports with server-side
  resource and action authorization.
- Run current and previous stable desktop Chrome, Edge and Firefox checks,
  including keyboard operation, visible focus, 200% zoom and the tested viewport.
- Deploy behind the HTTPS proxy with operator-owned TLS, client secret and
  database credentials. No production browser or identity claim is established
  by this scaffold.
