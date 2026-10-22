# Console implementation

SRC04 [#74](https://github.com/i-got-this-faa/device-audit/issues/74) selects
Go `html/template`, embedded CSS and JavaScript ES modules, with progressive
enhancement. The controller now hosts a minimal server-rendered console and
administrator authentication surface from SEC06 [#82](https://github.com/i-got-this-faa/device-audit/issues/82).
It is not a fleet dashboard or a browser-qualified release.

Implemented routes:

- `GET /auth/login` starts OIDC Authorization Code + PKCE S256 login for the
  configured issuer. The one-use state transaction expires after five minutes.
- `GET /auth/callback` consumes the transaction, verifies the ID token and MFA
  `amr` value, checks the local issuer/subject role binding and creates a
  server-side session.
- `GET /auth/session` returns the signed-in subject, current role and CSRF
  token. `POST /auth/logout` requires CSRF and Origin checks, revokes the
  session and clears the cookie.
- `GET /console` is the minimal viewer page.
- `GET|POST /admin/role-bindings` lists bindings and changes a subject's
  `viewer`/`admin` role. Admin-only.
- `GET /signed-out` is the public post-logout page.

Sessions are stored in PostgreSQL schema version 2. The session browser state
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

The proxy should expose only console/auth routes and separately authorized
bootstrap routes. This table records what the local implementation and tests
cover; it is not a passing browser or production IdP matrix.

| Request or state | Status |
| --- | --- |
| Anonymous `GET /console` or protected HTML | Implemented: redirect to `/auth/login` with allowlisted return path |
| Anonymous JSON, export or mutation | Implemented for current JSON/admin routes: 401 without protected data |
| `/auth/login` | Implemented with bounded one-use state/nonce/PKCE transaction |
| Valid callback with viewer/admin and MFA | Implemented against fake TLS issuer; real IdP not run |
| Missing, expired or reused state, mismatched nonce, invalid token signature, issuer, audience or expiry | Rejected by library/service paths; not every case has a separate browser test |
| Unknown identity, wrong issuer or missing local binding | Implemented: 403, no account creation |
| Forged email, group, organization, proxy identity or device header | Implemented: no header is read for roles; forged-header test passes |
| Viewer reads fleet/device/findings/exports | Not implemented; only the minimal console page exists |
| Viewer performs admin action | Implemented for role bindings: 403 with no mutation |
| Admin performs an allowlisted action | Role-binding management requires authentication within five minutes; durable audit events are not implemented |
| Missing/invalid CSRF, foreign Origin or mutation over GET | Implemented and tested |
| Exactly 15 minutes idle or eight hours since login | Implemented in memory-store HTTP tests; server, not cookie, controls it |
| Role removed or identity revoked | Implemented: next request denied; server-side session is not authority |
| Session/role store unavailable | Implemented: 503, no memory fallback |
| Valid CSRF-protected `POST /auth/logout` | Implemented: server session revoked, cookie expired |
| Replayed cookie after logout or expired session | Implemented in tests; server state rejects reuse |
| Browser Back or shared-cache replay after logout | Protected responses send `no-store`; no browser test yet |
| Device signing, mesh or chain credential as admin identity | Not an accepted admin path; no end-to-end test |
| IdP unavailable | New login fails closed; existing local sessions remain until expiry/revocation |

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
