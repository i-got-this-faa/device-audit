# Console implementation plan

SRC04 [#74](https://github.com/i-got-this-faa/device-audit/issues/74) selects
Go `html/template`, embedded CSS and JavaScript ES modules, with progressive
enhancement. The [identity decision](../../docs/decisions.md#console-and-administrator-identity-src04-74)
defines one-organization authorization, OIDC login, session expiry and roles.
There is no console executable, template bundle or authentication implementation
yet. The current loopback fixture API has no administrator authentication.

Planned pages cover fleet/device health, telemetry availability, diagnostic
findings, repair/upgrade/replacement reports, sustainability assumptions,
federated rounds/model versions and commitment receipts. Values and evidence
availability must remain inspectable without JavaScript. No frontend dependency,
Node runtime, CDN, transpiler or JavaScript package lock is needed by this choice.

## Reproduce the local build

Use the exact Go toolchain declared by `go.mod`, currently 1.27.1. From a clean
checkout of the desired commit, install the pinned Python schema-test
dependencies in an isolated environment:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r models/test-requirements.txt
go version
go mod verify
make check cross-build
CGO_ENABLED=0 go build -trimpath -buildvcs=false -o bin/controller ./apps/controller
```

These commands build and check the existing scaffold, not a dashboard. Once
implemented, controller-owned handlers import the console package in this
directory and embed its reviewed templates/static files at compile time; the
same controller build command must include them without a network asset fetch
or generated files. Pin any future module dependency with `go.mod` and `go.sum`.
Record the source commit, Go version and build environment with release evidence;
these commands alone do not assert bit-identical builds across platforms.

Target current and previous stable desktop Chrome, Edge and Firefox at release
qualification. Record exact browser/OS versions, keyboard/focus and 200% zoom
checks, and the tested viewport. There are no passing browser tests yet.

## Browser acceptance matrix for implementation

The routes below are proposed contracts, not existing endpoints. The public
proxy exposes only console/auth routes and separately authorized bootstrap,
never the development fixture API as a substitute for protected handlers.

| Request or state | Required result |
| --- | --- |
| Anonymous `GET /console` or protected HTML | Redirect to `/auth/login` without device data; return path must be an allowlisted local path |
| Anonymous JSON, export or mutation | 401 without evidence or login HTML; no side effect |
| `/auth/login` | Start bounded one-use state/nonce/PKCE transaction for the configured issuer |
| Valid `/auth/callback` with prebound viewer/admin and MFA | Consume login transaction, rotate session, redirect to local console |
| Missing, expired, reused or mismatched state/nonce; invalid PKCE or token signature, issuer, audience or expiry | Reject callback and issue no application session |
| Valid IdP identity without local binding, or wrong issuer/deployment | 403 without protected data or automatic account creation |
| Attacker-supplied email, group, organization header or forged proxy identity header | Cannot grant a role or change the deployment boundary |
| Viewer reads deployment device/fleet/provenance/receipt or bounded export | Authorized read; enforce resource scope and export limits server-side |
| Viewer creates/cancels diagnostics, authorizes enrollment, revokes devices, manages rounds/promotion or changes roles | 403 with no mutation |
| Admin performs one of those allowlisted actions | Check resource/action permission and CSRF, persist audit event with action, actor and outcome; sensitive actions also require fresh IdP authentication |
| Valid session with missing/invalid CSRF token, foreign Origin or mutation over GET | Reject without mutation; GET logout is not supported |
| Exactly 15 minutes idle or eight hours since login | Session invalid; HTML returns to login, JSON/mutations return 401 |
| Local role removed or identity revoked | Next request denied; existing cookie cannot retain authority |
| Session/role store unavailable | 503, no volatile fallback or protected response |
| Valid CSRF-protected `POST /auth/logout` | Invalidate server session, expire cookie, return to public signed-out page |
| Replayed cookie after logout, restart with revoked state, or expired session | Deny; server state controls acceptance |
| Browser Back or shared-cache replay after logout | Protected responses are no-store; revalidation cannot reveal data |
| Device signing key, mesh credential or chain signer supplied as admin identity | Deny, even with admitted network access |
| IdP unavailable | New login and required reauthentication fail closed; existing valid sessions remain bounded by local expiry and revocation |

OIDC provider registration, maintained library selection, secret provisioning,
MFA claim mapping, durable sessions/roles, proxy routing, browser checks and all
matrix cases remain implementation evidence to collect. No local password or
unauthenticated development bypass is selected for a deployed console.
