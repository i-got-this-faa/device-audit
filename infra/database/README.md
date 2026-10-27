# PostgreSQL persistence and migrations

[Decision #73](../../docs/decisions.md#provisional-hosting-persistence-and-tenancy-73)
selects PostgreSQL provisionally for a single-organization deployment. Task #19
binds the controller to PostgreSQL and applies versioned migrations. Schema
version 5 adds #97 inventory revisions alongside #18 bootstrap admission,
#83 signed-device evidence and #82 console identity tables.
Repository writes are durable transactions; the unsigned fixture HTTP API still
uses its separate in-memory store. The [TLS bootstrap routes](../enrollment/README.md)
use this repository. Signed
telemetry ingestion remains separate work.

## Implemented binding

- `infra/database` uses `github.com/jackc/pgx/v5` through `database/sql`.
- Set `DEVICE_AUDIT_DATABASE_URL` or pass `--database-url`. The controller
  connects, pings, applies embedded forward-only migrations, and reports
  `database=connected` plus `schema_version` from `/healthz`.
- A connection, ping or migration failure aborts startup before the HTTP
  listener binds. There is no automatic fallback to memory when a database URL
  is configured.
- An empty database URL keeps the explicit development mode: samples remain in
  memory and health reports `database=not_configured`.
- `schema_migrations` records each applied version, name and time. Rerunning the
  controller applies no migration and preserves existing rows.
- `001_initial.sql` is the candidate device/telemetry schema. `002_console_auth.sql`
  adds `console_role_bindings`, `console_login_transactions` and
  `console_sessions`; raw session and login identifiers are stored only as
  SHA-256 digests.
- `003_device_repository.sql` adds `controller_deployments`,
  `enrollment_challenges`, `device_enrollments` and `device_evidence`. The old
  candidate tables remain unchanged and are never imported as trusted identities.
- `004_bootstrap_admission.sql` adds `bootstrap_tokens`,
  `enrollment_network_challenges` and `device_network_bindings`. Tokens and
  decrypted proofs retain only hashes. Public binding metadata and the admission
  fingerprint commit with signing enrollment and token/challenge consumption.
  Existing signing-only rows gain no network admission.
- `005_inventory_revisions.sql` appends complete inventory snapshots with
  enrollment digest, observation source, authenticated administrator provenance
  and optimistic revision checks. See [the inventory API](../../internal/controller/inventory.md).
- A PostgreSQL advisory lock serializes concurrent migration runs.
- Each migration runs in one transaction. A failed migration rolls back and
  leaves the previous ledger version in place.
- Migrations are forward-only. The runner never drops or recreates tables.

## Reproduce the migration checks

Start a disposable PostgreSQL 17 instance, then:

```sh
export TEST_DATABASE_URL='postgres://user@127.0.0.1:5432/device_audit_test?sslmode=disable'
make database-check
```

The integration tests create isolated databases and cover:

- fresh schema application and idempotent restart;
- upgrade from a prior schema while retaining existing rows;
- an injected failing migration that does not advance the ledger or leave a
  half-written table;
- concurrent migration attempts that apply each migration once;
- controller startup failure on an unavailable database and on a migration
  ledger conflict, with no listener left open;
- health output for a connected database, schema version 5 and the configured
  auth mode;
- the PostgreSQL auth store lifecycle, including role bindings, one-use login
  transactions, session touch/revocation and subject-session revocation;
- real version-2 upgrades retaining candidate samples and console bindings,
  without granting candidate rows enrollment trust;
- enrollment/challenge and evidence/sequence rollback, independent concurrent
  writers, exact signed-byte preservation, gaps/exhaustion, expiry after lock
  waits, cancellation, unavailable storage and writer-process kills before and
  after commit;
- #18 TLS admission, fresh-admin token issuance, duplicate/concurrent redemption,
  network proof rejection, lock-wait expiry/cancellation, admission-write
  rollback and deferred COMMIT failure;
- version-3 upgrades preserving signing identities without creating network admission.

CI runs the same target against a PostgreSQL 17 service.

For an abrupt database restart, put PostgreSQL server tools `initdb` and `pg_ctl`
on `PATH`, then run `make storage-crash-check` as a non-root user. This target
creates and removes its own disposable loopback cluster. It never restarts the
server from `TEST_DATABASE_URL`. It commits enrollment and evidence, stops
PostgreSQL with `pg_ctl -m immediate`, verifies an outage fails writes, then
checks identity, provenance, bootstrap token consumption, network binding,
challenge consumption and replay state after crash recovery. The test requires `fsync=on` and `full_page_writes=on`. This additional
target is opt-in and is not run by the existing CI database job.

[The #83 PR evidence comment](https://github.com/i-got-this-faa/device-audit/pull/186#issuecomment-6359146745) records
the local PostgreSQL 17.11 result and the remaining qualification gaps.

## Backup and recovery assumptions

These are provisional deployment requirements from decision #73. Backup and
restore automation and recovery qualification are not implemented by #19.

- Plan encrypted daily backups to storage outside the database host and a
  backup before migrations. Successful daily backups assume up to 24 hours of
  data loss after host loss. This is not a measured recovery guarantee.
  Retention, restore time and final recovery objectives remain open. A
  persistent volume alone is not a backup.
- The deployment operator owns backup access, encryption/recovery keys and
  restore procedures. Keep recovery keys recoverable independently of the lost
  host, with access restricted to authorized operators. Dedicate backups and
  credentials to the deployment's single organization.
- Before release, prove that committed records survive controller and database
  restarts, database outages reject writes, and an off-host backup restores onto
  a clean host. Check enrollment, revocation and replay state after restoring,
  before reopening ingestion. Stale security state must not silently re-admit
  devices or reports. Record actual data loss and restore time.

## Still open

- Wiring authenticated mesh device traffic to the repository (#24, #89),
  including signed acknowledgements and revocation
  authority/races (#90).
- Retention, authenticated receipt lookup and reconciliation after an uncertain
  commit. Replay is rejection, never proof that a particular payload was stored.
- Durable audit events, session/login-row cleanup and IdP revocation. Fresh
  authentication is enforced for role changes and bootstrap-token issuance;
  future sensitive administrator
  actions must apply the same policy.
- Selecting the production database version, TLS settings, least-privilege role,
  retention and backup schedule.
- Qualifying the deployed controller/database configuration and storage hardware,
  and proving an off-host backup restores onto a clean host. The isolated #83
  tests establish neither disaster recovery nor protection from stale backups.
- Reviewing every future migration for lock time, rollback behavior and
  compatibility with the prior release.

The versioned migrations remain schemas under review; applying them does not
qualify the schema or the authentication boundary for production. The deployment operator owns database
and backup secrets. Hosting, sizing and recovery objectives remain open under
#73.
