# PostgreSQL persistence and migrations

[Decision #73](../../docs/decisions.md#provisional-hosting-persistence-and-tenancy-73)
selects PostgreSQL provisionally for a single-organization deployment. Task #19
now binds the controller to PostgreSQL and applies versioned migrations. This
does **not** make telemetry durable: samples still live in the controller's
in-memory development store until #83 and its dependent work.

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
- `schema_migrations` records the applied version, name and time. Rerunning the
  controller applies no migration and preserves existing rows.
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
- concurrent migration attempts that apply the schema once;
- controller startup failure on an unavailable database and on a migration
  ledger conflict, with no listener left open;
- health output for a connected database and schema version.

CI runs the same target against a PostgreSQL 17 service.

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

- Persisting devices, telemetry samples, enrollment, revocation and replay
  state transactionally (#83, #89, #90).
- Selecting the production database version, TLS settings, least-privilege role,
  retention and backup schedule.
- Proving committed data survives process and database restarts, that outages
  reject writes, and that an off-host backup restores onto a clean host.
- Reviewing every future migration for lock time, rollback behavior and
  compatibility with the prior release.

`migrations/001_initial.sql` remains a candidate schema under review; applying it
does not qualify the schema for production. The deployment operator owns
database and backup secrets. Hosting, sizing and recovery objectives remain open
under #73.
