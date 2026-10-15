# Provisional PostgreSQL persistence plan

[Decision #73](../../docs/decisions.md#provisional-hosting-persistence-and-tenancy-73)
selects PostgreSQL provisionally for a single-organization deployment. This is
reversible pending #14 and the missing patent PDF. The SQL in `migrations/`
remains a schema candidate, not a validated migration or runtime dependency.
The controller currently uses memory only and loses samples on restart.

## Planned storage and recovery boundary

- Run one PostgreSQL service beside the controller on the private host, with a
  persistent volume outside either service's disposable files. Permit database
  access only to the deployment's controller and authorized operators.
- Dedicate the database, credentials and backups to one organization. There is
  no shared tenant schema or tenant isolation implementation. A shared service
  requires a new access/schema decision before implementation.
- Persist controller records, enrollment, revocations and replay state before
  acknowledging durable writes. The candidate schema needs review for these
  requirements. Controller and database restarts must retain committed state;
  database failure must return an error without falling back to memory.
- Plan encrypted daily backups to storage outside the database host, plus a
  backup before migrations. Successful daily backups assume up to 24 hours of
  data loss after host loss. This provisional assumption is not a measured
  recovery guarantee. Retention, restore time and final recovery objectives
  remain open. A persistent volume alone is not a backup.
- The deployment operator owns backup access, encryption/recovery keys and
  restore procedures. Keep recovery keys recoverable independently of the lost
  host, with access restricted to authorized operators.

Before integration, select the database version, driver, migration tool and
record retention policy. Before release, prove committed data survives process
restarts, database outages reject writes, and an off-host backup restores onto
a clean host. Check enrollment, revocation and replay state after restore before
reopening ingestion; stale security state must not silently re-admit devices or
reports. Record actual data loss and restore time. None of this recovery or
access evidence exists in the scaffold.
