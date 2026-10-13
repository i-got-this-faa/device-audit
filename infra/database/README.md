# PostgreSQL schema candidate

PostgreSQL was proposed in the handoff. The SQL in `migrations/` is a starting
schema for review, not a validated production migration or an active runtime
dependency. The controller currently uses memory only. Select a database
version, driver, migration tool, tenancy/access model, retention and backup
policy before integrating this schema.
