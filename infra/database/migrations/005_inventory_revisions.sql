CREATE TABLE inventory_revisions (
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    schema_version text NOT NULL CHECK (schema_version = 'device-audit.inventory-record.v1'),
    observed_at timestamptz NOT NULL,
    recorded_at timestamptz NOT NULL CHECK (recorded_at >= observed_at),
    source_reference text NOT NULL CHECK (source_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    enrollment_sha256 bytea NOT NULL CHECK (octet_length(enrollment_sha256) = 32),
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    inventory jsonb NOT NULL CHECK (jsonb_typeof(inventory) = 'object'),
    PRIMARY KEY (deployment_id, device_id, revision),
    FOREIGN KEY (deployment_id, device_id) REFERENCES device_enrollments(deployment_id, device_id)
);
