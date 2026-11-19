-- One durable revocation audit record per signed enrollment. The admission
-- flag stays device_enrollments.revoked_at; the controller sets both in one
-- transaction under the device row lock. Revoked rows set by hand before this
-- migration have no record and are not backfilled with an invented actor.
CREATE TABLE device_revocation_events (
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    revoked_at timestamptz NOT NULL,
    reason_reference text NOT NULL CHECK (reason_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    enrollment_sha256 bytea NOT NULL CHECK (octet_length(enrollment_sha256) = 32),
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, device_id),
    FOREIGN KEY (deployment_id, device_id) REFERENCES device_enrollments(deployment_id, device_id)
);
