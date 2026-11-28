-- AUD01 #119: bounded off-chain signed audit evidence. Each row is a snapshot of
-- the exact bytes of one device-signed telemetry envelope, one prediction, or one
-- device-signed diagnostic result, with its owner device and retention metadata.
-- Rows are immutable here. Retention enforcement and tombstones belong to #132,
-- which will replace the delete guard.
CREATE TABLE audit_evidence (
    deployment_id text NOT NULL,
    evidence_id text NOT NULL CHECK (evidence_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    kind text NOT NULL CHECK (kind IN ('telemetry', 'prediction', 'diagnostic')),
    schema_version text NOT NULL CHECK (length(schema_version) BETWEEN 1 AND 128),
    device_id text NOT NULL,
    source_ref text NOT NULL CHECK (length(source_ref) BETWEEN 1 AND 256),
    content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 10485760),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    stored_at timestamptz NOT NULL,
    retention_expires_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, evidence_id),
    -- One source is stored once, so an ID never names two copies of one record.
    UNIQUE (deployment_id, kind, source_ref),
    CHECK (sha256(content) = sha256),
    CHECK (retention_expires_at > stored_at),
    FOREIGN KEY (deployment_id, device_id)
        REFERENCES device_enrollments(deployment_id, device_id)
);

CREATE FUNCTION audit_evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'audit_evidence rows are immutable' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER audit_evidence_immutable BEFORE UPDATE OR DELETE ON audit_evidence
    FOR EACH ROW EXECUTE FUNCTION audit_evidence_immutable();
