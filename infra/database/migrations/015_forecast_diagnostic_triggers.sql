-- FED06 #70: immutable links from an evaluated, fresh forecast to the bounded
-- diagnostic assignment it launched. A row names the forecast (device, assessment
-- time, category), the evaluated model behind it and the signed assignment. The
-- local insight is the assignment's terminal result, read through the
-- assignment, so no result bytes are copied here.

CREATE TABLE forecast_diagnostic_triggers (
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    as_of timestamptz NOT NULL,
    category text NOT NULL CHECK (category IN ('cpu', 'gpu', 'memory', 'storage', 'battery', 'thermal', 'network')),
    assignment_id text NOT NULL,
    probe_id text NOT NULL CHECK (probe_id IN ('storage_health.v1', 'system_errors.v1')),
    policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    probability double precision NOT NULL CHECK (probability >= 0 AND probability <= 1),
    horizon_hours integer NOT NULL CHECK (horizon_hours > 0),
    model_version text NOT NULL CHECK (length(model_version) BETWEEN 1 AND 255),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    evaluation_sha256 bytea NOT NULL CHECK (octet_length(evaluation_sha256) = 32),
    evidence_sequence bigint CHECK (evidence_sequence BETWEEN 1 AND 9007199254740991),
    created_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    -- One forecast launches at most one job per category.
    PRIMARY KEY (deployment_id, device_id, as_of, category),
    UNIQUE (deployment_id, assignment_id),
    FOREIGN KEY (deployment_id, assignment_id)
        REFERENCES diagnostic_assignments(deployment_id, assignment_id),
    FOREIGN KEY (deployment_id, device_id)
        REFERENCES device_enrollments(deployment_id, device_id)
);

CREATE INDEX forecast_diagnostic_triggers_device_idx
    ON forecast_diagnostic_triggers (deployment_id, device_id, as_of DESC, category);

CREATE FUNCTION forecast_diagnostic_triggers_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'forecast_diagnostic_triggers rows are immutable' USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER forecast_diagnostic_triggers_immutable BEFORE UPDATE OR DELETE ON forecast_diagnostic_triggers
    FOR EACH ROW EXECUTE FUNCTION forecast_diagnostic_triggers_immutable();
