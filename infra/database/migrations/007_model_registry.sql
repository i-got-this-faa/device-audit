-- FED07 #112: authenticated, versioned model artifacts. Artifacts and
-- approvals are immutable; only the two slot references change.
CREATE TABLE model_artifacts (
    deployment_id text NOT NULL REFERENCES controller_deployments(deployment_id),
    model_version text NOT NULL CHECK (model_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    artifact bytea NOT NULL CHECK (octet_length(artifact) BETWEEN 1 AND 16777216),
    source_reference text NOT NULL CHECK (source_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    uploaded_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, model_version),
    -- One artifact is one version, so a digest never names two models.
    UNIQUE (deployment_id, artifact_sha256),
    UNIQUE (deployment_id, model_version, artifact_sha256)
);

CREATE TABLE model_approvals (
    deployment_id text NOT NULL,
    model_version text NOT NULL,
    artifact_sha256 bytea NOT NULL,
    evaluation_sha256 bytea NOT NULL CHECK (octet_length(evaluation_sha256) = 32),
    policy_version text NOT NULL CHECK (policy_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    approved_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, model_version),
    UNIQUE (deployment_id, model_version, artifact_sha256),
    FOREIGN KEY (deployment_id, model_version, artifact_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256)
);

CREATE FUNCTION model_registry_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER model_artifacts_immutable BEFORE UPDATE OR DELETE ON model_artifacts
    FOR EACH ROW EXECUTE FUNCTION model_registry_immutable();
CREATE TRIGGER model_approvals_immutable BEFORE UPDATE OR DELETE ON model_approvals
    FOR EACH ROW EXECUTE FUNCTION model_registry_immutable();

CREATE TABLE model_references (
    deployment_id text NOT NULL REFERENCES controller_deployments(deployment_id),
    slot text NOT NULL CHECK (slot IN ('active', 'candidate')),
    model_version text NOT NULL,
    artifact_sha256 bytea NOT NULL,
    -- Non-null only for the active slot, so that slot alone must reference an
    -- approval. The database refuses an unapproved active model.
    approved_version text GENERATED ALWAYS AS (CASE WHEN slot = 'active' THEN model_version END) STORED,
    set_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, slot),
    FOREIGN KEY (deployment_id, model_version, artifact_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256),
    FOREIGN KEY (deployment_id, approved_version, artifact_sha256)
        REFERENCES model_approvals(deployment_id, model_version, artifact_sha256)
);
