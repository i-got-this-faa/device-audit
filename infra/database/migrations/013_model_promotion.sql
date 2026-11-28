-- FED10 #115: held-out evaluation and promotion of candidate models. An
-- approval, and so an active model, needs a stored passing evaluation. The
-- evaluation and the decision for a candidate are written once.
CREATE TABLE model_evaluations (
    deployment_id text NOT NULL,
    model_version text NOT NULL,
    artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256) = 32),
    evaluation_sha256 bytea NOT NULL CHECK (octet_length(evaluation_sha256) = 32),
    report bytea NOT NULL CHECK (octet_length(report) BETWEEN 1 AND 1048576),
    policy_version text NOT NULL CHECK (policy_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    verdict text NOT NULL CHECK (verdict IN ('pass', 'fail', 'blocked')),
    reasons jsonb NOT NULL CHECK (jsonb_typeof(reasons) = 'array'),
    submitted_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    -- The held-out partition is scored once per candidate, so a version has at
    -- most one evaluation, whatever its verdict.
    PRIMARY KEY (deployment_id, model_version),
    UNIQUE (deployment_id, evaluation_sha256),
    UNIQUE (deployment_id, model_version, artifact_sha256, evaluation_sha256),
    FOREIGN KEY (deployment_id, model_version, artifact_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256),
    CHECK ((verdict = 'pass') = (jsonb_array_length(reasons) = 0))
);

CREATE TABLE model_promotions (
    deployment_id text NOT NULL,
    model_version text NOT NULL,
    artifact_sha256 bytea NOT NULL,
    evaluation_sha256 bytea NOT NULL,
    promotion_policy_version text NOT NULL CHECK (promotion_policy_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    outcome text NOT NULL CHECK (outcome IN ('promoted', 'rejected')),
    reasons jsonb NOT NULL CHECK (jsonb_typeof(reasons) = 'array'),
    baseline_version text,
    baseline_artifact_sha256 bytea,
    baseline_evaluation_sha256 bytea,
    checks jsonb NOT NULL CHECK (jsonb_typeof(checks) = 'array'),
    decided_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    -- Non-null only for a promotion, so only a promotion must reference an approval.
    promoted_version text GENERATED ALWAYS AS (CASE WHEN outcome = 'promoted' THEN model_version END) STORED,
    PRIMARY KEY (deployment_id, model_version),
    FOREIGN KEY (deployment_id, model_version, artifact_sha256, evaluation_sha256)
        REFERENCES model_evaluations(deployment_id, model_version, artifact_sha256, evaluation_sha256),
    FOREIGN KEY (deployment_id, promoted_version, artifact_sha256)
        REFERENCES model_approvals(deployment_id, model_version, artifact_sha256),
    CHECK ((outcome = 'promoted') = (jsonb_array_length(reasons) = 0)),
    CHECK ((baseline_version IS NULL) = (baseline_artifact_sha256 IS NULL)
        AND (baseline_version IS NULL) = (baseline_evaluation_sha256 IS NULL))
);

CREATE TRIGGER model_evaluations_immutable BEFORE UPDATE OR DELETE ON model_evaluations
    FOR EACH ROW EXECUTE FUNCTION model_registry_immutable();
CREATE TRIGGER model_promotions_immutable BEFORE UPDATE OR DELETE ON model_promotions
    FOR EACH ROW EXECUTE FUNCTION model_registry_immutable();

-- The active slot references an approval, so this makes an unevaluated or
-- failing model impossible to activate, even by direct SQL.
CREATE FUNCTION model_approval_requires_passing_evaluation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM model_evaluations
        WHERE deployment_id = NEW.deployment_id AND model_version = NEW.model_version
            AND artifact_sha256 = NEW.artifact_sha256 AND evaluation_sha256 = NEW.evaluation_sha256
            AND verdict = 'pass') THEN
        RAISE EXCEPTION 'approval needs a stored passing evaluation of this artifact'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER model_approvals_require_evaluation BEFORE INSERT ON model_approvals
    FOR EACH ROW EXECUTE FUNCTION model_approval_requires_passing_evaluation();

-- A promotion must cite the evaluation its approval cites.
CREATE FUNCTION model_promotion_matches_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.outcome = 'promoted' AND NOT EXISTS (SELECT 1 FROM model_approvals
        WHERE deployment_id = NEW.deployment_id AND model_version = NEW.model_version
            AND artifact_sha256 = NEW.artifact_sha256 AND evaluation_sha256 = NEW.evaluation_sha256) THEN
        RAISE EXCEPTION 'promotion must cite the evaluation of its approval'
            USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER model_promotions_match_approval BEFORE INSERT ON model_promotions
    FOR EACH ROW EXECUTE FUNCTION model_promotion_matches_approval();
