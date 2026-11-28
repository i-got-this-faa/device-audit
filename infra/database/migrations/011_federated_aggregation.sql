-- FED03 #43: durable federated aggregation provenance and reproducible
-- candidate builds. Outcomes are append-only and never alter the active model.

CREATE TABLE federated_aggregations (
    deployment_id text NOT NULL,
    round_id text NOT NULL,
    candidate_id text NOT NULL CHECK (candidate_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    base_model_version text NOT NULL,
    base_model_sha256 bytea NOT NULL CHECK (octet_length(base_model_sha256) = 32),
    feature_version text NOT NULL CHECK (feature_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    parameter_count integer NOT NULL CHECK (parameter_count BETWEEN 1 AND 4096),
    weighting_policy text NOT NULL CHECK (weighting_policy = 'sample-count-weighted.v1'),
    status text NOT NULL CHECK (status IN ('succeeded', 'failed')),
    failure_reason text CHECK (failure_reason IS NULL OR failure_reason IN ('no_updates', 'insufficient_participants', 'aggregation_failed', 'cancelled')),
    participant_count integer NOT NULL CHECK (participant_count >= 0),
    total_samples bigint NOT NULL CHECK (total_samples >= 0),
    input_sha256 bytea NOT NULL CHECK (octet_length(input_sha256) = 32),
    participants jsonb NOT NULL CHECK (jsonb_typeof(participants) = 'array'),
    weights_bytes bytea CHECK (weights_bytes IS NULL OR octet_length(weights_bytes) = parameter_count * 8),
    weights_sha256 bytea CHECK (weights_sha256 IS NULL OR octet_length(weights_sha256) = 32),
    candidate_model_version text,
    candidate_model_sha256 bytea CHECK (candidate_model_sha256 IS NULL OR octet_length(candidate_model_sha256) = 32),
    created_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, round_id),
    UNIQUE (deployment_id, candidate_id),
    CHECK ((status = 'succeeded') = (failure_reason IS NULL)),
    CHECK (
        (status = 'succeeded' AND weights_bytes IS NOT NULL AND weights_sha256 IS NOT NULL AND sha256(weights_bytes) = weights_sha256 AND candidate_model_version IS NOT NULL AND candidate_model_sha256 IS NOT NULL) OR
        (status = 'failed' AND weights_bytes IS NULL AND weights_sha256 IS NULL AND candidate_model_version IS NULL AND candidate_model_sha256 IS NULL)
    ),
    FOREIGN KEY (deployment_id, round_id)
        REFERENCES federated_rounds(deployment_id, round_id),
    FOREIGN KEY (deployment_id, base_model_version, base_model_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256),
    FOREIGN KEY (deployment_id, candidate_model_version, candidate_model_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256)
);

CREATE TRIGGER federated_aggregations_immutable
    BEFORE UPDATE OR DELETE ON federated_aggregations
    FOR EACH ROW EXECUTE FUNCTION federated_records_immutable();

CREATE FUNCTION federated_aggregation_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    r federated_rounds%ROWTYPE;
    u_count integer;
    u_samples bigint;
    matched_count integer;
    distinct_count integer;
BEGIN
    SELECT * INTO r
    FROM federated_rounds
    WHERE deployment_id = NEW.deployment_id AND round_id = NEW.round_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'federated round not found for aggregation' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.candidate_id <> r.candidate_id
        OR NEW.base_model_version <> r.base_model_version
        OR NEW.base_model_sha256 <> r.base_model_sha256
        OR NEW.feature_version <> (r.record ->> 'feature_version')
        OR NEW.parameter_count <> (r.record ->> 'parameter_count')::integer THEN
        RAISE EXCEPTION 'federated aggregation metadata does not match round' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF r.status = 'open' THEN
        RAISE EXCEPTION 'federated aggregation requires a closed or cancelled round' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status = 'succeeded' THEN
        IF r.status <> 'closed'
            OR NEW.participant_count < (r.record ->> 'min_participants')::integer
            OR NEW.participant_count = 0
            OR jsonb_array_length(NEW.participants) <> NEW.participant_count THEN
            RAISE EXCEPTION 'succeeded aggregation requires a closed round meeting quorum' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT COUNT(*), COALESCE(SUM(sample_count), 0)
        INTO u_count, u_samples
        FROM federated_updates
        WHERE deployment_id = NEW.deployment_id AND round_id = NEW.round_id;
        IF u_count <> NEW.participant_count
            OR u_count < (r.record ->> 'min_participants')::integer
            OR u_samples <> NEW.total_samples THEN
            RAISE EXCEPTION 'succeeded aggregation participant count or samples do not match federated_updates' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
        SELECT COUNT(*)
        INTO matched_count
        FROM jsonb_array_elements(NEW.participants) AS elem
        JOIN federated_updates AS u
          ON u.deployment_id = NEW.deployment_id
         AND u.round_id = NEW.round_id
         AND u.device_id = elem ->> 'device_id'
         AND u.signing_key_id = elem ->> 'signing_key_id'
         AND jsonb_typeof(elem -> 'sequence') = 'number'
         AND (elem ->> 'sequence') ~ '^[0-9]+$'
         AND u.sequence = (elem ->> 'sequence')::bigint
         AND jsonb_typeof(elem -> 'sample_count') = 'number'
         AND (elem ->> 'sample_count') ~ '^[0-9]+$'
         AND u.sample_count = (elem ->> 'sample_count')::bigint
         AND (elem ->> 'update_sha256') ~ '^[0-9a-f]{64}$'
         AND u.update_sha256 = decode(elem ->> 'update_sha256', 'hex')
         AND (elem ->> 'request_sha256') ~ '^[0-9a-f]{64}$'
         AND u.request_sha256 = decode(elem ->> 'request_sha256', 'hex');
        SELECT COUNT(DISTINCT elem ->> 'device_id')
        INTO distinct_count
        FROM jsonb_array_elements(NEW.participants) AS elem;
        IF matched_count <> NEW.participant_count OR distinct_count <> NEW.participant_count THEN
            RAISE EXCEPTION 'succeeded aggregation participants do not match stored federated_updates' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    ELSIF NEW.failure_reason = 'cancelled' AND r.status <> 'cancelled' THEN
        RAISE EXCEPTION 'cancelled aggregation requires a cancelled round' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER federated_aggregations_insert_guard
    BEFORE INSERT ON federated_aggregations
    FOR EACH ROW EXECUTE FUNCTION federated_aggregation_insert_guard();
