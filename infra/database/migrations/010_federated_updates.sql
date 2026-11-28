-- FED09 #114: validate and durably persist signed federated updates before
-- aggregation. Rows are append-only and immutable; sequence marks advance
-- atomically on device_enrollments.

CREATE TABLE federated_updates (
    deployment_id text NOT NULL,
    round_id text NOT NULL,
    device_id text NOT NULL,
    signing_key_id text NOT NULL CHECK (signing_key_id ~ '^ed25519:[a-f0-9]{64}$'),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 2 AND 9007199254740991),
    candidate_id text NOT NULL CHECK (candidate_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    base_model_version text NOT NULL,
    base_model_sha256 bytea NOT NULL CHECK (octet_length(base_model_sha256) = 32),
    feature_version text NOT NULL CHECK (feature_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    parameter_count integer NOT NULL CHECK (parameter_count BETWEEN 1 AND 4096),
    sample_count bigint NOT NULL CHECK (sample_count BETWEEN 1 AND 1000000000),
    weights_bytes bytea NOT NULL CHECK (octet_length(weights_bytes) BETWEEN 8 AND 32768 AND octet_length(weights_bytes) = parameter_count * 8),
    update_sha256 bytea NOT NULL CHECK (octet_length(update_sha256) = 32),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    accepted_at timestamptz NOT NULL,
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    PRIMARY KEY (deployment_id, round_id, device_id),
    UNIQUE (deployment_id, device_id, sequence),
    CHECK (sha256(weights_bytes) = update_sha256),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '24 hours'),
    CHECK (accepted_at >= issued_at AND accepted_at < expires_at),
    FOREIGN KEY (deployment_id, round_id)
        REFERENCES federated_rounds(deployment_id, round_id),
    FOREIGN KEY (deployment_id, round_id, device_id)
        REFERENCES federated_round_participants(deployment_id, round_id, device_id),
    FOREIGN KEY (deployment_id, device_id, signing_key_id)
        REFERENCES device_enrollments(deployment_id, device_id, signing_key_id),
    FOREIGN KEY (deployment_id, base_model_version, base_model_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256)
);

CREATE INDEX federated_updates_round_idx
    ON federated_updates (deployment_id, round_id, accepted_at, device_id);

CREATE TRIGGER federated_updates_immutable
    BEFORE UPDATE OR DELETE ON federated_updates
    FOR EACH ROW EXECUTE FUNCTION federated_records_immutable();

CREATE FUNCTION federated_update_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    r federated_rounds%ROWTYPE;
    p_key text;
    p_eligibility text;
    p_accepted timestamptz;
    dev_revoked timestamptz;
BEGIN
    SELECT * INTO r
    FROM federated_rounds
    WHERE deployment_id = NEW.deployment_id AND round_id = NEW.round_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'federated round not found for update' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF r.status <> 'open' THEN
        RAISE EXCEPTION 'federated updates require an open round' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.candidate_id <> r.candidate_id
        OR NEW.base_model_version <> r.base_model_version
        OR NEW.base_model_sha256 <> r.base_model_sha256
        OR NEW.feature_version <> (r.record ->> 'feature_version')
        OR NEW.parameter_count <> (r.record ->> 'parameter_count')::integer THEN
        RAISE EXCEPTION 'federated update metadata does not match round' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.issued_at < r.opened_at OR NEW.issued_at >= r.deadline
        OR NEW.expires_at > r.deadline
        OR NEW.accepted_at < r.opened_at OR NEW.accepted_at >= r.deadline THEN
        RAISE EXCEPTION 'federated update timestamps fall outside the round window' USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    SELECT signing_key_id, eligibility, accepted_at
    INTO p_key, p_eligibility, p_accepted
    FROM federated_round_participants
    WHERE deployment_id = NEW.deployment_id AND round_id = NEW.round_id AND device_id = NEW.device_id;
    IF NOT FOUND OR p_eligibility <> 'eligible' OR p_key <> NEW.signing_key_id OR p_accepted IS NULL THEN
        RAISE EXCEPTION 'federated update requires an eligible admitted participant' USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    SELECT revoked_at INTO dev_revoked
    FROM device_enrollments
    WHERE deployment_id = NEW.deployment_id AND device_id = NEW.device_id AND signing_key_id = NEW.signing_key_id;
    IF NOT FOUND OR dev_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'federated update requires an unrevoked device key' USING ERRCODE = 'integrity_constraint_violation';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER federated_updates_insert_guard
    BEFORE INSERT ON federated_updates
    FOR EACH ROW EXECUTE FUNCTION federated_update_insert_guard();
