-- FED01 #40: durable federated round state and participant eligibility.
-- A round is written once. Only its status can change, and only from open to
-- closed or cancelled. A participant row can only gain accepted_at, and only
-- inside its open round's window. Nothing is deleted.

-- Migration 001 declared candidate federated_rounds and model_updates tables
-- that no code reads or writes. The round schema below replaces them; FED03 #43
-- adds its own update table. Refuse to drop either if a hand-made row exists.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM model_updates) OR EXISTS (SELECT 1 FROM federated_rounds) THEN
        RAISE EXCEPTION 'candidate federated_rounds or model_updates rows exist; migrate them by hand before 008';
    END IF;
END
$$;
DROP TABLE model_updates;
DROP TABLE federated_rounds;

-- Lets a participant reference the exact device and key it was snapshotted with.
ALTER TABLE device_enrollments ADD UNIQUE (deployment_id, device_id, signing_key_id);

CREATE TABLE federated_rounds (
    deployment_id text NOT NULL REFERENCES controller_deployments(deployment_id),
    round_id text NOT NULL CHECK (round_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    -- One candidate reserves one aggregation attempt.
    candidate_id text NOT NULL CHECK (candidate_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    base_model_version text NOT NULL,
    base_model_sha256 bytea NOT NULL CHECK (octet_length(base_model_sha256) = 32),
    opened_at timestamptz NOT NULL,
    deadline timestamptz NOT NULL,
    -- The exact validated round, so a repeat is compared with what was stored.
    record jsonb NOT NULL CHECK (jsonb_typeof(record) = 'object'),
    status text NOT NULL CHECK (status IN ('open', 'closed', 'cancelled')),
    PRIMARY KEY (deployment_id, round_id),
    UNIQUE (deployment_id, candidate_id),
    CHECK (deadline > opened_at AND deadline <= opened_at + interval '7 days'),
    FOREIGN KEY (deployment_id, base_model_version, base_model_sha256)
        REFERENCES model_artifacts(deployment_id, model_version, artifact_sha256)
);

CREATE TABLE federated_round_participants (
    deployment_id text NOT NULL,
    round_id text NOT NULL,
    device_id text NOT NULL,
    signing_key_id text NOT NULL,
    eligibility text NOT NULL CHECK (eligibility IN ('eligible', 'ineligible')),
    reason text CHECK (reason IN ('revoked', 'incompatible_features', 'insufficient_local_data', 'not_authorized')),
    accepted_at timestamptz,
    PRIMARY KEY (deployment_id, round_id, device_id),
    CHECK ((eligibility = 'eligible') = (reason IS NULL)),
    -- Only an eligible participant can be admitted.
    CHECK (accepted_at IS NULL OR eligibility = 'eligible'),
    FOREIGN KEY (deployment_id, round_id) REFERENCES federated_rounds(deployment_id, round_id),
    FOREIGN KEY (deployment_id, device_id, signing_key_id)
        REFERENCES device_enrollments(deployment_id, device_id, signing_key_id)
);

CREATE TABLE federated_round_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id text NOT NULL,
    round_id text NOT NULL,
    from_status text CHECK (from_status IN ('open', 'closed', 'cancelled')),
    to_status text NOT NULL CHECK (to_status IN ('open', 'closed', 'cancelled')),
    reason text NOT NULL CHECK (reason IN ('opened', 'deadline', 'cancelled')),
    at timestamptz NOT NULL,
    -- Null only for the controller's own deadline transition.
    actor_issuer text CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text CHECK (length(actor_subject) BETWEEN 1 AND 255),
    CHECK ((actor_issuer IS NULL) = (actor_subject IS NULL)),
    CHECK ((reason = 'deadline') = (actor_issuer IS NULL)),
    CHECK ((from_status IS NULL) = (reason = 'opened')),
    FOREIGN KEY (deployment_id, round_id) REFERENCES federated_rounds(deployment_id, round_id)
);

CREATE FUNCTION federated_records_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER federated_rounds_no_delete BEFORE DELETE ON federated_rounds
    FOR EACH ROW EXECUTE FUNCTION federated_records_immutable();
CREATE TRIGGER federated_round_participants_no_delete BEFORE DELETE ON federated_round_participants
    FOR EACH ROW EXECUTE FUNCTION federated_records_immutable();
CREATE TRIGGER federated_round_events_immutable BEFORE UPDATE OR DELETE ON federated_round_events
    FOR EACH ROW EXECUTE FUNCTION federated_records_immutable();

CREATE FUNCTION federated_round_status_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF to_jsonb(NEW) - 'status' IS DISTINCT FROM to_jsonb(OLD) - 'status'
        OR OLD.status <> 'open' OR NEW.status NOT IN ('closed', 'cancelled') THEN
        RAISE EXCEPTION 'a round only moves from open to closed or cancelled' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER federated_rounds_status_guard BEFORE UPDATE ON federated_rounds
    FOR EACH ROW EXECUTE FUNCTION federated_round_status_guard();

CREATE FUNCTION federated_participant_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Compare the stored admission time, not now(): the controller reads its
    -- own clock, and an expired round can still be open until it is touched.
    IF to_jsonb(NEW) - 'accepted_at' IS DISTINCT FROM to_jsonb(OLD) - 'accepted_at'
        OR OLD.accepted_at IS NOT NULL OR NEW.accepted_at IS NULL
        OR NOT EXISTS (SELECT 1 FROM federated_rounds
            WHERE deployment_id = OLD.deployment_id AND round_id = OLD.round_id AND status = 'open'
                AND NEW.accepted_at >= opened_at AND NEW.accepted_at < deadline) THEN
        RAISE EXCEPTION 'a participant is admitted once, inside its open round window' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER federated_round_participants_guard BEFORE UPDATE ON federated_round_participants
    FOR EACH ROW EXECUTE FUNCTION federated_participant_guard();

-- The snapshot is inserted without an admission; only the guarded update admits.
CREATE FUNCTION federated_participant_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.accepted_at IS NOT NULL THEN
        RAISE EXCEPTION 'a participant is admitted by update, not insert' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER federated_round_participants_insert_guard BEFORE INSERT ON federated_round_participants
    FOR EACH ROW EXECUTE FUNCTION federated_participant_insert_guard();
