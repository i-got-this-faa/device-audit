-- DIA05 #109: durable signed diagnostic assignments, leases, cancellations,
-- and append-only terminal results. First committed terminal transition wins.

CREATE TABLE diagnostic_controller_sequences (
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    last_sequence bigint NOT NULL CHECK (last_sequence BETWEEN 0 AND 9007199254740991),
    PRIMARY KEY (deployment_id, device_id),
    FOREIGN KEY (deployment_id, device_id)
        REFERENCES device_enrollments(deployment_id, device_id)
);

CREATE TABLE diagnostic_assignments (
    deployment_id text NOT NULL,
    assignment_id text NOT NULL CHECK (assignment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    device_id text NOT NULL,
    controller_key_id text NOT NULL CHECK (controller_key_id ~ '^ed25519:[a-f0-9]{64}$'),
    assignment_sequence bigint NOT NULL CHECK (assignment_sequence BETWEEN 1 AND 9007199254740991),
    assignment_sha256 bytea NOT NULL CHECK (octet_length(assignment_sha256) = 32),
    probe_id text NOT NULL CHECK (probe_id IN ('storage_health.v1', 'system_errors.v1')),
    arguments jsonb NOT NULL CHECK (jsonb_typeof(arguments) = 'object'),
    wall_seconds integer NOT NULL CHECK (wall_seconds BETWEEN 1 AND 300),
    max_output_bytes integer NOT NULL CHECK (max_output_bytes BETWEEN 1 AND 1048576),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    signed_assignment jsonb NOT NULL CHECK (jsonb_typeof(signed_assignment) = 'object'),
    status text NOT NULL CHECK (status IN ('pending', 'leased', 'cancel_requested', 'succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected')),
    delivery_count integer NOT NULL DEFAULT 0 CHECK (delivery_count >= 0),
    first_dispatched_at timestamptz,
    last_dispatched_at timestamptz,
    lease_expires_at timestamptz,
    cancel_requested_at timestamptz,
    cancel_actor_issuer text CHECK (length(cancel_actor_issuer) BETWEEN 1 AND 2048),
    cancel_actor_subject text CHECK (length(cancel_actor_subject) BETWEEN 1 AND 255),
    terminal_reason text CHECK (length(terminal_reason) BETWEEN 1 AND 128),
    terminal_at timestamptz,
    created_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, assignment_id),
    UNIQUE (deployment_id, device_id, assignment_sequence),
    CHECK (expires_at > issued_at AND expires_at <= issued_at + interval '24 hours'),
    CHECK (issued_at + make_interval(secs => wall_seconds) <= expires_at),
    CHECK ((cancel_actor_issuer IS NULL) = (cancel_actor_subject IS NULL)),
    CHECK ((cancel_requested_at IS NULL) = (cancel_actor_issuer IS NULL)),
    CHECK ((lease_expires_at IS NULL) OR (first_dispatched_at IS NOT NULL AND last_dispatched_at IS NOT NULL AND lease_expires_at <= expires_at)),
    CHECK (
        (status IN ('pending', 'leased', 'cancel_requested') AND terminal_at IS NULL AND terminal_reason IS NULL) OR
        (status IN ('succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected') AND terminal_at IS NOT NULL AND terminal_reason IS NOT NULL)
    ),
    FOREIGN KEY (deployment_id, device_id)
        REFERENCES device_enrollments(deployment_id, device_id)
);

CREATE INDEX diagnostic_assignments_device_idx
    ON diagnostic_assignments (deployment_id, device_id, issued_at, assignment_sequence);

CREATE TABLE diagnostic_results (
    deployment_id text NOT NULL,
    assignment_id text NOT NULL,
    device_id text NOT NULL,
    signing_key_id text NOT NULL CHECK (signing_key_id ~ '^ed25519:[a-f0-9]{64}$'),
    sequence bigint NOT NULL CHECK (sequence BETWEEN 2 AND 9007199254740991),
    assignment_sha256 bytea NOT NULL CHECK (octet_length(assignment_sha256) = 32),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    boot_id text NOT NULL CHECK (boot_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    started_at timestamptz,
    finished_at timestamptz NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    state text NOT NULL CHECK (state IN ('succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected')),
    reason text CHECK (length(reason) BETWEEN 1 AND 128),
    evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'array'),
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    accepted_at timestamptz NOT NULL,
    PRIMARY KEY (deployment_id, assignment_id),
    UNIQUE (deployment_id, device_id, sequence),
    FOREIGN KEY (deployment_id, assignment_id)
        REFERENCES diagnostic_assignments(deployment_id, assignment_id),
    FOREIGN KEY (deployment_id, device_id, signing_key_id)
        REFERENCES device_enrollments(deployment_id, device_id, signing_key_id)
);

CREATE TABLE diagnostic_assignment_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id text NOT NULL,
    assignment_id text NOT NULL,
    from_status text CHECK (from_status IN ('pending', 'leased', 'cancel_requested', 'succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected')),
    to_status text NOT NULL CHECK (to_status IN ('pending', 'leased', 'cancel_requested', 'succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected')),
    reason text NOT NULL CHECK (length(reason) BETWEEN 1 AND 128),
    at timestamptz NOT NULL,
    actor_issuer text CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text CHECK (length(actor_subject) BETWEEN 1 AND 255),
    CHECK ((actor_issuer IS NULL) = (actor_subject IS NULL)),
    FOREIGN KEY (deployment_id, assignment_id)
        REFERENCES diagnostic_assignments(deployment_id, assignment_id)
);

CREATE FUNCTION diagnostic_records_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER diagnostic_assignments_no_delete
    BEFORE DELETE ON diagnostic_assignments
    FOR EACH ROW EXECUTE FUNCTION diagnostic_records_immutable();
CREATE TRIGGER diagnostic_results_immutable
    BEFORE UPDATE OR DELETE ON diagnostic_results
    FOR EACH ROW EXECUTE FUNCTION diagnostic_records_immutable();
CREATE TRIGGER diagnostic_assignment_events_immutable
    BEFORE UPDATE OR DELETE ON diagnostic_assignment_events
    FOR EACH ROW EXECUTE FUNCTION diagnostic_records_immutable();

CREATE FUNCTION diagnostic_assignments_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    dev_revoked timestamptz;
BEGIN
    IF NEW.status <> 'pending' OR NEW.delivery_count <> 0 THEN
        RAISE EXCEPTION 'diagnostic assignment must start pending with zero deliveries' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT revoked_at INTO dev_revoked
    FROM device_enrollments
    WHERE deployment_id = NEW.deployment_id AND device_id = NEW.device_id;
    IF NOT FOUND OR dev_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'cannot create diagnostic assignment for revoked or unknown device' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER diagnostic_assignments_insert_guard
    BEFORE INSERT ON diagnostic_assignments
    FOR EACH ROW EXECUTE FUNCTION diagnostic_assignments_insert_guard();

CREATE FUNCTION diagnostic_assignments_transition_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    mutable_cols CONSTANT text[] := ARRAY[
        'status', 'delivery_count', 'first_dispatched_at', 'last_dispatched_at',
        'lease_expires_at', 'cancel_requested_at', 'cancel_actor_issuer',
        'cancel_actor_subject', 'terminal_reason', 'terminal_at'
    ];
    dev_revoked timestamptz;
BEGIN
    IF (to_jsonb(NEW) - mutable_cols) IS DISTINCT FROM (to_jsonb(OLD) - mutable_cols) THEN
        RAISE EXCEPTION 'diagnostic assignment identity and contract fields are immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status IN ('succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected') THEN
        RAISE EXCEPTION 'diagnostic assignment terminal state is final' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.cancel_requested_at IS NOT NULL AND (
        NEW.cancel_requested_at IS DISTINCT FROM OLD.cancel_requested_at OR
        NEW.cancel_actor_issuer IS DISTINCT FROM OLD.cancel_actor_issuer OR
        NEW.cancel_actor_subject IS DISTINCT FROM OLD.cancel_actor_subject
    ) THEN
        RAISE EXCEPTION 'diagnostic assignment cancellation request metadata is immutable' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'pending' AND NEW.status NOT IN ('leased', 'cancelled', 'expired') THEN
        RAISE EXCEPTION 'invalid pending diagnostic assignment transition' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'leased' AND NEW.status NOT IN ('cancel_requested', 'succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected') THEN
        RAISE EXCEPTION 'invalid leased diagnostic assignment transition' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF OLD.status = 'cancel_requested' AND NEW.status NOT IN ('succeeded', 'failed', 'cancelled', 'expired', 'rebooted', 'rejected') THEN
        RAISE EXCEPTION 'invalid cancel_requested diagnostic assignment transition' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.status = 'leased' THEN
        SELECT revoked_at INTO dev_revoked
        FROM device_enrollments
        WHERE deployment_id = NEW.deployment_id AND device_id = NEW.device_id;
        IF NOT FOUND OR dev_revoked IS NOT NULL THEN
            RAISE EXCEPTION 'cannot dispatch diagnostic assignment to revoked device' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER diagnostic_assignments_transition_guard
    BEFORE UPDATE ON diagnostic_assignments
    FOR EACH ROW EXECUTE FUNCTION diagnostic_assignments_transition_guard();

CREATE FUNCTION diagnostic_results_insert_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    a diagnostic_assignments%ROWTYPE;
    dev_revoked timestamptz;
BEGIN
    SELECT * INTO a
    FROM diagnostic_assignments
    WHERE deployment_id = NEW.deployment_id AND assignment_id = NEW.assignment_id;
    IF NOT FOUND OR a.device_id <> NEW.device_id OR a.assignment_sha256 <> NEW.assignment_sha256 THEN
        RAISE EXCEPTION 'diagnostic result does not match assignment' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF a.status NOT IN ('leased', 'cancel_requested') THEN
        RAISE EXCEPTION 'diagnostic result requires a non-terminal leased assignment' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    SELECT revoked_at INTO dev_revoked
    FROM device_enrollments
    WHERE deployment_id = NEW.deployment_id AND device_id = NEW.device_id AND signing_key_id = NEW.signing_key_id;
    IF NOT FOUND OR dev_revoked IS NOT NULL THEN
        RAISE EXCEPTION 'diagnostic result rejected for revoked or unknown device' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER diagnostic_results_insert_guard
    BEFORE INSERT ON diagnostic_results
    FOR EACH ROW EXECUTE FUNCTION diagnostic_results_insert_guard();
