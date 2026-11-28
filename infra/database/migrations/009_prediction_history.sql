-- ML11 #107: durable prediction and health history with model, feature,
-- horizon, telemetry-evidence and historical-baseline provenance.
-- Rows are append-only and immutable.

CREATE TABLE device_predictions (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    as_of timestamptz NOT NULL,
    expires_at timestamptz,
    recorded_at timestamptz NOT NULL,

    rules_version text NOT NULL CHECK (rules_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    rule_reason text NOT NULL CHECK (length(rule_reason) BETWEEN 1 AND 128),

    health_status text NOT NULL CHECK (health_status IN ('unknown', 'healthy', 'degraded', 'critical')),
    probability double precision CHECK (probability IS NULL OR (probability >= 0 AND probability <= 1 AND probability::text NOT IN ('NaN', 'Infinity', '-Infinity'))),
    probability_unit text NOT NULL CHECK (probability_unit = 'probability'),
    horizon_hours bigint CHECK (horizon_hours IS NULL OR (horizon_hours BETWEEN 1 AND 4294967295)),
    unknown_reason text CHECK (unknown_reason IS NULL OR unknown_reason IN ('insufficient_evidence', 'model_unavailable', 'stale_evidence')),

    model_status text NOT NULL CHECK (model_status IN ('ready', 'unavailable', 'unknown', 'healthy', 'degraded', 'critical')),
    model_error text NOT NULL DEFAULT '' CHECK (length(model_error) <= 128),
    model_version text,
    model_sha256 bytea CHECK (model_sha256 IS NULL OR octet_length(model_sha256) = 32),
    policy_version text CHECK (policy_version IS NULL OR policy_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    policy_sha256 bytea CHECK (policy_sha256 IS NULL OR octet_length(policy_sha256) = 32),
    evaluation_sha256 bytea CHECK (evaluation_sha256 IS NULL OR octet_length(evaluation_sha256) = 32),

    evidence_sequence bigint,
    evidence_collected_at timestamptz,
    evidence_received_at timestamptz,
    evidence_payload_sha256 bytea CHECK (evidence_payload_sha256 IS NULL OR octet_length(evidence_payload_sha256) = 32),
    evidence_request_sha256 bytea CHECK (evidence_request_sha256 IS NULL OR octet_length(evidence_request_sha256) = 32),
    evidence_source text CHECK (evidence_source IS NULL OR evidence_source IN ('fixture', 'endpoint')),
    evidence_telemetry_schema_version text CHECK (evidence_telemetry_schema_version IS NULL OR evidence_telemetry_schema_version = 'device-audit.telemetry.v2'),

    feature_version text NOT NULL CHECK (feature_version ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    feature_window_start text NOT NULL CHECK (feature_window_start ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),
    feature_window_end text NOT NULL CHECK (feature_window_end ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'),
    feature_status text NOT NULL CHECK (feature_status IN ('complete', 'incomplete')),
    feature_count integer NOT NULL CHECK (feature_count >= 0),
    feature_samples_read integer NOT NULL CHECK (feature_samples_read >= 0),
    feature_last_sequence bigint NOT NULL CHECK (feature_last_sequence >= 0),
    feature_vector jsonb NOT NULL CHECK (jsonb_typeof(feature_vector) = 'object'),

    fault_current_from timestamptz NOT NULL,
    fault_current_to timestamptz NOT NULL,
    fault_current_days integer NOT NULL CHECK (fault_current_days = 7),
    fault_current_sampled_days integer NOT NULL CHECK (fault_current_sampled_days BETWEEN 0 AND 7),
    fault_current_sufficient boolean NOT NULL,
    fault_baseline_from timestamptz NOT NULL,
    fault_baseline_to timestamptz NOT NULL,
    fault_baseline_days integer NOT NULL CHECK (fault_baseline_days = 21),
    fault_baseline_sampled_days integer NOT NULL CHECK (fault_baseline_sampled_days BETWEEN 0 AND 21),
    fault_baseline_sufficient boolean NOT NULL,
    fault_observation_note text NOT NULL CHECK (length(fault_observation_note) BETWEEN 1 AND 256),
    fault_summary jsonb NOT NULL CHECK (jsonb_typeof(fault_summary) = 'object'),
    fault_samples_read integer NOT NULL CHECK (fault_samples_read >= 0),
    fault_last_sequence bigint NOT NULL CHECK (fault_last_sequence >= 0),

    prediction jsonb CHECK (prediction IS NULL OR jsonb_typeof(prediction) = 'object'),

    CHECK (
        (health_status = 'unknown' AND probability IS NULL AND horizon_hours IS NULL AND unknown_reason IS NOT NULL) OR
        (health_status IN ('healthy', 'degraded', 'critical') AND probability IS NOT NULL AND horizon_hours IS NOT NULL AND unknown_reason IS NULL AND model_version IS NOT NULL AND evidence_sequence IS NOT NULL AND feature_status = 'complete')
    ),
    CHECK (unknown_reason IS DISTINCT FROM 'model_unavailable' OR (model_version IS NULL AND model_sha256 IS NULL AND policy_version IS NULL AND policy_sha256 IS NULL AND evaluation_sha256 IS NULL)),
    CHECK (
        (model_version IS NULL) = (model_sha256 IS NULL) AND
        (model_version IS NULL) = (policy_version IS NULL) AND
        (model_version IS NULL) = (policy_sha256 IS NULL) AND
        (model_version IS NULL) = (evaluation_sha256 IS NULL)
    ),
    CHECK (
        (
            evidence_sequence IS NULL AND evidence_collected_at IS NULL AND evidence_received_at IS NULL AND
            evidence_payload_sha256 IS NULL AND evidence_request_sha256 IS NULL AND evidence_source IS NULL AND
            evidence_telemetry_schema_version IS NULL AND expires_at IS NULL AND prediction IS NULL AND
            health_status = 'unknown' AND unknown_reason IN ('insufficient_evidence', 'model_unavailable')
        ) OR (
            evidence_sequence IS NOT NULL AND evidence_collected_at IS NOT NULL AND evidence_received_at IS NOT NULL AND
            evidence_payload_sha256 IS NOT NULL AND evidence_request_sha256 IS NOT NULL AND evidence_source IS NOT NULL AND
            evidence_telemetry_schema_version = 'device-audit.telemetry.v2' AND
            expires_at IS NOT NULL AND expires_at > as_of AND prediction IS NOT NULL
        )
    ),
    CHECK (health_status = 'unknown' OR evidence_collected_at <= as_of),
    CHECK (fault_baseline_from < fault_baseline_to AND fault_baseline_to = fault_current_from AND fault_current_from < fault_current_to),

    FOREIGN KEY (deployment_id, device_id)
        REFERENCES device_enrollments(deployment_id, device_id),
    FOREIGN KEY (deployment_id, device_id, evidence_sequence)
        REFERENCES device_evidence(deployment_id, device_id, sequence),
    FOREIGN KEY (deployment_id, model_version, model_sha256)
        REFERENCES model_approvals(deployment_id, model_version, artifact_sha256)
);

CREATE INDEX device_predictions_window_idx
    ON device_predictions (deployment_id, device_id, as_of, id);

CREATE FUNCTION device_predictions_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'device_predictions rows are immutable' USING ERRCODE = 'integrity_constraint_violation';
END
$$;

CREATE TRIGGER device_predictions_no_mutate BEFORE UPDATE OR DELETE ON device_predictions
    FOR EACH ROW EXECUTE FUNCTION device_predictions_immutable();

CREATE FUNCTION device_predictions_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    ev_payload bytea;
    ev_req bytea;
    ev_collected timestamptz;
    ev_received timestamptz;
    ap_eval bytea;
    ap_policy text;
BEGIN
    IF NEW.evidence_sequence IS NOT NULL THEN
        SELECT payload_bytes, request_sha256, collected_at, received_at
            INTO ev_payload, ev_req, ev_collected, ev_received
            FROM device_evidence
            WHERE deployment_id = NEW.deployment_id
              AND device_id = NEW.device_id
              AND sequence = NEW.evidence_sequence;
        IF NOT FOUND
            OR sha256(ev_payload) IS DISTINCT FROM NEW.evidence_payload_sha256
            OR ev_req IS DISTINCT FROM NEW.evidence_request_sha256
            OR ev_collected IS DISTINCT FROM NEW.evidence_collected_at
            OR ev_received IS DISTINCT FROM NEW.evidence_received_at THEN
            RAISE EXCEPTION 'prediction evidence reference does not match stored device_evidence' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    IF NEW.model_version IS NOT NULL THEN
        SELECT evaluation_sha256, policy_version
            INTO ap_eval, ap_policy
            FROM model_approvals
            WHERE deployment_id = NEW.deployment_id
              AND model_version = NEW.model_version
              AND artifact_sha256 = NEW.model_sha256;
        IF NOT FOUND
            OR ap_eval IS DISTINCT FROM NEW.evaluation_sha256
            OR ap_policy IS DISTINCT FROM NEW.policy_version THEN
            RAISE EXCEPTION 'prediction model reference does not match stored model_approvals' USING ERRCODE = 'integrity_constraint_violation';
        END IF;
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER device_predictions_insert_guard BEFORE INSERT ON device_predictions
    FOR EACH ROW EXECUTE FUNCTION device_predictions_evidence_guard();
