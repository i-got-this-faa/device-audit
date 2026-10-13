-- Candidate schema only; the scaffold does not execute migrations.
BEGIN;
CREATE TABLE devices (
    id text PRIMARY KEY,
    enrolled_at timestamptz NOT NULL,
    identity_public_key bytea NOT NULL,
    mesh_public_key text NOT NULL UNIQUE,
    revoked_at timestamptz
);
CREATE TABLE telemetry_samples (
    device_id text NOT NULL REFERENCES devices(id),
    sequence bigint NOT NULL CHECK (sequence >= 0),
    collected_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    schema_version text NOT NULL,
    payload jsonb NOT NULL,
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    signature bytea NOT NULL,
    PRIMARY KEY (device_id, sequence)
);
CREATE TABLE federated_rounds (
    id text PRIMARY KEY,
    base_model_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending', 'training', 'aggregating', 'evaluating', 'promoted', 'failed')),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE model_updates (
    round_id text NOT NULL REFERENCES federated_rounds(id),
    device_id text NOT NULL REFERENCES devices(id),
    sample_count bigint NOT NULL CHECK (sample_count > 0),
    artifact_digest bytea NOT NULL CHECK (octet_length(artifact_digest) = 32),
    received_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (round_id, device_id)
);
CREATE TABLE audit_reports (
    id text PRIMARY KEY,
    device_id text NOT NULL REFERENCES devices(id),
    report jsonb NOT NULL,
    evidence_digest bytea NOT NULL CHECK (octet_length(evidence_digest) = 32),
    generated_at timestamptz NOT NULL DEFAULT now(),
    contract_receipt jsonb
);
COMMIT;
