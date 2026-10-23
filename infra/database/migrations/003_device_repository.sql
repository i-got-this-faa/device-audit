-- These tables admit signed application identities only. Candidate devices and
-- samples from migration 001 remain untouched and confer no enrollment trust.
CREATE TABLE controller_deployments (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    deployment_id text NOT NULL UNIQUE
        CHECK (deployment_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')
);

CREATE TABLE enrollment_challenges (
    deployment_id text NOT NULL REFERENCES controller_deployments(deployment_id),
    id text NOT NULL CHECK (id ~ '^[a-f0-9]{64}$'),
    device_id text NOT NULL CHECK (device_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    signing_key_id text NOT NULL CHECK (signing_key_id ~ '^ed25519:[a-f0-9]{64}$'),
    authorization_reference text NOT NULL
        CHECK (authorization_reference ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (deployment_id, id),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at))
);

CREATE TABLE device_enrollments (
    deployment_id text NOT NULL,
    device_id text NOT NULL CHECK (device_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    signing_key_id text NOT NULL CHECK (signing_key_id ~ '^ed25519:[a-f0-9]{64}$'),
    public_key bytea NOT NULL CHECK (octet_length(public_key) = 32),
    challenge_id text NOT NULL,
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    enrolled_at timestamptz NOT NULL,
    last_sequence bigint NOT NULL CHECK (last_sequence BETWEEN 1 AND 9007199254740991),
    revoked_at timestamptz,
    PRIMARY KEY (deployment_id, device_id),
    UNIQUE (deployment_id, signing_key_id),
    UNIQUE (deployment_id, challenge_id),
    FOREIGN KEY (deployment_id, challenge_id) REFERENCES enrollment_challenges(deployment_id, id)
);

CREATE TABLE device_evidence (
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    sequence bigint NOT NULL CHECK (sequence BETWEEN 2 AND 9007199254740991),
    envelope jsonb NOT NULL CHECK (jsonb_typeof(envelope) = 'object'),
    payload_bytes bytea NOT NULL CHECK (octet_length(payload_bytes) BETWEEN 1 AND 262144),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    collected_at timestamptz NOT NULL,
    received_at timestamptz NOT NULL,
    PRIMARY KEY (deployment_id, device_id, sequence),
    FOREIGN KEY (deployment_id, device_id) REFERENCES device_enrollments(deployment_id, device_id)
);
