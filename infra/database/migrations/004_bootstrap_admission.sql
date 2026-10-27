CREATE TABLE bootstrap_tokens (
    deployment_id text NOT NULL REFERENCES controller_deployments(deployment_id),
    id text NOT NULL CHECK (id ~ '^[a-f0-9]{64}$'),
    device_id text NOT NULL CHECK (device_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    token_sha256 bytea NOT NULL CHECK (octet_length(token_sha256) = 32),
    issued_by_issuer text NOT NULL CHECK (issued_by_issuer <> ''),
    issued_by_subject text NOT NULL CHECK (issued_by_subject <> ''),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    PRIMARY KEY (deployment_id, id),
    UNIQUE (deployment_id, token_sha256),
    CHECK (expires_at > created_at AND expires_at <= created_at + interval '10 minutes'),
    CHECK (consumed_at IS NULL OR (consumed_at >= created_at AND consumed_at < expires_at))
);

CREATE TABLE enrollment_network_challenges (
    deployment_id text NOT NULL,
    challenge_id text NOT NULL,
    bootstrap_id text NOT NULL,
    network_public_key bytea NOT NULL CHECK (octet_length(network_public_key) = 32),
    proof_sha256 bytea NOT NULL CHECK (octet_length(proof_sha256) = 32),
    sealed_proof bytea NOT NULL CHECK (octet_length(sealed_proof) = 80),
    PRIMARY KEY (deployment_id, challenge_id),
    UNIQUE (deployment_id, bootstrap_id),
    FOREIGN KEY (deployment_id, challenge_id) REFERENCES enrollment_challenges(deployment_id, id),
    FOREIGN KEY (deployment_id, bootstrap_id) REFERENCES bootstrap_tokens(deployment_id, id)
);

CREATE TABLE device_network_bindings (
    deployment_id text NOT NULL,
    device_id text NOT NULL,
    network_public_key bytea NOT NULL CHECK (octet_length(network_public_key) = 32),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    PRIMARY KEY (deployment_id, device_id),
    UNIQUE (deployment_id, network_public_key),
    FOREIGN KEY (deployment_id, device_id) REFERENCES device_enrollments(deployment_id, device_id)
);
