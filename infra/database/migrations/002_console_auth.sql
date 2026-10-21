-- Console identity, one-use login transactions and server-side sessions.
-- Session and login identifiers are stored as SHA-256 digests, never raw.
CREATE TABLE console_role_bindings (
    issuer text NOT NULL,
    subject text NOT NULL,
    role text NOT NULL CHECK (role IN ('viewer', 'admin')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (issuer, subject)
);

CREATE TABLE console_login_transactions (
    state_digest bytea PRIMARY KEY CHECK (octet_length(state_digest) = 32),
    nonce text NOT NULL,
    code_verifier text NOT NULL,
    return_to text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at)
);

CREATE TABLE console_sessions (
    id_digest bytea PRIMARY KEY CHECK (octet_length(id_digest) = 32),
    csrf_token text NOT NULL,
    issuer text NOT NULL,
    subject text NOT NULL,
    role text NOT NULL CHECK (role IN ('viewer', 'admin')),
    created_at timestamptz NOT NULL,
    authenticated_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (idle_expires_at <= absolute_expires_at)
);

CREATE INDEX console_sessions_absolute_expiry_idx ON console_sessions (absolute_expires_at);
CREATE INDEX console_sessions_subject_idx ON console_sessions (issuer, subject);
