-- AUD02 #45: canonical signed off-chain audit manifests. A manifest names the
-- stored evidence (AUD01) it covers and is signed by the controller audit key.
-- Rows are immutable, so a manifest ID names one manifest forever and a changed
-- reference, digest or version needs a new ID. The manifest holds the private
-- blinding nonce; only commitment_sha256 and commitment_id are public.

CREATE TABLE audit_manifests (
    deployment_id text NOT NULL,
    manifest_id text NOT NULL CHECK (manifest_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$'),
    commitment_id bytea NOT NULL CHECK (octet_length(commitment_id) = 32),
    commitment_sha256 bytea NOT NULL CHECK (octet_length(commitment_sha256) = 32),
    -- SHA-256 of the manifest signing bytes and signature (the commitment input).
    manifest_sha256 bytea NOT NULL CHECK (octet_length(manifest_sha256) = 32),
    -- SHA-256 of the canonical request, so an identical retry is recognised.
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    policy_version text NOT NULL CHECK (length(policy_version) BETWEEN 1 AND 128),
    controller_key_id text NOT NULL CHECK (controller_key_id ~ '^ed25519:[a-f0-9]{64}$'),
    manifest jsonb NOT NULL CHECK (jsonb_typeof(manifest) = 'object'),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    actor_issuer text NOT NULL CHECK (length(actor_issuer) BETWEEN 1 AND 2048),
    actor_subject text NOT NULL CHECK (length(actor_subject) BETWEEN 1 AND 255),
    PRIMARY KEY (deployment_id, manifest_id),
    UNIQUE (deployment_id, commitment_id),
    CHECK (expires_at > created_at)
);

CREATE TABLE audit_manifest_evidence (
    deployment_id text NOT NULL,
    manifest_id text NOT NULL,
    reference_id text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('telemetry', 'prediction', 'diagnostic')),
    device_id text NOT NULL,
    schema_version text NOT NULL CHECK (length(schema_version) BETWEEN 1 AND 128),
    sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 10485760),
    model_version text CHECK (length(model_version) BETWEEN 1 AND 255),
    model_sha256 bytea CHECK (octet_length(model_sha256) = 32),
    methodology_version text NOT NULL CHECK (length(methodology_version) BETWEEN 1 AND 128),
    PRIMARY KEY (deployment_id, manifest_id, reference_id),
    CHECK ((model_version IS NULL) = (model_sha256 IS NULL)),
    FOREIGN KEY (deployment_id, manifest_id)
        REFERENCES audit_manifests(deployment_id, manifest_id),
    -- A reference is a stored evidence record; its digest must be that record's.
    FOREIGN KEY (deployment_id, reference_id)
        REFERENCES audit_evidence(deployment_id, evidence_id)
);

CREATE FUNCTION audit_manifests_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% rows are immutable', TG_TABLE_NAME USING ERRCODE = 'integrity_constraint_violation';
END
$$;
CREATE TRIGGER audit_manifests_immutable BEFORE UPDATE OR DELETE ON audit_manifests
    FOR EACH ROW EXECUTE FUNCTION audit_manifests_immutable();
CREATE TRIGGER audit_manifest_evidence_immutable BEFORE UPDATE OR DELETE ON audit_manifest_evidence
    FOR EACH ROW EXECUTE FUNCTION audit_manifests_immutable();
