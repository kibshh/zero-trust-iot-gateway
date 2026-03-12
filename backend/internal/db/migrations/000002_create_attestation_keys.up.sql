CREATE TABLE IF NOT EXISTS attestation_keys (
    device_id       TEXT        NOT NULL PRIMARY KEY REFERENCES devices(id),
    public_key_der  BYTEA       NOT NULL,              -- DER-encoded SPKI public key
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
