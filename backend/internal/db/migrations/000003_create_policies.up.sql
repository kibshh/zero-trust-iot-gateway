CREATE TABLE IF NOT EXISTS policies (
    device_id            TEXT        NOT NULL PRIMARY KEY REFERENCES devices(id),
    allowed_hashes       BYTEA[]     NOT NULL DEFAULT '{}', -- array of 32-byte SHA-256 firmware hashes
    min_firmware_version BIGINT      NOT NULL DEFAULT 0,
    issued_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at           TIMESTAMPTZ NOT NULL,
    revoked              BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS policies_device_id_active
    ON policies(device_id)
    WHERE revoked = FALSE;
