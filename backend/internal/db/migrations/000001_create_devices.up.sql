CREATE TABLE IF NOT EXISTS devices (
    id               TEXT        NOT NULL PRIMARY KEY,   -- hex-encoded 16-byte device ID
    status           SMALLINT    NOT NULL DEFAULT 0,     -- 0=active, 1=revoked, 2=suspended
    firmware_version BIGINT      NOT NULL DEFAULT 0,     -- monotonic anti-rollback counter
    registered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
