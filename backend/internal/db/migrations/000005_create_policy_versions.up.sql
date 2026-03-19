-- Dedicated version counter table, separate from the policy payload.
-- This allows Next() to atomically increment a version without touching
-- or creating a policy row, which avoids ghost rows with invalid data.
CREATE TABLE IF NOT EXISTS policy_versions (
    device_id TEXT   NOT NULL PRIMARY KEY REFERENCES devices(id),
    version   BIGINT NOT NULL DEFAULT 1
);
