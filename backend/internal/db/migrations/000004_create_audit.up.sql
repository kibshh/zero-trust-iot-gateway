CREATE TABLE IF NOT EXISTS audit_records (
    id          BIGSERIAL   NOT NULL PRIMARY KEY,
    device_id   TEXT        NOT NULL REFERENCES devices(id),
    action      SMALLINT    NOT NULL,
    decision    SMALLINT    NOT NULL,
    actor       SMALLINT    NOT NULL,
    origin      SMALLINT    NOT NULL,
    intent      SMALLINT    NOT NULL,
    state       SMALLINT    NOT NULL,
    source      SMALLINT    NOT NULL,
    received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_records_device_id ON audit_records(device_id);
CREATE INDEX IF NOT EXISTS audit_records_received_at ON audit_records(received_at);
