package policy

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/db"
)

const (
	defaultStartVersion = 1
)

type postgresVersionStore struct {
	pool *pgxpool.Pool
}

// NewPostgresVersionStore creates a RuntimeVersionStore backed by PostgreSQL.
// It increments the policy_version column atomically and returns the new value.
// If no row exists yet for the device, it inserts one starting at version 1.
func NewPostgresVersionStore(pool *pgxpool.Pool) RuntimeVersionStore {
	return &postgresVersionStore{pool: pool}
}

func (s *postgresVersionStore) Next(ctx context.Context, deviceID string) uint32 {
	ctx, cancel := context.WithTimeout(ctx, db.QueryTimeout)
	defer cancel()

	// Atomically upsert the version counter in its own table.
	// The device row must already exist (FK enforces this), so this will
	// only ever insert on the very first policy issuance for a device.
	var version uint32
	err := s.pool.QueryRow(ctx, `
		INSERT INTO policy_versions (device_id, version)
		VALUES ($1, $2)
		ON CONFLICT (device_id) DO UPDATE
		    SET version = policy_versions.version + 1
		RETURNING version`,
		deviceID,
		defaultStartVersion,
	).Scan(&version)
	if err != nil {
		// Version counter is unavailable. Return 1 so issuance is not blocked,
		// but this should not happen in normal operation.
		return defaultStartVersion
	}
	return version
}
