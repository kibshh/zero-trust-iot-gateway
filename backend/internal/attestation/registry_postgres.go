package attestation

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/db"
)

// pgUniqueViolation is the PostgreSQL error code for unique constraint violations.
const pgUniqueViolation = "23505"

type postgresRegistry struct {
	pool *pgxpool.Pool
}

// NewPostgresRegistry creates a PublicKeyRegistry backed by PostgreSQL.
func NewPostgresRegistry(pool *pgxpool.Pool) PublicKeyRegistry {
	return &postgresRegistry{pool: pool}
}

func (r *postgresRegistry) Lookup(deviceID string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), db.QueryTimeout)
	defer cancel()

	var pubKeyDER []byte
	err := r.pool.QueryRow(ctx,
		`SELECT public_key_der FROM attestation_keys WHERE device_id = $1`,
		deviceID,
	).Scan(&pubKeyDER)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	return pubKeyDER, nil
}

func (r *postgresRegistry) Register(deviceID string, pubKeyDER []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), db.QueryTimeout)
	defer cancel()

	_, err := r.pool.Exec(ctx,
		`INSERT INTO attestation_keys (device_id, public_key_der) VALUES ($1, $2)`,
		deviceID, pubKeyDER,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
			return ErrDeviceAlreadyExists
		}
		return err
	}
	return nil
}
