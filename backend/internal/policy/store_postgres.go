package policy

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/db"
)

type postgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a policy Store backed by PostgreSQL.
func NewPostgresStore(pool *pgxpool.Pool) Store {
	return &postgresStore{pool: pool}
}

func (s *postgresStore) Load(ctx context.Context, deviceID string) (*Policy, error) {
	ctx, cancel := context.WithTimeout(ctx, db.QueryTimeout)
	defer cancel()

	return s.scan(ctx, `
		SELECT device_id, allowed_hashes, min_firmware_version, issued_at, expires_at, revoked
		FROM policies WHERE device_id = $1`,
		deviceID,
	)
}

func (s *postgresStore) LoadActive(ctx context.Context, deviceID string) (*Policy, error) {
	ctx, cancel := context.WithTimeout(ctx, db.QueryTimeout)
	defer cancel()

	return s.scan(ctx, `
		SELECT device_id, allowed_hashes, min_firmware_version, issued_at, expires_at, revoked
		FROM policies
		WHERE device_id = $1 AND revoked = FALSE AND expires_at > NOW()`,
		deviceID,
	)
}

func (s *postgresStore) Save(ctx context.Context, pol *Policy) error {
	ctx, cancel := context.WithTimeout(ctx, db.QueryTimeout)
	defer cancel()

	_, err := s.pool.Exec(ctx, `
		INSERT INTO policies
		    (device_id, allowed_hashes, min_firmware_version, issued_at, expires_at, revoked)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (device_id) DO UPDATE SET
		    allowed_hashes       = EXCLUDED.allowed_hashes,
		    min_firmware_version = EXCLUDED.min_firmware_version,
		    issued_at            = EXCLUDED.issued_at,
		    expires_at           = EXCLUDED.expires_at,
		    revoked              = EXCLUDED.revoked`,
		pol.DeviceID, pol.AllowedHashes, pol.MinFirmwareVersion,
		pol.IssuedAt, pol.ExpiresAt, pol.Revoked,
	)
	return err
}

func (s *postgresStore) scan(ctx context.Context, query string, args ...any) (*Policy, error) {
	row := s.pool.QueryRow(ctx, query, args...)
	pol := &Policy{}
	err := row.Scan(
		&pol.DeviceID,
		&pol.AllowedHashes,
		&pol.MinFirmwareVersion,
		&pol.IssuedAt,
		&pol.ExpiresAt,
		&pol.Revoked,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrPolicyNotFound
		}
		return nil, err
	}
	return pol, nil
}
