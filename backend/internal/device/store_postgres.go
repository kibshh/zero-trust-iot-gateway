package device

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type postgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a device Store backed by PostgreSQL.
func NewPostgresStore(pool *pgxpool.Pool) Store {
	return &postgresStore{pool: pool}
}

func (s *postgresStore) Load(deviceID string) (*Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	row := s.pool.QueryRow(ctx,
		`SELECT id, status, firmware_version, registered_at, last_seen_at
		 FROM devices WHERE id = $1`,
		deviceID,
	)

	dev := &Device{}
	var status int16
	err := row.Scan(&dev.ID, &status, &dev.FirmwareVersion, &dev.RegisteredAt, &dev.LastSeenAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDeviceNotFound
		}
		return nil, err
	}
	dev.Status = Status(status)
	return dev, nil
}

func (s *postgresStore) Save(dev *Device) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO devices (id, status, firmware_version, registered_at, last_seen_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (id) DO UPDATE SET
		     status           = EXCLUDED.status,
		     firmware_version = EXCLUDED.firmware_version,
		     last_seen_at     = EXCLUDED.last_seen_at`,
		dev.ID, int16(dev.Status), dev.FirmwareVersion, dev.RegisteredAt, dev.LastSeenAt,
	)
	return err
}

func (s *postgresStore) List() ([]*Device, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT id, status, firmware_version, registered_at, last_seen_at
		 FROM devices ORDER BY registered_at ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*Device
	for rows.Next() {
		dev := &Device{}
		var status int16
		if err := rows.Scan(&dev.ID, &status, &dev.FirmwareVersion, &dev.RegisteredAt, &dev.LastSeenAt); err != nil {
			return nil, err
		}
		dev.Status = Status(status)
		result = append(result, dev)
	}
	return result, rows.Err()
}
