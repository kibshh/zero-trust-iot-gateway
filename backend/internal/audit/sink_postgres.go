package audit

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/db"
)

type postgresSink struct {
	pool *pgxpool.Pool
}

// NewPostgresSink creates an audit Sink backed by PostgreSQL.
func NewPostgresSink(pool *pgxpool.Pool) Sink {
	return &postgresSink{pool: pool}
}

// Ingest inserts all records in a single batched round-trip.
func (s *postgresSink) Ingest(ctx context.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}

	// Use a short absolute deadline so a slow DB never blocks the HTTP handler.
	ctx, cancel := context.WithTimeout(ctx, db.BatchTimeout)
	defer cancel()

	batch := &pgx.Batch{}
	for _, rec := range records {
		batch.Queue(
			`INSERT INTO audit_records
			    (device_id, action, decision, actor, origin, intent, state, source, received_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			rec.DeviceID,
			rec.Action,
			rec.Decision,
			rec.Actor,
			rec.Origin,
			rec.Intent,
			rec.State,
			rec.Source,
			rec.ReceivedAt,
		)
	}

	br := s.pool.SendBatch(ctx, batch)
	defer br.Close()

	for range records {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}
