package audit

import (
	"context"
	"time"
)

// CurrentSchemaVersion is the audit ingest payload version this backend accepts.
// Bump this when the Record wire format changes incompatibly.
const CurrentSchemaVersion = uint8(1)

// Record represents a single policy audit event from a device
type Record struct {
	DeviceID   string    `json:"device_id"`
	Action     uint8     `json:"action"`
	Decision   uint8     `json:"decision"`
	Actor      uint8     `json:"actor"`
	Origin     uint8     `json:"origin"`
	Intent     uint8     `json:"intent"`
	State      uint8     `json:"state"`
	Source     uint8     `json:"source"`
	ReceivedAt time.Time `json:"received_at"` // Set by the server on ingest; not supplied by the device
}

// Sink defines the interface for audit log ingestion (sink pattern)
// A sink only receives and stores data, it does not return query results
type Sink interface {
	// Ingest receives and stores audit records from a device
	Ingest(ctx context.Context, records []Record) error
}
