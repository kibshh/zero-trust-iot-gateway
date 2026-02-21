package audit

import "context"

// Record represents a single policy audit event from a device
type Record struct {
	DeviceID string `json:"device_id"`
	Action   uint8  `json:"action"`
	Decision uint8  `json:"decision"`
	Actor    uint8  `json:"actor"`
	Origin   uint8  `json:"origin"`
	Intent   uint8  `json:"intent"`
	State    uint8  `json:"state"`
	Source   uint8  `json:"source"`
}

// Sink defines the interface for audit log ingestion (sink pattern)
// A sink only receives and stores data, it does not return query results
type Sink interface {
	// Ingest receives and stores audit records from a device
	Ingest(ctx context.Context, records []Record) error
}
