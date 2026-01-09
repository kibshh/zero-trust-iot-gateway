package audit

import "context"

// Sink defines the interface for audit log ingestion (sink pattern)
// A sink only receives and stores data, it does not return query results
type Sink interface {
	// Ingest receives and stores audit records from devices
	Ingest(ctx context.Context, record any) error
}

