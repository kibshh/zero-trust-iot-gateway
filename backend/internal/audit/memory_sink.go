package audit

import (
	"context"
	"sync"
)

// MemorySink stores audit records in memory (development/testing use)
type MemorySink struct {
	mu      sync.Mutex
	records []Record
}

// NewMemorySink creates a new in-memory audit sink
func NewMemorySink() *MemorySink {
	return &MemorySink{}
}

// Ingest appends records to the in-memory store
func (s *MemorySink) Ingest(_ context.Context, records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, records...)
	return nil
}

// Records returns a copy of all stored audit records (for testing/inspection)
func (s *MemorySink) Records() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out
}

// Count returns the number of stored records
func (s *MemorySink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}
