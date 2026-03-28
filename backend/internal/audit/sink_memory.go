package audit

import (
	"context"
	"sync"
)

// memorySink stores audit records in memory (development/testing use)
type memorySink struct {
	mu      sync.RWMutex
	records []Record
}

// NewMemorySink creates a new in-memory audit sink
func NewMemorySink() Sink {
	return &memorySink{}
}

// Ingest appends records to the in-memory store
func (s *memorySink) Ingest(_ context.Context, records []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, records...)
	return nil
}

// Records returns a copy of all stored audit records (for testing/inspection)
func (s *memorySink) Records() []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Record, len(s.records))
	copy(out, s.records)
	return out
}

// Count returns the number of stored records
func (s *memorySink) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.records)
}
