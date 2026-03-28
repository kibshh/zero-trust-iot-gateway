package policy

import (
	"context"
	"sync"
)

type memoryVersionStore struct {
	mu       sync.RWMutex
	versions map[string]uint32
}

// NewMemoryVersionStore returns an in-memory RuntimeVersionStore.
func NewMemoryVersionStore() RuntimeVersionStore {
	return &memoryVersionStore{
		versions: make(map[string]uint32),
	}
}

func (s *memoryVersionStore) Next(_ context.Context, deviceID string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.versions[deviceID]++
	return s.versions[deviceID]
}
