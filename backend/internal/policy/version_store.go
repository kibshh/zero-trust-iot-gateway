package policy

import "sync"

// RuntimeVersionStore tracks the monotonically increasing ZTPV policy version
// per device identity. Each call to Next increments and returns the new version.
type RuntimeVersionStore interface {
	// Next increments the version counter for the given device and returns it.
	// The first call for a previously unseen device returns 1.
	Next(deviceID string) uint32
}

type memoryVersionStore struct {
	mu       sync.Mutex
	versions map[string]uint32
}

// NewMemoryVersionStore returns an in-memory RuntimeVersionStore.
func NewMemoryVersionStore() RuntimeVersionStore {
	return &memoryVersionStore{
		versions: make(map[string]uint32),
	}
}

func (s *memoryVersionStore) Next(deviceID string) uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.versions[deviceID]++
	return s.versions[deviceID]
}
