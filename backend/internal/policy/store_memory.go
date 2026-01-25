package policy

import (
	"sync"
	"time"
)

type memoryStore struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

func NewMemoryStore() Store {
	return &memoryStore{
		policies: make(map[string]*Policy),
	}
}

func (s *memoryStore) LoadActive(deviceID string) (*Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pol, ok := s.policies[deviceID]
	if !ok {
		return nil, ErrPolicyNotFound
	}

	// Check if policy is still valid
	if pol.Revoked || time.Now().After(pol.ExpiresAt) {
		return nil, ErrPolicyNotFound
	}

	return pol, nil
}

func (s *memoryStore) Save(policy *Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.policies[policy.DeviceID] = policy
	return nil
}

