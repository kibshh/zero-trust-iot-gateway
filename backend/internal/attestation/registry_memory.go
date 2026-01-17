package attestation

import (
	"errors"
	"sync"
)

var ErrDeviceNotFound = errors.New("device not found")
var ErrDeviceAlreadyExists = errors.New("device already exists")

type memoryRegistry struct {
	mu   sync.RWMutex
	keys map[string][]byte // DER-encoded SPKI public keys
}

func NewMemoryRegistry() *memoryRegistry {
	return &memoryRegistry{
		keys: make(map[string][]byte),
	}
}

func (r *memoryRegistry) Lookup(deviceID string) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key, ok := r.keys[deviceID]
	if !ok {
		return nil, ErrDeviceNotFound
	}
	return key, nil
}

func (r *memoryRegistry) Register(deviceID string, pubKeyDER []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.keys[deviceID]; exists {
		return ErrDeviceAlreadyExists
	}

	r.keys[deviceID] = pubKeyDER
	return nil
}