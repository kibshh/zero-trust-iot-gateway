package attestation

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"time"
)

var (
	ErrDeviceUnknown = errors.New("device unknown")
	ErrDeviceRevoked = errors.New("device revoked")
	ErrInvalidDeviceID = errors.New("invalid device id")
)

const (
	NonceSize = 32
	TTL = 30 * time.Second
	DeviceIDSize = 32
)

// memoryService is an in-memory attestation challenge store.
// It is NOT persistent and is intended only for initial backend bring-up.
type memoryService struct {
	mu         sync.Mutex
	challenges map[string]Challenge
}

func NewMemoryService() Service {
	return &memoryService{
		challenges: make(map[string]Challenge),
	}
}

func (s *memoryService) CreateChallenge(ctx context.Context, deviceID string) (Challenge, error) {
	if len(deviceID) != DeviceIDSize {
		return Challenge{}, ErrInvalidDeviceID
	}

	nonce := make([]byte, NonceSize)
	// Cryptographically secure random number generator.
	// Error occured if error is not nil.
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, err
	}

	now := time.Now()

	challenge := Challenge{
		DeviceID:  deviceID,
		Nonce:     nonce,
		IssuedAt:  now,
		ExpiresAt: now.Add(TTL),
	}

	s.mu.Lock()
	s.challenges[deviceID] = challenge
	s.mu.Unlock()

	// Successfully created challenge.
	return challenge, nil
}

