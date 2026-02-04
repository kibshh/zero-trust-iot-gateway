package attestation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
)

// memoryService is an in-memory attestation challenge store.
// It is NOT persistent and is intended only for initial backend bring-up.
type memoryService struct {
	mu                sync.Mutex
	challenges        map[string]Challenge
	registry          PublicKeyRegistry
	firmwareWhitelist map[[FirmwareHashSize]byte]struct{}
}

func NewMemoryService(registry PublicKeyRegistry) *memoryService {
	return &memoryService{
		challenges:        make(map[string]Challenge),
		registry:          registry,
		firmwareWhitelist: make(map[[FirmwareHashSize]byte]struct{}),
	}
}

// AddFirmwareHash adds a firmware hash to the whitelist
func (s *memoryService) AddFirmwareHash(hash []byte) error {
	if len(hash) != FirmwareHashSize {
		return errors.New("invalid firmware hash size")
	}

	var key [FirmwareHashSize]byte
	copy(key[:], hash)

	s.mu.Lock()
	s.firmwareWhitelist[key] = struct{}{}
	s.mu.Unlock()

	return nil
}

// RemoveFirmwareHash removes a firmware hash from the whitelist
func (s *memoryService) RemoveFirmwareHash(hash []byte) {
	if len(hash) != FirmwareHashSize {
		return
	}

	var key [FirmwareHashSize]byte
	copy(key[:], hash)

	s.mu.Lock()
	delete(s.firmwareWhitelist, key)
	s.mu.Unlock()
}

func (s *memoryService) CreateChallenge(ctx context.Context, deviceID string) (Challenge, error) {
	// deviceID is hex-encoded, so it should be 32 characters (16 bytes * 2)
	if len(deviceID) != DeviceIDSize*2 {
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

func (s *memoryService) Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error) {
	s.mu.Lock()
	ch, ok := s.challenges[req.DeviceID]
	if ok {
		delete(s.challenges, req.DeviceID) // one-time use
	}
	s.mu.Unlock()

	if !ok {
		return VerifyResult{Granted: false}, nil
	}

	if time.Now().After(ch.ExpiresAt) {
		return VerifyResult{Granted: false}, nil
	}

	pubKeyDER, err := s.registry.Lookup(req.DeviceID)
	if err != nil {
		return VerifyResult{Granted: false}, nil
	}

	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != DeviceIDSize {
		return VerifyResult{Granted: false}, nil
	}

	// Rebuild canonical buffer: nonce || device_id || firmware_hash
	buf := make([]byte, 0, NonceSize+DeviceIDSize+FirmwareHashSize)
	buf = append(buf, ch.Nonce...)
	buf = append(buf, rawID...)
	buf = append(buf, req.FirmwareHash...)

	if !VerifyECDSAP256(pubKeyDER, buf, req.SignatureDER) {
		return VerifyResult{Granted: false}, nil
	}

	if !s.isFirmwareAllowed(req.FirmwareHash) {
		return VerifyResult{Granted: false}, nil
	}

	return VerifyResult{Granted: true}, nil
}

// isFirmwareAllowed checks if firmware hash is in the whitelist
func (s *memoryService) isFirmwareAllowed(firmwareHash []byte) bool {
	if len(firmwareHash) != FirmwareHashSize {
		return false
	}

	var key [FirmwareHashSize]byte
	copy(key[:], firmwareHash)

	s.mu.Lock()
	_, allowed := s.firmwareWhitelist[key]
	s.mu.Unlock()

	return allowed
}

