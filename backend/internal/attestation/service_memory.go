package attestation

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
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
	mu         sync.Mutex
	challenges map[string]Challenge
}

func NewMemoryService() Service {
	return &memoryService{
		challenges: make(map[string]Challenge),
	}
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

	// Lookup device public key (stub for now)
	pubKey, err := s.lookupPublicKey(req.DeviceID)
	if err != nil {
		return VerifyResult{Granted: false}, nil
	}

	// Rebuild canonical buffer: nonce || device_id || firmware_hash
	buf := make([]byte, 0, NonceSize+DeviceIDSize+FirmwareHashSize)
	buf = append(buf, ch.Nonce...)
	buf = append(buf, []byte(req.DeviceID)...)
	buf = append(buf, req.FirmwareHash...)

	if !s.verifyECDSAP256(pubKey, buf, req.SignatureDER) {
		return VerifyResult{Granted: false}, nil
	}

	if !s.isFirmwareAllowed(req.FirmwareHash) {
		return VerifyResult{Granted: false}, nil
	}

	return VerifyResult{Granted: true}, nil
}

// lookupPublicKey retrieves the device's public key (stub implementation)
func (s *memoryService) lookupPublicKey(deviceID string) (*ecdsa.PublicKey, error) {
	// TODO: Implement actual device lookup from device service
	// For now, return error to deny all requests
	return nil, ErrDeviceUnknown
}

// verifyECDSAP256 verifies an ECDSA P-256 signature
func (s *memoryService) verifyECDSAP256(pubKey *ecdsa.PublicKey, message []byte, signatureDER []byte) bool {
	// Hash the message
	hash := sha256.Sum256(message)

	// Verify signature (signatureDER is ASN.1 encoded as SEQUENCE { r INTEGER, s INTEGER })
	return ecdsa.VerifyASN1(pubKey, hash[:], signatureDER)
}

// isFirmwareAllowed checks if firmware hash is in the whitelist (stub implementation)
func (s *memoryService) isFirmwareAllowed(firmwareHash []byte) bool {
	// TODO: Implement actual firmware whitelist check
	// For now, deny all firmware
	return false
}

