package attestation

import "time"

// Constants for the attestation model
const (
	DeviceIDSize      = 16
	FirmwareHashSize  = 32
	MaxSignatureSize  = 72
)

// Challenge represents a single attestation challenge, this is internal model.
type Challenge struct {
	DeviceID  string
	Nonce     []byte // 32 bytes, cryptographically secure random
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type VerifyRequest struct {
	DeviceID     string
	FirmwareHash []byte
	SignatureDER []byte
}

type VerifyResult struct {
	Granted bool
}
