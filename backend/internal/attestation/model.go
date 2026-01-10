package attestation

import "time"

// Challenge represents a single attestation challenge, this is internal model.
type Challenge struct {
	DeviceID  string
	Nonce     []byte // 32 bytes, cryptographically secure random
	IssuedAt  time.Time
	ExpiresAt time.Time
}
