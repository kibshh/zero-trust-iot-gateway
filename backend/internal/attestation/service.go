package attestation

import "context"

// Service defines the interface for attestation operations
type Service interface {
	// Creates a challenge (nonce) for device attestation
	// Returns the nonce to be sent to the device and error if any.
	CreateChallenge(ctx context.Context, deviceID string) (Challenge, error)
}

