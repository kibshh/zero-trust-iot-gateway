package attestation

import "context"

// Service defines the interface for attestation operations
type Service interface {
	// CreateChallenge creates a challenge (nonce) for device attestation
	// Returns the nonce to be sent to the device
	CreateChallenge(ctx context.Context, deviceID string) (any, error)

	// Verify verifies an attestation response from a device
	// Returns the authorization decision (granted/denied) and any error
	Verify(ctx context.Context, resp any) (bool, error)
}

