package attestation

import "context"

// Service defines the interface for attestation operations
type Service interface {
	// Register stores the device's public key (DER-encoded SPKI) for future attestation.
	// Returns ErrDeviceAlreadyExists if the device is already registered.
	Register(ctx context.Context, deviceID string, pubKeyDER []byte) error

	// CreateChallenge issues a nonce challenge for the given device.
	// Returns the challenge to be sent to the device.
	CreateChallenge(ctx context.Context, deviceID string) (Challenge, error)

	// Verify checks the attestation response from the device.
	Verify(ctx context.Context, req VerifyRequest) (VerifyResult, error)
}

