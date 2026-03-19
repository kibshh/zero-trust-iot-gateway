package attestation

import "context"

// PublicKeyRegistry provides device public key lookup and registration.
// Keys are stored as DER-encoded SubjectPublicKeyInfo (SPKI) format.
type PublicKeyRegistry interface {
	// Lookup retrieves the DER-encoded public key for a given device ID.
	Lookup(ctx context.Context, deviceID string) ([]byte, error)
	// Register stores a new device public key and its device ID.
	Register(ctx context.Context, deviceID string, pubKeyDER []byte) error
}
