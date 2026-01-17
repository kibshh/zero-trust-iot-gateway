package attestation

// PublicKeyRegistry provides device public key lookup and registration.
// Keys are stored as DER-encoded SubjectPublicKeyInfo (SPKI) format.
type PublicKeyRegistry interface {
	// Lookup retrieves the DER-encoded public key for a given device ID.
	Lookup(deviceID string) ([]byte, error)
	// Register stores a new device public key and its device ID.
	Register(deviceID string, pubKeyDER []byte) error
}
