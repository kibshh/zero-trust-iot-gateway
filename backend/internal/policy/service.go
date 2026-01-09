package policy

import "context"

// Service defines the interface for policy management operations
type Service interface {
	// Issue creates and signs a policy for a device
	// Returns the signed policy blob
	Issue(ctx context.Context, deviceID string) ([]byte, error)

	// Revoke revokes the active policy for a device
	Revoke(ctx context.Context, deviceID string) error
}

