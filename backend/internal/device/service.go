package device

import "context"

// Service defines the interface for device management operations
type Service interface {
	// Register registers a new device with the backend
	// Returns the device ID and any error
	Register(ctx context.Context, req any) (any, error)

	// Get retrieves device information by device ID
	Get(ctx context.Context, deviceID string) (any, error)

	// Revoke revokes a device, marking it as permanently locked out
	Revoke(ctx context.Context, deviceID string) error
}

