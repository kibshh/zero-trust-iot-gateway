package device

import "context"

// Service defines the interface for device management operations.
type Service interface {
	// Get returns the device with the given ID, or ErrDeviceNotFound.
	Get(ctx context.Context, deviceID string) (*Device, error)

	// Revoke marks the device as revoked.
	// Returns ErrDeviceNotFound if the device does not exist.
	// Returns ErrDeviceAlreadyRevoked if the device is already revoked.
	Revoke(ctx context.Context, deviceID string) error

	// List returns all registered devices.
	List(ctx context.Context) ([]*Device, error)
}
