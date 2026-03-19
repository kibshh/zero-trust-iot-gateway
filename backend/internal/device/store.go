package device

import (
	"context"
	"errors"
)

var (
	ErrDeviceNotFound       = errors.New("device not found")
	ErrDeviceAlreadyRevoked = errors.New("device already revoked")
)

type Store interface {
	// Load retrieves a device by ID.
	Load(ctx context.Context, deviceID string) (*Device, error)
	// Save stores or updates a device.
	Save(ctx context.Context, device *Device) error
	// List returns all devices in the store.
	List(ctx context.Context) ([]*Device, error)
}
