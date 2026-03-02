package device

import "errors"

var (
	ErrDeviceNotFound       = errors.New("device not found")
	ErrDeviceAlreadyRevoked = errors.New("device already revoked")
)

type Store interface {
	// Load retrieves a device by ID
	Load(deviceID string) (*Device, error)
	// Save stores or updates a device
	Save(device *Device) error
	// List returns all devices in the store
	List() ([]*Device, error)
}
