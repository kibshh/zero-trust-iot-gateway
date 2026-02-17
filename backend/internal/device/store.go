package device

import "errors"

var (
	ErrDeviceNotFound = errors.New("device not found")
)

type Store interface {
	// Load retrieves a device by ID
	Load(deviceID string) (*Device, error)
	// Save stores or updates a device
	Save(device *Device) error
}

