package device

import "errors"

var (
	ErrDeviceNotFound = errors.New("device not found")
)

type Store interface {
	Load(deviceID string) (*Device, error)
	Save(device *Device) error
}

