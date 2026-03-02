package device

import "context"

// deviceService implements Service on top of a Store.
type deviceService struct {
	store Store
}

// NewService creates a new device service backed by the given store.
func NewService(store Store) Service {
	return &deviceService{store: store}
}

// Get returns the device with the given ID, or ErrDeviceNotFound.
func (s *deviceService) Get(_ context.Context, deviceID string) (*Device, error) {
	return s.store.Load(deviceID)
}

// Revoke marks the device as StatusRevoked.
// Returns ErrDeviceNotFound if the device does not exist.
// Returns ErrDeviceAlreadyRevoked if the device is already revoked.
func (s *deviceService) Revoke(_ context.Context, deviceID string) error {
	dev, err := s.store.Load(deviceID)
	if err != nil {
		return err
	}

	if dev.Status == StatusRevoked {
		return ErrDeviceAlreadyRevoked
	}

	dev.Status = StatusRevoked
	return s.store.Save(dev)
}

// List returns all registered devices.
func (s *deviceService) List(_ context.Context) ([]*Device, error) {
	return s.store.List()
}
