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
func (s *deviceService) Get(ctx context.Context, deviceID string) (*Device, error) {
	return s.store.Load(ctx, deviceID)
}

// Revoke marks the device as StatusRevoked.
// Returns ErrDeviceNotFound if the device does not exist.
// Returns ErrDeviceAlreadyRevoked if the device is already revoked.
func (s *deviceService) Revoke(ctx context.Context, deviceID string) error {
	dev, err := s.store.Load(ctx, deviceID)
	if err != nil {
		return err
	}

	if dev.Status == StatusRevoked {
		return ErrDeviceAlreadyRevoked
	}

	dev.Status = StatusRevoked
	return s.store.Save(ctx, dev)
}

// List returns all registered devices.
func (s *deviceService) List(ctx context.Context) ([]*Device, error) {
	return s.store.List(ctx)
}
