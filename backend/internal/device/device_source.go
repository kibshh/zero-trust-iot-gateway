package device

import (
	"context"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/policy"
)

// DeviceSourceAdapter adapts device.Store to policy.DeviceSource interface
type DeviceSourceAdapter struct {
	store Store
}

// NewDeviceSourceAdapter creates an adapter that implements policy.DeviceSource
func NewDeviceSourceAdapter(store Store) *DeviceSourceAdapter {
	return &DeviceSourceAdapter{store: store}
}

// GetDeviceInfo implements policy.DeviceSource
func (a *DeviceSourceAdapter) GetDeviceInfo(ctx context.Context, deviceID string) (*policy.DeviceInfo, error) {
	dev, err := a.store.Load(deviceID)
	if err != nil {
		return nil, err
	}

	return &policy.DeviceInfo{
		ID:      dev.ID,
		Revoked: dev.Status == StatusRevoked,
	}, nil
}

