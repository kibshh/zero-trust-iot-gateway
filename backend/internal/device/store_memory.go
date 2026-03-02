package device

import "sync"

type memoryStore struct {
	mu      sync.RWMutex
	devices map[string]*Device
}

func NewMemoryStore() Store {
	return &memoryStore{
		devices: make(map[string]*Device),
	}
}

func (s *memoryStore) Load(deviceID string) (*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dev, ok := s.devices[deviceID]
	if !ok {
		return nil, ErrDeviceNotFound
	}
	return dev, nil
}

func (s *memoryStore) Save(device *Device) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.devices[device.ID] = device
	return nil
}

func (s *memoryStore) List() ([]*Device, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*Device, 0, len(s.devices))
	for _, dev := range s.devices {
		result = append(result, dev)
	}
	return result, nil
}

