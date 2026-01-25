package device

import (
	"bytes"
	"errors"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/policy"
)

var (
	ErrDeviceRevoked            = errors.New("device revoked")
	ErrNoActivePolicy           = errors.New("no active policy")
	ErrFirmwareNotWhitelisted   = errors.New("firmware not whitelisted")
	ErrFirmwareVersionRollback  = errors.New("firmware version rollback detected")
)

type Authorizer struct {
	deviceStore Store
	policyStore policy.Store
}

func NewAuthorizer(deviceStore Store, policyStore policy.Store) *Authorizer {
	return &Authorizer{
		deviceStore: deviceStore,
		policyStore: policyStore,
	}
}

// Authorize checks if the device with given firmware is authorized.
// Returns nil if authorized, error otherwise.
func (a *Authorizer) Authorize(deviceID string, firmwareHash []byte) error {
	// Step 1: Load device
	dev, err := a.deviceStore.Load(deviceID)
	if err != nil {
		return err
	}

	// Step 2: Revocation check
	if dev.Status == StatusRevoked {
		return ErrDeviceRevoked
	}

	// Step 3: Load active policy
	pol, err := a.policyStore.LoadActive(deviceID)
	if err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			return ErrNoActivePolicy
		}
		return err
	}

	// Step 4: Anti-rollback / monotonic version check
	if dev.FirmwareVersion < pol.MinFirmwareVersion {
		return ErrFirmwareVersionRollback
	}

	// Step 5: Firmware hash whitelist check
	if !isHashWhitelisted(firmwareHash, pol.AllowedHashes) {
		return ErrFirmwareNotWhitelisted
	}

	return nil
}

func isHashWhitelisted(hash []byte, whitelist [][]byte) bool {
	for _, allowed := range whitelist {
		if bytes.Equal(hash, allowed) {
			return true
		}
	}
	return false
}
