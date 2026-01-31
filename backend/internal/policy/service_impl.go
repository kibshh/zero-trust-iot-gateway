package policy

import (
	"context"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrDeviceIDInvalid = errors.New("invalid device ID")
	ErrDeviceNotFound  = errors.New("device not found")
	ErrDeviceRevoked   = errors.New("device is revoked")
	ErrPolicyRevoked   = errors.New("policy is revoked")
	ErrPolicyExpired   = errors.New("policy has expired")
)

// DeviceInfo contains the minimal device information needed for policy operations
type DeviceInfo struct {
	ID      string
	Revoked bool
}

// DeviceSource provides device information for policy operations
// Defined here to avoid import cycle with device package
type DeviceSource interface {
	GetDeviceInfo(ctx context.Context, deviceID string) (*DeviceInfo, error)
}

// PolicyService implements the Service interface
type PolicyService struct {
	builder *Builder
	signer  *Signer
	store   Store
	devices DeviceSource
}

// NewPolicyService creates a new PolicyService with all dependencies
func NewPolicyService(builder *Builder, signer *Signer, store Store, devices DeviceSource) *PolicyService {
	return &PolicyService{
		builder: builder,
		signer:  signer,
		store:   store,
		devices: devices,
	}
}

// Issue loads the active policy for a device, signs it, and returns the packed blob
func (s *PolicyService) Issue(ctx context.Context, deviceID string) ([]byte, error) {
	// Decode device ID from hex
	deviceIDBytes, err := hex.DecodeString(deviceID)
	if err != nil || len(deviceIDBytes) != DeviceIDSize {
		return nil, ErrDeviceIDInvalid
	}

	// Verify device exists and is not revoked
	devInfo, err := s.devices.GetDeviceInfo(ctx, deviceID)
	if err != nil {
		return nil, ErrDeviceNotFound
	}
	if devInfo.Revoked {
		return nil, ErrDeviceRevoked
	}

	// Load policy from store
	policy, err := s.store.Load(deviceID)
	if err != nil {
		return nil, err
	}

	// Check policy status explicitly
	if policy.Revoked {
		return nil, ErrPolicyRevoked
	}
	if time.Now().After(policy.ExpiresAt) {
		return nil, ErrPolicyExpired
	}

	// Build canonical payload
	payload, err := s.builder.Build(policy, deviceIDBytes)
	if err != nil {
		return nil, err
	}

	// Sign the payload
	signature, err := s.signer.Sign(payload)
	if err != nil {
		return nil, err
	}

	// Pack into wire format
	signedPolicy := &SignedPolicy{
		Payload:   payload,
		Signature: signature,
	}
	return signedPolicy.Pack(), nil
}

// Revoke marks the policy for a device as revoked
func (s *PolicyService) Revoke(ctx context.Context, deviceID string) error {
	// Load the policy first
	policy, err := s.store.Load(deviceID)
	if err != nil {
		return err
	}

	// Already revoked is not an error
	if policy.Revoked {
		return nil
	}

	// Mark as revoked
	policy.Revoked = true

	// Save back
	return s.store.Save(policy)
}

