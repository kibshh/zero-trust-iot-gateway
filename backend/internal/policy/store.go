package policy

import "errors"

var (
	ErrPolicyNotFound = errors.New("policy not found")
)

type Store interface {
	// Load retrieves a policy by device ID (regardless of revoked/expired status)
	Load(deviceID string) (*Policy, error)
	// LoadActive retrieves a policy only if it's not revoked and not expired
	LoadActive(deviceID string) (*Policy, error)
	// Save stores or updates a policy
	Save(policy *Policy) error
}

