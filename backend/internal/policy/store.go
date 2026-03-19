package policy

import (
	"context"
	"errors"
)

var (
	ErrPolicyNotFound = errors.New("policy not found")
)

type Store interface {
	// Load retrieves a policy by device ID (regardless of revoked/expired status).
	Load(ctx context.Context, deviceID string) (*Policy, error)
	// LoadActive retrieves a policy only if it's not revoked and not expired.
	LoadActive(ctx context.Context, deviceID string) (*Policy, error)
	// Save stores or updates a policy.
	Save(ctx context.Context, policy *Policy) error
}

