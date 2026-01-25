package policy

import "errors"

var (
	ErrPolicyNotFound = errors.New("policy not found")
)

type Store interface {
	LoadActive(deviceID string) (*Policy, error)
	Save(policy *Policy) error
}

