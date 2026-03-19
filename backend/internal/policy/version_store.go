package policy

import "context"

// RuntimeVersionStore tracks the monotonically increasing ZTPV policy version
// per device identity. Each call to Next increments and returns the new version.
type RuntimeVersionStore interface {
	// Next increments the version counter for the given device and returns it.
	// The first call for a previously unseen device returns 1.
	Next(ctx context.Context, deviceID string) uint32
}
