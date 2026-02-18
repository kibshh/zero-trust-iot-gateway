package policy

import "context"

// Service defines the interface for policy management operations
type Service interface {
	// Issue creates and signs an authorization policy (ZTPL format) for a device
	// Returns the packed signed policy blob
	Issue(ctx context.Context, deviceID string) ([]byte, error)

	// IssueRuntime creates and signs a runtime policy (ZTPV format) for a device
	// Returns the complete ZTPV blob with embedded signature
	IssueRuntime(ctx context.Context, deviceID string) ([]byte, error)

	// Revoke revokes the active policy for a device
	Revoke(ctx context.Context, deviceID string) error
}
