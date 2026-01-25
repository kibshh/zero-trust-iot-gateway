package device

import "time"

type Status uint8

const (
	StatusActive Status = iota
	StatusRevoked
	StatusSuspended
)

type Device struct {
	ID              string
	Status          Status
	FirmwareVersion uint64    // Monotonic version for anti-rollback
	RegisteredAt    time.Time
	LastSeenAt      time.Time
}

