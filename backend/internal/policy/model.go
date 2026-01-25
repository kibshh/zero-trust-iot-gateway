package policy

import "time"

type Policy struct {
	DeviceID           string
	AllowedHashes      [][]byte // Whitelisted firmware hashes
	MinFirmwareVersion uint64   // Anti-rollback: minimum allowed version
	IssuedAt           time.Time
	ExpiresAt          time.Time
	Revoked            bool
}

