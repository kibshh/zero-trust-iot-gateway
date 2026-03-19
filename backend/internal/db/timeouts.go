package db

import "time"

const (
	// QueryTimeout is the deadline for single-row read/write operations.
	QueryTimeout = 5 * time.Second
	// BatchTimeout is the deadline for multi-row operations (list, batch insert).
	BatchTimeout = 10 * time.Second
)
