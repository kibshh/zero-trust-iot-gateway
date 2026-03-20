# PostgreSQL in Go with `pgx/v5`

A complete reference for using PostgreSQL in Go via `pgx/v5` and `pgxpool`, covering setup, queries, error handling, batch operations, and migrations.

---

## Table of Contents

1. [Why pgx over database/sql](#1-why-pgx-over-databasesql)
2. [Connection Pool Setup](#2-connection-pool-setup)
3. [The Three Query Methods](#3-the-three-query-methods)
4. [Scanning Results](#4-scanning-results)
5. [Error Handling](#5-error-handling)
6. [Upsert — INSERT ON CONFLICT](#6-upsert--insert-on-conflict)
7. [Batch Operations](#7-batch-operations)
8. [Context and Timeouts](#8-context-and-timeouts)
9. [Migrations with golang-migrate](#9-migrations-with-golang-migrate)
10. [Structuring a Postgres Store](#10-structuring-a-postgres-store)

---

## 1. Why pgx over database/sql

Go's standard library has `database/sql`, but `pgx` is the de-facto driver for PostgreSQL in production Go. Key differences:

| Feature                       | `database/sql` + lib/pq | `pgx/v5`             |
|-------------------------------|------------------------|----------------------|
| PostgreSQL-native types       | limited                | full support         |
| Binary protocol               | no                     | yes (faster)         |
| `BYTEA[]`, `TIMESTAMPTZ`, etc.| manual                 | native               |
| Batch queries                 | no                     | yes (`pgx.Batch`)    |
| Built-in pool                 | via `sql.DB`           | `pgxpool.Pool`       |
| Error inspection              | string parsing         | structured `PgError` |

---

## 2. Connection Pool Setup

Always use `pgxpool` in a server — it manages a pool of reusable connections so you don't open and close a TCP connection on every query.

```go
import "github.com/jackc/pgx/v5/pgxpool"

// pgxpool.New takes a context and a DSN (Data Source Name).
pool, err := pgxpool.New(ctx, "postgres://user:pass@localhost:5432/mydb")
if err != nil {
    log.Fatal(err)
}
defer pool.Close()
```

### DSN format

```
postgres://USER:PASSWORD@HOST:PORT/DBNAME?sslmode=disable
```

Common options:

```
sslmode=disable          local dev only — no encryption, never in production
sslmode=require          encrypted, but no certificate verification (vulnerable to MITM)
sslmode=verify-ca        encrypted + verifies certificate authority (trusted issuer)
sslmode=verify-full      encrypted + verifies CA and hostname (most secure, recommended)
pool_max_conns=10        max open connections (default 4)
pool_min_conns=2         keep alive at least N connections
connect_timeout=5        seconds to wait for initial connection
```

### Tuning pool size

The pool is shared across all goroutines. If you set `pool_max_conns` too low, goroutines queue waiting for a connection. If too high, PostgreSQL itself gets overwhelmed. A starting point:

```
max_conns = (number of CPU cores * 2) + active disk spindles
```

For small services, 10–20 is a sensible ceiling.

---

## 3. The Three Query Methods

`pgxpool.Pool` exposes three methods depending on what you expect back:

```
pool.Exec(ctx, sql, args...)         → executes, returns tag + error
                                       use for INSERT / UPDATE / DELETE with no RETURNING

pool.QueryRow(ctx, sql, args...)     → returns exactly one row
                                       use for SELECT … WHERE id = $1

pool.Query(ctx, sql, args...)        → returns a cursor over multiple rows
                                       use for SELECT returning 0..N rows
```

### Exec — write without reading back

```go
tag, err := pool.Exec(ctx,
    `UPDATE devices SET status = $1 WHERE id = $2`,
    StatusRevoked, deviceID,
)
// tag.RowsAffected() tells you how many rows matched
```

### QueryRow — single row lookup

```go
var name string
err := pool.QueryRow(ctx,
    `SELECT name FROM users WHERE id = $1`, id,
).Scan(&name)

if errors.Is(err, pgx.ErrNoRows) {
    return nil, ErrNotFound  // translate to domain error
}
```

### Query — multiple rows

```go
rows, err := pool.Query(ctx,
    `SELECT id, name FROM users ORDER BY name`,
)
if err != nil {
    return nil, err
}
defer rows.Close()  // always close, even if you break early

var users []User
for rows.Next() {
    var u User
    if err := rows.Scan(&u.ID, &u.Name); err != nil {
        return nil, err
    }
    users = append(users, u)
}

// Check for iteration errors — do not skip this
return users, rows.Err()
```

> Always check `rows.Err()` after the loop. Network errors mid-iteration end up there, not in the initial `Query` call.

---

## 4. Scanning Results

`Scan` maps database columns to Go variables **in the same order as they appear in the SELECT**.

```go
row := pool.QueryRow(ctx,
    `SELECT id, status, firmware_version, registered_at, last_seen_at
     FROM devices WHERE id = $1`,
    deviceID,
)

dev := &Device{}
var status int16  // DB stores SMALLINT, cast to domain type after scan
err := row.Scan(
    &dev.ID,
    &status,            // ← scan into plain int16 first
    &dev.FirmwareVersion,
    &dev.RegisteredAt,
    &dev.LastSeenAt,
)
dev.Status = Status(status)  // ← then convert to domain type
```

### Type mapping

| PostgreSQL type  | Go type            |
|------------------|--------------------|
| `TEXT`           | `string`           |
| `BIGINT`         | `int64`            |
| `SMALLINT`       | `int16`            |
| `BOOLEAN`        | `bool`             |
| `BYTEA`          | `[]byte`           |
| `BYTEA[]`        | `[][]byte`         |
| `TIMESTAMPTZ`    | `time.Time`        |
| `UUID`           | `[16]byte` or `pgtype.UUID` |

---

## 5. Error Handling

### "No rows" — the most common case

```go
err := pool.QueryRow(ctx, query, args...).Scan(&dest)
if errors.Is(err, pgx.ErrNoRows) {
    return nil, ErrNotFound  // translate to your domain error
}
if err != nil {
    return nil, err          // unexpected DB error
}
```

Never return `pgx.ErrNoRows` directly to callers outside the store layer — translate it to a domain-level sentinel error so the rest of the code stays decoupled from pgx.

### PostgreSQL error codes — structured inspection

When a query fails due to a constraint or conflict, PostgreSQL sends back a structured error with a 5-character SQLSTATE code. Use `pgconn.PgError` to inspect it:

```go
import (
    "github.com/jackc/pgx/v5/pgconn"
    "errors"
)

const pgUniqueViolation = "23505"  // unique_violation SQLSTATE

_, err := pool.Exec(ctx, `INSERT INTO keys (device_id, key) VALUES ($1, $2)`, id, key)
if err != nil {
    var pgErr *pgconn.PgError
    if errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation {
        return ErrAlreadyExists  // translate to domain error
    }
    return err
}
```

> Always use `errors.As` to inspect typed errors — never compare `err.Error()` strings.

### Common SQLSTATE codes

| Code    | Name                    | When it fires                          |
|---------|-------------------------|----------------------------------------|
| `23505` | `unique_violation`      | INSERT breaks a UNIQUE constraint      |
| `23503` | `foreign_key_violation` | INSERT references a non-existent FK    |
| `23502` | `not_null_violation`    | INSERT/UPDATE leaves a NOT NULL column empty |
| `40001` | `serialization_failure` | Optimistic lock conflict in SERIALIZABLE tx |

---

## 6. Upsert — INSERT ON CONFLICT

An upsert either inserts a new row or updates the existing one atomically. This avoids a separate SELECT + INSERT/UPDATE pair, which would require a transaction and still be prone to race conditions.

### Update on conflict

```go
_, err := pool.Exec(ctx, `
    INSERT INTO devices (id, status, firmware_version, registered_at, last_seen_at)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (id) DO UPDATE SET
        status           = EXCLUDED.status,
        firmware_version = EXCLUDED.firmware_version,
        last_seen_at     = EXCLUDED.last_seen_at`,
    dev.ID, int16(dev.Status), dev.FirmwareVersion, dev.RegisteredAt, dev.LastSeenAt,
)
```

`EXCLUDED` refers to the row that was attempted to be inserted — so `EXCLUDED.status` means "the value that was in the INSERT". Columns not listed in the `DO UPDATE SET` keep their old values.

### Atomic counter with RETURNING

Insert a counter row if it doesn't exist, or increment it if it does, and return the new value — all in one round-trip:

```go
var version uint32
err := pool.QueryRow(ctx, `
    INSERT INTO policy_versions (device_id, version)
    VALUES ($1, 1)
    ON CONFLICT (device_id) DO UPDATE
        SET version = policy_versions.version + 1
    RETURNING version`,
    deviceID,
).Scan(&version)
```

This is the correct way to implement a monotonic counter — no transactions needed, no race conditions.

---

## 7. Batch Operations

When you need to insert many rows, sending them one at a time means one network round-trip per row. `pgx.Batch` queues multiple statements and sends them all in a single round-trip.

```go
import "github.com/jackc/pgx/v5"

batch := &pgx.Batch{}

for _, rec := range records {
    batch.Queue(
        `INSERT INTO audit_records
             (device_id, action, decision, received_at)
         VALUES ($1, $2, $3, $4)`,
        rec.DeviceID, rec.Action, rec.Decision, rec.ReceivedAt,
    )
}

// Send all queued statements in one round-trip
br := pool.SendBatch(ctx, batch)
defer br.Close()  // must close to release the connection back to the pool

// Iterate results — one Exec() call per queued statement
for range records {
    if _, err := br.Exec(); err != nil {
        return err
    }
}
```

Key rules:
- Call `br.Close()` always — it releases the connection even if you return early on error.
- Call `br.Exec()` (or `br.Query`/`br.QueryRow`) once per queued statement, in order.
- If any statement fails, subsequent `br.Exec()` calls still return errors — drain them all or just close.

---

## 8. Context and Timeouts

Every pgx method takes a `context.Context`. This is the primary mechanism for two things:

1. **Timeout** — cancel the query if it takes too long.
2. **Propagation** — if the HTTP request is cancelled (client disconnects), the database query is also cancelled.

### The correct pattern

```go
// Inherit from the caller's context, then add a local ceiling.
// context.WithTimeout(ctx, ...) means:
//   deadline = min(caller's existing deadline, now + QueryTimeout)
// This composes correctly — if the request already has 2s left and
// QueryTimeout is 5s, the query gets 2s, not 5s.

func (s *store) Load(ctx context.Context, id string) (*Device, error) {
    ctx, cancel := context.WithTimeout(ctx, db.QueryTimeout)
    defer cancel()

    // ... pool.QueryRow(ctx, ...)
}
```

### Why NOT context.Background()

```go
// Wrong — creates an isolated timeout with no connection to the request
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
```

If you use `context.Background()`, the database query keeps running even after the HTTP client disconnected, wasting database resources.

### Define timeouts as named constants

```go
// db/timeouts.go
const (
    QueryTimeout = 5 * time.Second   // single row read/write
    BatchTimeout = 10 * time.Second  // multi-row operations
)
```

This makes it easy to find and change them, and prevents scattered magic numbers.

---

## 9. Migrations with golang-migrate

Schema migrations are SQL files that evolve the database schema in version-controlled, ordered steps. `golang-migrate` applies them in order and tracks which ones have already run.

### File naming convention

```
000001_create_devices.up.sql      ← applies the change
000001_create_devices.down.sql    ← reverses it
000002_create_attestation_keys.up.sql
000002_create_attestation_keys.down.sql
...
```

The number prefix determines the order. `up` migrates forward, `down` rolls back.

### Embedding migrations into the binary

Go's `//go:embed` directive bundles the SQL files into the compiled binary, so you don't need to ship them separately:

```go
package db

import (
    "embed"
    "fmt"

    "github.com/golang-migrate/migrate/v4"
    _ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
    "github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func Migrate(dsn string) error {
    src, err := iofs.New(migrationsFS, "migrations")
    if err != nil {
        return fmt.Errorf("loading migration sources: %w", err)
    }

    m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
    if err != nil {
        return fmt.Errorf("creating migrator: %w", err)
    }
    defer m.Close()

    // Up() applies all pending migrations.
    // ErrNoChange means all migrations are already applied — not an error.
    if err := m.Up(); err != nil && err != migrate.ErrNoChange {
        return fmt.Errorf("running migrations: %w", err)
    }
    return nil
}
```

### Calling it at startup

```go
// main.go — run migrations before accepting traffic
if err := db.Migrate(cfg.DatabaseDSN); err != nil {
    return fmt.Errorf("running migrations: %w", err)
}
log.Println("Database migrations applied")
```

Migrations are idempotent — `golang-migrate` tracks applied migrations in a `schema_migrations` table it manages automatically. Running `Migrate` twice is safe.

### Example migration file

```sql
-- 000001_create_devices.up.sql
CREATE TABLE IF NOT EXISTS devices (
    id               TEXT        NOT NULL PRIMARY KEY,
    status           SMALLINT    NOT NULL DEFAULT 0,
    firmware_version BIGINT      NOT NULL DEFAULT 0,
    registered_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

```sql
-- 000001_create_devices.down.sql
DROP TABLE IF EXISTS devices;
```

---

## 10. Structuring a Postgres Store

The idiomatic pattern in this project: define an interface, keep the postgres implementation in a separate file, inject the pool via the constructor.

```
device/
├── store.go            ← Store interface definition
├── store_memory.go     ← in-memory implementation (dev/test)
└── store_postgres.go   ← PostgreSQL implementation (production)
```

### The interface (store.go)

```go
type Store interface {
    Load(ctx context.Context, deviceID string) (*Device, error)
    Save(ctx context.Context, device *Device) error
    List(ctx context.Context) ([]*Device, error)
}
```

### The postgres implementation (store_postgres.go)

```go
type postgresStore struct {
    pool *pgxpool.Pool
}

// Constructor returns the interface type, not the concrete type.
// Callers never depend on postgresStore directly.
func NewPostgresStore(pool *pgxpool.Pool) Store {
    return &postgresStore{pool: pool}
}

func (s *postgresStore) Load(ctx context.Context, deviceID string) (*Device, error) {
    ctx, cancel := context.WithTimeout(ctx, db.QueryTimeout)
    defer cancel()

    row := s.pool.QueryRow(ctx,
        `SELECT id, status FROM devices WHERE id = $1`, deviceID,
    )

    var dev Device
    var status int16
    if err := row.Scan(&dev.ID, &status); err != nil {
        if errors.Is(err, pgx.ErrNoRows) {
            return nil, ErrDeviceNotFound  // domain error, not pgx error
        }
        return nil, err
    }
    dev.Status = Status(status)
    return &dev, nil
}
```

### Wiring in main.go

```go
pool, err := pgxpool.New(ctx, cfg.DatabaseDSN)
if err != nil {
    return fmt.Errorf("connecting to database: %w", err)
}
defer pool.Close()

deviceStore := device.NewPostgresStore(pool)  // satisfies device.Store interface
```

The service layer receives `device.Store` — it never imports pgx. If you want to run tests without a real database, swap in `device.NewMemoryStore()`. The service code does not change.
