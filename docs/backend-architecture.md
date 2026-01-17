# Backend Architecture

This document describes the software structure, layers, and components of the Go backend.

## Directory Structure

```
backend/
├── cmd/
│   └── server/           # Application entry point
│       └── main.go
├── internal/
│   ├── server/           # HTTP layer (handlers, routing)
│   │   ├── server.go
│   │   ├── attestation_challenge.go
│   │   ├── attestation_verify.go
│   │   └── device_register.go
│   ├── attestation/      # Attestation domain
│   │   ├── service.go         # Service interface
│   │   ├── service_memory.go  # In-memory implementation
│   │   ├── registry.go        # Public key registry interface
│   │   ├── registry_memory.go # In-memory registry implementation
│   │   ├── model.go           # Domain models (Challenge, VerifyRequest, etc.)
│   │   └── crypto.go          # Cryptographic helpers (ECDSA verification)
│   ├── policy/           # Policy management domain
│   │   └── service.go    # Service interface (Issue, Revoke)
│   └── audit/            # Audit logging domain
│       └── sink.go       # Sink interface (Ingest)
└── go.mod
```

## Architecture Layers

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP Layer (server/)                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐       │
│  │   Handlers   │ │   Routing    │ │   Server     │       │
│  └──────────────┘ └──────────────┘ └──────────────┘       │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ uses
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                  Service Layer (internal/)                  │
│  ┌──────────────┐ ┌──────────────┐                        │
│  │ Attestation  │ │   Policy     │                        │
│  │   Service    │ │   Service    │                        │
│  └──────────────┘ └──────────────┘                        │
│                                                              │
│  ┌──────────────┐                                          │
│  │ Audit Sink   │                                          │
│  └──────────────┘                                          │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ implements
                           ▼
┌─────────────────────────────────────────────────────────────┐
│              Implementation Layer (memory/)                 │
│  ┌──────────────┐ ┌──────────────┐                        │
│  │ In-Memory    │ │ In-Memory    │                        │
│  │  Service     │ │  Registry    │                        │
│  └──────────────┘ └──────────────┘                        │
└─────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. HTTP Layer (`internal/server/`)

**Purpose**: HTTP request handling, routing, and server lifecycle management.

**Components**:
- `server.go`: Main server struct, configuration, routing, lifecycle (Start/Stop)
- `attestation_challenge.go`: POST `/api/v1/attestation/challenge` handler
- `attestation_verify.go`: POST `/api/v1/attestation/verify` handler
- `device_register.go`: POST `/api/v1/devices/register` handler

**Responsibilities**:
- Parse HTTP requests (JSON decoding, validation)
- Validate input format (hex encoding, sizes)
- Call appropriate service methods
- Format HTTP responses (status codes, JSON encoding)
- Error handling and HTTP status mapping

### 2. Attestation Domain (`internal/attestation/`)

**Purpose**: Device attestation (challenge generation, signature verification).

**Interfaces**:
- `Service`: CreateChallenge, Verify
- `PublicKeyRegistry`: Lookup, Register

**Implementations**:
- `service_memory.go`: In-memory challenge store (TTL-based expiration)
- `registry_memory.go`: In-memory public key storage

**Supporting**:
- `model.go`: Challenge, VerifyRequest, VerifyResult structs
- `crypto.go`: VerifyECDSAP256 (DER parsing, P-256 enforcement, signature verification)

**Flow**:
1. Device requests challenge → `CreateChallenge` generates nonce
2. Device responds with signature → `Verify` checks challenge, verifies signature, validates firmware

### 3. Policy Domain (`internal/policy/`)

**Purpose**: Policy issuance and revocation.

**Interface**:
- `Service`: Issue, Revoke

**Note**: Currently interface-only (implementation pending).

### 4. Audit Domain (`internal/audit/`)

**Purpose**: Audit log ingestion (write-only sink pattern).

**Interface**:
- `Sink`: Ingest (takes audit records from devices)

**Note**: Currently interface-only (implementation pending).

## Request Flow Example: Device Registration

```
ESP32 Device
    │
    │ POST /api/v1/devices/register
    │ { device_id: "...", public_key: "..." }
    ▼
┌──────────────────────────────────────┐
│ HTTP Handler (device_register.go)   │
│  - Parse JSON                        │
│  - Validate device_id (hex, 16B)    │
│  - Validate public_key (hex, DER)   │
│  - Parse public key (x509)          │
└──────────────────────────────────────┘
    │
    │ s.registry.Register(deviceID, pubKeyDER)
    ▼
┌──────────────────────────────────────┐
│ PublicKeyRegistry (registry_memory)  │
│  - Check if device exists            │
│  - Store DER-encoded public key      │
└──────────────────────────────────────┘
    │
    │ 201 Created (no body)
    ▼
ESP32 Device
```

## Request Flow Example: Attestation

```
ESP32 Device
    │
    │ POST /api/v1/attestation/challenge
    │ { device_id: "..." }
    ▼
┌──────────────────────────────────────┐
│ HTTP Handler (attestation_challenge)│
│  - Parse JSON                        │
│  - Validate device_id                │
└──────────────────────────────────────┘
    │
    │ attestationSvc.CreateChallenge()
    ▼
┌──────────────────────────────────────┐
│ Attestation Service (service_memory) │
│  - Generate 32-byte nonce            │
│  - Store challenge (TTL: 30s)        │
└──────────────────────────────────────┘
    │
    │ { nonce: "..." }
    ▼
ESP32 Device
    │
    │ (Sign: nonce || device_id || firmware_hash)
    │
    │ POST /api/v1/attestation/verify
    │ { device_id, firmware_hash, signature }
    ▼
┌──────────────────────────────────────┐
│ HTTP Handler (attestation_verify)   │
│  - Parse JSON                        │
│  - Validate all fields               │
└──────────────────────────────────────┘
    │
    │ attestationSvc.Verify()
    ▼
┌──────────────────────────────────────┐
│ Attestation Service (service_memory) │
│  - Lookup challenge (one-time use)   │
│  - Check expiration                  │
│  - registry.Lookup(deviceID)         │
│  - Rebuild: nonce||device_id||hash   │
│  - VerifyECDSAP256(signature)        │
│  - Check firmware whitelist          │
└──────────────────────────────────────┘
    │
    │ VerifyECDSAP256 (crypto.go)
    │  - Parse DER public key           │
    │  - Enforce P-256 curve            │
    │  - Hash message (SHA-256)         │
    │  - Parse DER signature (ASN.1)    │
    │  - ecdsa.Verify()                 │
    │
    │ { granted: true/false }
    ▼
ESP32 Device
```

## Service Dependencies

```
Server
  ├── attestation.Service
  │     └── PublicKeyRegistry (embedded)
  ├── policy.Service
  └── audit.Sink
```

**Note**: Currently, `Server` holds both `attestationSvc` and `registry` separately. The registry is used directly in device registration, while the service uses it for attestation verification.

## Design Principles

1. **Interface-based design**: Service interfaces enable easy swapping of implementations (memory → database)
2. **Separation of concerns**: HTTP layer handles transport, services handle business logic
3. **Dependency injection**: Services injected into Server constructor
4. **Hex encoding**: Binary data (device IDs, keys, hashes) transmitted as hex strings in JSON
5. **Fail-closed**: Invalid input → 400 Bad Request; unknown errors → 500 Internal Server Error
6. **Idempotency**: Device registration returns 409 Conflict if device already exists

