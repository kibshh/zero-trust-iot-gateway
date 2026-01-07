# Zero-Trust IoT Gateway Backend

Backend service for managing and controlling IoT gateway devices.

## Overview

The backend provides:
- Device identity management
- Firmware attestation verification
- Policy distribution and enforcement
- Device authorization and revocation
- Audit logging

## Project Structure

```
backend/
├── cmd/
│   └── server/      # Server application entry point
│       └── main.go
├── internal/         # Private application code
│   ├── config/      # Configuration management
│   ├── device/      # Device management
│   ├── audit/       # Audit sink
│   ├── attestation/ # Attestation verification
│   ├── policy/      # Policy management
│   └── server/      # HTTP/gRPC server implementation
└── go.mod           # Go module definition
```

## Development

### Prerequisites

- Go 1.21 or later

### Running

```bash
go run cmd/server/main.go
```

### Building

```bash
go build -o backend cmd/server/main.go
```

## TODO

- [ ] Configuration management
- [ ] Database/storage layer
- [ ] HTTP/gRPC API server
- [ ] Device management service
- [ ] Attestation verification service
- [ ] Policy management service
- [ ] Authentication/authorization
- [ ] Audit logging

