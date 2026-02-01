package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/audit"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/device"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/policy"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/server"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		log.Printf("Shutdown signal received: %s", sig)
		cancel()
	}()

	// Initialize and start backend services
	if err := run(ctx); err != nil {
		log.Fatalf("Backend error: %v", err)
	}
}

func run(ctx context.Context) error {
	// TODO: Initialize configuration
	// TODO: Initialize database/storage

	// Initialize stores
	deviceStore := device.NewMemoryStore()
	policyStore := policy.NewMemoryStore()

	// Initialize authorizer
	authorizer := device.NewAuthorizer(deviceStore, policyStore)

	// TODO: Initialize device management service
	var deviceSvc device.Service = nil // TODO: implement device service

	// TODO: Initialize attestation service
	var attestationSvc attestation.Service = nil // TODO: implement attestation service

	// Initialize policy signing key (dev mode: generate ephemeral key)
	// TODO: Load from secure storage in production
	signingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	log.Println("WARNING: Using ephemeral signing key (dev mode)")

	// Initialize policy service
	policyBuilder := policy.NewBuilder()
	policySigner, err := policy.NewSignerFromKey(signingKey)
	if err != nil {
		return err
	}
	deviceSource := device.NewDeviceSourceAdapter(deviceStore)
	policySvc := policy.NewPolicyService(policyBuilder, policySigner, policyStore, deviceSource)

	// TODO: Initialize audit sink
	var auditSink audit.Sink = nil // TODO: implement audit sink

	// Initialize HTTP server with default configuration
	cfg := server.DefaultConfig()
	srv := server.New(
		cfg,
		attestationSvc,
		authorizer,
		deviceSvc,
		policySvc,
		auditSink,
	)

	// Start server (blocks until context is cancelled)
	return srv.Start(ctx)
}

