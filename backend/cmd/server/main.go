package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/audit"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/config"
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
	// Load and validate configuration from environment
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return fmt.Errorf("configuration error: %w", err)
	}

	// Load signing key from file, or generate ephemeral key in dev mode
	signingKey, err := config.LoadSigningKey(cfg)
	if err != nil {
		return fmt.Errorf("signing key error: %w", err)
	}
	if cfg.DevEphemeralKey {
		log.Printf("WARNING: %s=true — ephemeral signing key in use; do not run in production", config.EnvDevEphemeralKey)
	}

	// TODO: Initialize database/storage

	// Initialize stores
	deviceStore := device.NewMemoryStore()
	policyStore := policy.NewMemoryStore()

	// Initialize authorizer
	authorizer := device.NewAuthorizer(deviceStore, policyStore)

	// TODO: Initialize device management service
	var deviceSvc device.Service = nil

	// TODO: Initialize attestation service
	var attestationSvc attestation.Service = nil

	// Initialize policy service
	policyBuilder := policy.NewBuilder()
	ztpvBuilder := policy.NewZTPVBuilder()
	policySigner, err := policy.NewSignerFromKey(signingKey)
	if err != nil {
		return fmt.Errorf("policy signer error: %w", err)
	}
	deviceSource := device.NewDeviceSourceAdapter(deviceStore)
	policySvc := policy.NewPolicyService(policyBuilder, ztpvBuilder, policySigner, policyStore, deviceSource)

	// Initialize audit sink (dev mode: in-memory)
	// TODO: Replace with persistent storage
	auditSink := audit.NewMemorySink()

	// Build server config from loaded configuration
	srvCfg := server.Config{
		Host:         cfg.ServerHost,
		Port:         cfg.ServerPort,
		ReadTimeout:  time.Duration(cfg.ServerReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(cfg.ServerWriteTimeoutSec) * time.Second,
		IdleTimeout:  time.Duration(cfg.ServerIdleTimeoutSec) * time.Second,
	}
	srv := server.New(
		srvCfg,
		attestationSvc,
		authorizer,
		deviceStore,
		deviceSvc,
		policySvc,
		auditSink,
	)

	// Start server (blocks until context is cancelled)
	return srv.Start(ctx)
}
