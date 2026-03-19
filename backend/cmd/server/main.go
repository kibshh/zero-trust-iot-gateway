package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/audit"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/config"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/db"
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
		log.Fatalf("Startup failed: %v", err)
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

	// Connect to PostgreSQL and run migrations
	pool, err := pgxpool.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if err := db.Migrate(cfg.DatabaseDSN); err != nil {
		return fmt.Errorf("running migrations: %w", err)
	}
	log.Println("Database migrations applied")

	// Initialize stores (PostgreSQL)
	deviceStore := device.NewPostgresStore(pool)
	policyStore := policy.NewPostgresStore(pool)

	// Initialize authorizer
	authorizer := device.NewAuthorizer(deviceStore, policyStore)

	// Initialize device service
	deviceSvc := device.NewService(deviceStore)

	// Initialize attestation registry and service
	registry := attestation.NewPostgresRegistry(pool)
	attestationSvc := attestation.NewMemoryService(registry)

	// Initialize policy service
	policyBuilder := policy.NewBuilder()
	ztpvBuilder := policy.NewZTPVBuilder()
	policySigner, err := policy.NewSignerFromKey(signingKey)
	if err != nil {
		return fmt.Errorf("policy signer error: %w", err)
	}
	deviceSource := device.NewDeviceSourceAdapter(deviceStore)
	versionStore := policy.NewPostgresVersionStore(pool)
	ruleSource := policy.NewDefaultRuleSource()
	policyTTL := time.Duration(cfg.PolicyTTLSec) * time.Second
	policySvc := policy.NewPolicyService(policyBuilder, ztpvBuilder, policySigner, policyStore, deviceSource, versionStore, ruleSource, policyTTL)

	// Initialize audit sink (PostgreSQL)
	auditSink := audit.NewPostgresSink(pool)

	// Build server config from loaded configuration
	srvCfg := server.Config{
		Host:                      cfg.ServerHost,
		Port:                      cfg.ServerPort,
		ReadTimeout:               time.Duration(cfg.ServerReadTimeoutSec) * time.Second,
		WriteTimeout:              time.Duration(cfg.ServerWriteTimeoutSec) * time.Second,
		IdleTimeout:               time.Duration(cfg.ServerIdleTimeoutSec) * time.Second,
		AuditMaxRecordsPerRequest: cfg.AuditMaxRecordsPerRequest,
		AuditMaxBodyBytes:         cfg.AuditMaxBodyBytes,
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
