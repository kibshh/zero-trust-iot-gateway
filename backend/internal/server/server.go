package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/audit"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/device"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/policy"
)

// Server represents the HTTP server for the zero-trust IoT gateway backend
type Server struct {
	httpServer *http.Server
	addr       string

	registry       attestation.PublicKeyRegistry
	attestationSvc attestation.Service
	authorizer     *device.Authorizer
	deviceStore    device.Store
	deviceSvc      device.Service
	policySvc      policy.Service
	auditSink      audit.Sink
}

// Config holds server configuration
type Config struct {
	Host         string
	Port         int
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// DefaultConfig returns a default server configuration
func DefaultConfig() Config {
	return Config{
		Host:         "0.0.0.0",
		Port:         8080,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
}

// New creates a new server instance
func New(
	cfg Config,
	attestationSvc attestation.Service,
	authorizer *device.Authorizer,
	deviceStore device.Store,
	deviceSvc device.Service,
	policySvc policy.Service,
	auditSink audit.Sink,
) *Server {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	mux := http.NewServeMux()

	server := &Server{
		addr:           addr,
		attestationSvc: attestationSvc,
		authorizer:     authorizer,
		deviceStore:    deviceStore,
		deviceSvc:      deviceSvc,
		policySvc:      policySvc,
		auditSink:      auditSink,
	}
	// Register API routes
	server.registerRoutes(mux)

	server.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	return server
}

// Start starts the HTTP server and blocks until context is cancelled
func (s *Server) Start(ctx context.Context) error {
	// Start server in a goroutine
	errChan := make(chan error, 1)
	go func() {
		log.Printf("Server starting on %s", s.addr)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Wait for context cancellation or server error
	select {
	case <-ctx.Done():
		log.Println("Shutting down server...")
		// Create shutdown context with timeout
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("server shutdown error: %w", err)
		}
		log.Println("Server shut down gracefully")
		return nil
	case err := <-errChan:
		return err
	}
}

// registerRoutes registers all API endpoints
func (s *Server) registerRoutes(mux *http.ServeMux) {
	// Health check endpoint
	mux.HandleFunc("/health", s.handleHealth)

	// Device management endpoints
	mux.HandleFunc("/api/v1/devices/register", s.handleDeviceRegister)
	mux.HandleFunc("/api/v1/devices/", s.handleDeviceOperations)

	// Attestation endpoints
	mux.HandleFunc("/api/v1/attestation/challenge", s.handleAttestationChallenge)
	mux.HandleFunc("/api/v1/attestation/verify", s.handleAttestationVerify)

	// Authorization endpoints
	mux.HandleFunc("/api/v1/authorization/request", s.handleAuthorizationRequest)

	// Policy endpoints
	mux.HandleFunc("/api/v1/policy/issue", s.handlePolicyIssue)
	mux.HandleFunc("/api/v1/policy/revoke", s.handlePolicyRevoke)

	// Audit endpoints
	mux.HandleFunc("/api/v1/audit/ingest", s.handleAuditIngest)
}

// TODO: Implement all endpoints OUTSIDE of this file.

// Health check handler
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}


