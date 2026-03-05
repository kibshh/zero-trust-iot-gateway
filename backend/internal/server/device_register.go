package server

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
)

type registerRequest struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

// handleDeviceRegister registers a new device and stores its public key.
// POST /api/v1/devices/register
// Request:  {"device_id":"<hex>","public_key":"<hex DER>"}
// Response: 201 {"status":"registered"} | 400 | 409 | 500
func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.attestationSvc == nil {
		http.Error(w, "attestation service not configured", http.StatusServiceUnavailable)
		return
	}

	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate device_id format (hex, 16 bytes)
	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != attestation.DeviceIDSize {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
		return
	}

	// Validate public key is non-empty hex
	pubKeyDER, err := hex.DecodeString(req.PublicKey)
	if err != nil || len(pubKeyDER) == 0 {
		http.Error(w, "invalid public_key", http.StatusBadRequest)
		return
	}

	// Basic sanity check: parse public key
	if _, err := x509.ParsePKIXPublicKey(pubKeyDER); err != nil {
		http.Error(w, "invalid public_key format", http.StatusBadRequest)
		return
	}

	if err := s.attestationSvc.Register(r.Context(), req.DeviceID, pubKeyDER); err != nil {
		if errors.Is(err, attestation.ErrDeviceAlreadyExists) {
			http.Error(w, "device already registered", http.StatusConflict)
			return
		}
		http.Error(w, "cannot register device", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"status":"registered"}`))
}

