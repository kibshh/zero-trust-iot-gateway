package server

import (
	"encoding/hex"
	"encoding/json"
	"crypto/x509"
	"errors"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
)

type registerRequest struct {
	DeviceID  string `json:"device_id"`
	PublicKey string `json:"public_key"`
}

func (s *Server) handleDeviceRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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

	// Validate public key
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

	err = s.registry.Register(req.DeviceID, pubKeyDER)
	if err != nil {
		if errors.Is(err, attestation.ErrDeviceAlreadyExists) {
			http.Error(w, "registration failed", http.StatusConflict)
			return
		}
		http.Error(w, "cannot register device", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

