package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
)

type challengeRequest struct {
	DeviceID string `json:"device_id"`
}

type challengeResponse struct {
	Nonce string `json:"nonce"`
}

// handleAttestationChallenge issues a nonce challenge for a registered device.
// POST /api/v1/attestation/challenge
// Request:  {"device_id":"<hex>"}
// Response: {"nonce":"<hex>"}
func (s *Server) handleAttestationChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.attestationSvc == nil {
		http.Error(w, "attestation service not configured", http.StatusServiceUnavailable)
		return
	}

	var req challengeRequest
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

	// Verify device is registered before issuing a challenge
	if _, err := s.deviceStore.Load(r.Context(), req.DeviceID); err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	challenge, err := s.attestationSvc.CreateChallenge(r.Context(), req.DeviceID)
	if err != nil {
		http.Error(w, "cannot create challenge", http.StatusInternalServerError)
		return
	}

	resp := challengeResponse{
		Nonce: hex.EncodeToString(challenge.Nonce),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
