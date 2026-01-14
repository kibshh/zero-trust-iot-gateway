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

// Attestation challenge handler
// Device ID should be provided in json body.
func (s *Server) handleAttestationChallenge(w http.ResponseWriter, r *http.Request) {
	// Handles POST requests only.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req challengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate device_id format (hex, 16 bytes)
	// Device ID will be used as a string but here it's validated if it's a valid hex string.
	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != attestation.DeviceIDSize {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
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
