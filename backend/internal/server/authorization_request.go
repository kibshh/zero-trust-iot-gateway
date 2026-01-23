package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/device"
)

type authorizationRequest struct {
	DeviceID     string `json:"device_id"`
	FirmwareHash string `json:"firmware_hash"`
}

type authorizationResponse struct {
	Authorized bool `json:"authorized"`
}

// Authorization request handler
// Device sends device_id and firmware_hash in JSON body.
// Returns {"authorized": true|false}
func (s *Server) handleAuthorizationRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req authorizationRequest
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

	// Validate firmware_hash format (hex, 32 bytes)
	firmwareHash, err := hex.DecodeString(req.FirmwareHash)
	if err != nil || len(firmwareHash) != attestation.FirmwareHashSize {
		http.Error(w, "invalid firmware_hash", http.StatusBadRequest)
		return
	}

	authorized := device.IsFirmwareAuthorized(req.DeviceID, firmwareHash)

	resp := authorizationResponse{
		Authorized: authorized,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}



