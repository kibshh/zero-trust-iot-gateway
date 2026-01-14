package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
)

type verifyRequest struct {
	DeviceID     string `json:"device_id"`
	FirmwareHash string `json:"firmware_hash"`
	Signature    string `json:"signature"`
}

type verifyResponse struct {
	Granted bool `json:"granted"`
}

// Attestation verify handler
// Device sends attestation response (device_id, firmware_hash, signature) in JSON body.
func (s *Server) handleAttestationVerify(w http.ResponseWriter, r *http.Request) {
	// Handles POST requests only.
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req verifyRequest
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

	// Validate signature format (hex, max 72 bytes)
	signatureDER, err := hex.DecodeString(req.Signature)
	if err != nil || len(signatureDER) == 0 || len(signatureDER) > attestation.MaxSignatureSize {
		http.Error(w, "invalid signature", http.StatusBadRequest)
		return
	}

	verifyReq := attestation.VerifyRequest{
		DeviceID:     req.DeviceID,
		FirmwareHash: firmwareHash,
		SignatureDER: signatureDER,
	}

	result, err := s.attestationSvc.Verify(r.Context(), verifyReq)
	if err != nil {
		http.Error(w, "cannot verify attestation", http.StatusInternalServerError)
		return
	}

	resp := verifyResponse{
		Granted: result.Granted,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

