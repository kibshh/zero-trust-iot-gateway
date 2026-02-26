package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/policy"
)

type policyRevokeRequest struct {
	DeviceID string `json:"device_id"`
}

// handlePolicyRevoke marks the active policy for a device as revoked.
// POST /api/v1/policy/revoke
// Request:  {"device_id":"<hex>"}
// Response: 200 {"status":"ok"} | 400 | 404 | 409 | 500
func (s *Server) handlePolicyRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policyRevokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != policy.ZTPVDeviceIDSize {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
		return
	}

	if _, err := s.deviceStore.Load(req.DeviceID); err != nil {
		http.Error(w, "device not found", http.StatusNotFound)
		return
	}

	if err := s.policySvc.Revoke(r.Context(), req.DeviceID); err != nil {
		if errors.Is(err, policy.ErrPolicyNotFound) {
			http.Error(w, "no active policy for device", http.StatusNotFound)
			return
		}
		http.Error(w, "revocation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
