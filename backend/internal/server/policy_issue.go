package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/policy"
)

type policyIssueRequest struct {
	DeviceID string `json:"device_id"`
}

type policyIssueResponse struct {
	Policy string `json:"policy"` // hex-encoded ZTPV blob
}

// handlePolicyIssue issues a signed runtime policy (ZTPV) for a device.
// POST /api/v1/policy/issue
// Request:  {"device_id":"<hex>"}
// Response: {"policy":"<hex-encoded ZTPV blob>"}
func (s *Server) handlePolicyIssue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req policyIssueRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	// Validate device_id format (hex, 16 bytes)
	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != policy.ZTPVDeviceIDSize {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
		return
	}

	// Issue runtime policy
	blob, err := s.policySvc.IssueRuntime(r.Context(), req.DeviceID)
	if err != nil {
		// Map policy errors to HTTP status codes
		if errors.Is(err, policy.ErrDeviceNotFound) || errors.Is(err, policy.ErrDeviceIDInvalid) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		if errors.Is(err, policy.ErrDeviceRevoked) {
			http.Error(w, "device revoked", http.StatusForbidden)
			return
		}
		http.Error(w, "policy issuance failed", http.StatusInternalServerError)
		return
	}

	resp := policyIssueResponse{
		Policy: hex.EncodeToString(blob),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
