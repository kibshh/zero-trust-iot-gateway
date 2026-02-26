package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/device"
)

type deviceInfoResponse struct {
	DeviceID     string `json:"device_id"`
	Status       uint8  `json:"status"`
	RegisteredAt int64  `json:"registered_at"`
	LastSeenAt   int64  `json:"last_seen_at"`
}

// handleDeviceOperations dispatches GET and DELETE on /api/v1/devices/{id}.
// GET    /api/v1/devices/{id} — return device info
// DELETE /api/v1/devices/{id} — revoke device (marks StatusRevoked, does not delete)
func (s *Server) handleDeviceOperations(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/devices/")

	rawID, err := hex.DecodeString(id)
	if err != nil || len(rawID) != attestation.DeviceIDSize {
		http.Error(w, "invalid device id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleDeviceGet(s, w, id)
	case http.MethodDelete:
		handleDeviceDelete(s, w, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleDeviceGet(s *Server, w http.ResponseWriter, id string) {
	dev, err := s.deviceStore.Load(id)
	if err != nil {
		if errors.Is(err, device.ErrDeviceNotFound) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load device", http.StatusInternalServerError)
		return
	}

	resp := deviceInfoResponse{
		DeviceID:     dev.ID,
		Status:       uint8(dev.Status),
		RegisteredAt: dev.RegisteredAt.Unix(),
		LastSeenAt:   dev.LastSeenAt.Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleDeviceDelete(s *Server, w http.ResponseWriter, id string) {
	dev, err := s.deviceStore.Load(id)
	if err != nil {
		if errors.Is(err, device.ErrDeviceNotFound) {
			http.Error(w, "device not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to load device", http.StatusInternalServerError)
		return
	}

	if dev.Status == device.StatusRevoked {
		http.Error(w, "device already revoked", http.StatusConflict)
		return
	}

	dev.Status = device.StatusRevoked
	if err := s.deviceStore.Save(dev); err != nil {
		http.Error(w, "revocation failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
