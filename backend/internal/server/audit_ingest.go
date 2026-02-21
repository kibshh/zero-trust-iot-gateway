package server

import (
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/audit"
)

type auditIngestRequest struct {
	DeviceID string              `json:"device_id"`
	Records  []auditIngestRecord `json:"records"`
}

type auditIngestRecord struct {
	Action   uint8 `json:"action"`
	Decision uint8 `json:"decision"`
	Actor    uint8 `json:"actor"`
	Origin   uint8 `json:"origin"`
	Intent   uint8 `json:"intent"`
	State    uint8 `json:"state"`
	Source   uint8 `json:"source"`
}

func (s *Server) handleAuditIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.auditSink == nil {
		http.Error(w, `{"error":"audit sink not configured"}`, http.StatusServiceUnavailable)
		return
	}

	var req auditIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != attestation.DeviceIDSize {
		http.Error(w, `{"error":"invalid device_id"}`, http.StatusBadRequest)
		return
	}

	if len(req.Records) == 0 {
		http.Error(w, `{"error":"records are required"}`, http.StatusBadRequest)
		return
	}

	if _, err := s.deviceStore.Load(req.DeviceID); err != nil {
		http.Error(w, `{"error":"unknown device"}`, http.StatusForbidden)
		return
	}

	records := make([]audit.Record, len(req.Records))
	for i, rec := range req.Records {
		records[i] = audit.Record{
			DeviceID: req.DeviceID,
			Action:   rec.Action,
			Decision: rec.Decision,
			Actor:    rec.Actor,
			Origin:   rec.Origin,
			Intent:   rec.Intent,
			State:    rec.State,
			Source:   rec.Source,
		}
	}

	if err := s.auditSink.Ingest(r.Context(), records); err != nil {
		http.Error(w, `{"error":"failed to store audit records"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
