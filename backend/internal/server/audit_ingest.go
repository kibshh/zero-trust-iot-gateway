package server

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/attestation"
	"github.com/kibshh/zero-trust-iot-gateway/backend/internal/audit"
)

type auditIngestRequest struct {
	SchemaVersion uint8               `json:"schema_version"`
	DeviceID      string              `json:"device_id"`
	Records       []auditIngestRecord `json:"records"`
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

// handleAuditIngest receives a batch of policy audit records from a device.
// POST /api/v1/audit/ingest
// Request:  {"schema_version":1,"device_id":"<hex>","records":[...]}
// Response: 200 {"status":"ok"} | 400 | 403 | 413 | 503
func (s *Server) handleAuditIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.auditSink == nil {
		http.Error(w, "audit sink not configured", http.StatusServiceUnavailable)
		return
	}

	// Enforce max body size before decoding to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, int64(s.auditMaxBodyBytes))

	var req auditIngestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Reject unknown schema versions to prevent silent misinterpretation
	if req.SchemaVersion != audit.CurrentSchemaVersion {
		http.Error(w, "unsupported schema_version", http.StatusBadRequest)
		return
	}

	// Validate device_id format (hex, 16 bytes)
	rawID, err := hex.DecodeString(req.DeviceID)
	if err != nil || len(rawID) != attestation.DeviceIDSize {
		http.Error(w, "invalid device_id", http.StatusBadRequest)
		return
	}

	if len(req.Records) == 0 {
		http.Error(w, "records are required", http.StatusBadRequest)
		return
	}

	// Enforce max records per request
	if len(req.Records) > s.auditMaxRecordsPerRequest {
		http.Error(w, "too many records in request", http.StatusRequestEntityTooLarge)
		return
	}

	// Verify device is registered
	if _, err := s.deviceStore.Load(r.Context(), req.DeviceID); err != nil {
		http.Error(w, "unknown device", http.StatusForbidden)
		return
	}

	// Stamp server-side receive time once for the whole batch
	receivedAt := time.Now().UTC()

	records := make([]audit.Record, len(req.Records))
	for i, rec := range req.Records {
		records[i] = audit.Record{
			DeviceID:   req.DeviceID,
			Action:     rec.Action,
			Decision:   rec.Decision,
			Actor:      rec.Actor,
			Origin:     rec.Origin,
			Intent:     rec.Intent,
			State:      rec.State,
			Source:     rec.Source,
			ReceivedAt: receivedAt,
		}
	}

	if err := s.auditSink.Ingest(r.Context(), records); err != nil {
		http.Error(w, "failed to store audit records", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
