// Package server is the Charter control-plane HTTP API (pilot scaffold).
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Pinger reports whether the database is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// EvidenceBackend describes the evidence store in use. The pilot scaffold only
// has a test fixture; it MUST NOT be presented as retention-enforced storage.
type EvidenceBackend struct {
	Kind              string `json:"kind"`
	RetentionEnforced bool   `json:"retention_enforced"`
	Notice            string `json:"notice"`
}

func TestFixtureBackend() EvidenceBackend {
	return EvidenceBackend{
		Kind:              "test-fixture",
		RetentionEnforced: false,
		Notice:            "TEST EVIDENCE ONLY: not immutable, not retention-enforced; do not use for real records",
	}
}

func New(db Pinger, ev EvidenceBackend) http.Handler {
	mux := http.NewServeMux()
	// Liveness: process is up. No dependencies checked.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "evidence_backend": ev})
	})
	// Readiness: database reachable. Fails closed.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "evidence_backend": ev})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
