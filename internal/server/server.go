// Package server is the Charter control-plane HTTP API (pilot scaffold).
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
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
	RetentionStatus   string `json:"retention_status,omitempty"`
	Notice            string `json:"notice"`
}

func TestFixtureBackend() EvidenceBackend {
	return EvidenceBackend{
		Kind:              "test-fixture",
		RetentionEnforced: false,
		Notice:            "TEST EVIDENCE ONLY: not immutable, not retention-enforced; do not use for real records",
	}
}

// PostgresEvidenceBackend describes the real evidence write path (#4). It is
// durable and append-only by privileges and triggers, but it is NOT
// retention-enforced storage and must not be presented as such.
func PostgresEvidenceBackend() EvidenceBackend {
	i := evidence.PG{}.Info()
	return EvidenceBackend{Kind: i.Kind, RetentionEnforced: i.RetentionEnforced, Notice: i.Notice}
}

// New builds the handler. Without WithAuth only the unauthenticated health
// endpoints exist; no data route is ever served unauthenticated.
func New(db Pinger, ev EvidenceBackend, opts ...Option) http.Handler {
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
	for _, o := range opts {
		o(mux)
	}
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
