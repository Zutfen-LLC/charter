package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// ExportAPI exposes the governed lifecycle only. It cannot read a turn/object
// or return bytes before the package has passed final delivery authorization.
type ExportAPI interface {
	Request(context.Context, store.Principal, records.NewExportRequest) (records.ExportSummary, error)
	Approve(context.Context, store.Principal, string, string) (records.ExportSummary, error)
	Generate(context.Context, store.Principal, string) (records.ExportSummary, error)
	Retrieve(context.Context, store.Principal, string) (ExportDelivery, error)
	Cancel(context.Context, store.Principal, string) error
	AuditDenial(context.Context, store.Principal, string, string, int) error
}

type ExportDelivery struct {
	DirectoryJSON  []byte
	ManifestDigest string
}

func decodeExportRequest(r *http.Request, dst any, keys ...string) error {
	const limit = 32 << 10
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || len(raw) > limit {
		return store.ErrNotFound
	}
	v, err := evidence.ParseJSON(raw)
	m, ok := v.(map[string]any)
	if err != nil || !ok || len(m) != len(keys) {
		return store.ErrNotFound
	}
	for _, k := range keys {
		if x, ok := m[k]; !ok || x == nil {
			return store.ErrNotFound
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return store.ErrNotFound
	}
	return nil
}

type exportResponse struct {
	http.ResponseWriter
	reject func(int)
	wrote  bool
}

func (w *exportResponse) WriteHeader(status int) {
	if w.wrote {
		return
	}
	w.wrote = true
	if status >= 400 && w.reject != nil {
		w.reject(status)
	}
	w.ResponseWriter.WriteHeader(status)
}

func (a *Auth) exportRoute(role, operation string, h handler) handler {
	protected := a.role(role, func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		if a.Exports == nil {
			notImplemented(w, r, p)
			return
		}
		h(w, r, p)
	})
	return func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		w.Header().Set("Cache-Control", "no-store")
		out := &exportResponse{ResponseWriter: w}
		if a.Exports != nil {
			out.reject = func(status int) {
				ctx, stop := context.WithTimeout(context.WithoutCancel(r.Context()), 750*time.Millisecond)
				defer stop()
				_ = a.Exports.AuditDenial(ctx, p, operation, r.PathValue("id"), status)
			}
		}
		protected(out, r, p)
	}
}

func (a *Auth) exportFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		deny(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrForbidden):
		deny(w, http.StatusForbidden, "forbidden")
	case errors.Is(err, records.ErrConflict), errors.Is(err, records.ErrExportConflict):
		deny(w, http.StatusConflict, "export conflict")
	default:
		// Backend errors can contain sensitive coordinates. Keep client and
		// operational output fixed; detailed attribution is in scoped audit.
		deny(w, http.StatusServiceUnavailable, "export unavailable")
	}
}

type exportStatus struct {
	ID             string     `json:"export_id"`
	State          string     `json:"state"`
	SnapshotDigest string     `json:"snapshot_digest"`
	ManifestDigest string     `json:"manifest_digest,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
}

func replyExportStatus(w http.ResponseWriter, s records.ExportSummary) {
	manifest := ""
	if s.State == records.ExportReady && s.ManifestDigest != "" {
		manifest = "sha256:" + s.ManifestDigest
	}
	writeJSON(w, http.StatusOK, exportStatus{ID: s.ID, State: s.State, SnapshotDigest: s.SnapshotDigest, ManifestDigest: manifest, ExpiresAt: s.ExpiresAt})
}

func (a *Auth) requestExport(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var intent records.ExportIntent
	if err := decodeExportRequest(r, &intent, "project_id", "matter_id", "custodian_ids", "window_start", "window_end", "reason"); err != nil {
		deny(w, http.StatusBadRequest, "invalid export intent")
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || len(keys[0]) == 0 || len(keys[0]) > 128 {
		deny(w, http.StatusBadRequest, "invalid idempotency key")
		return
	}
	s, err := a.Exports.Request(r.Context(), p, records.NewExportRequest{RequestID: keys[0], Intent: intent})
	if err != nil {
		a.exportFailure(w, err)
		return
	}
	replyExportStatus(w, s)
}

func (a *Auth) approveExport(w http.ResponseWriter, r *http.Request, p store.Principal) {
	id, ok := store.CanonicalID(r.PathValue("id"))
	if !ok {
		a.exportFailure(w, store.ErrNotFound)
		return
	}
	var req struct {
		SnapshotDigest string `json:"snapshot_digest"`
	}
	if err := decodeExportRequest(r, &req, "snapshot_digest"); err != nil {
		deny(w, http.StatusBadRequest, "invalid approval")
		return
	}
	s, err := a.Exports.Approve(r.Context(), p, id, req.SnapshotDigest)
	if err != nil {
		a.exportFailure(w, err)
		return
	}
	replyExportStatus(w, s)
}

func (a *Auth) generateExport(w http.ResponseWriter, r *http.Request, p store.Principal) {
	id, ok := store.CanonicalID(r.PathValue("id"))
	if !ok {
		a.exportFailure(w, store.ErrNotFound)
		return
	}
	s, err := a.Exports.Generate(r.Context(), p, id)
	if err != nil {
		a.exportFailure(w, err)
		return
	}
	replyExportStatus(w, s)
}

func (a *Auth) retrieveExport(w http.ResponseWriter, r *http.Request, p store.Principal) {
	// net/http routes GET to HEAD too; do not count a request for metadata
	// as a package handoff.
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	id, ok := store.CanonicalID(r.PathValue("id"))
	if !ok {
		a.exportFailure(w, store.ErrNotFound)
		return
	}
	pck, err := a.Exports.Retrieve(r.Context(), p, id)
	if err != nil {
		a.exportFailure(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.charter.export-directory+json")
	w.Header().Set("Content-Disposition", `attachment; filename="charter-export.json"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Charter-Manifest-Digest", pck.ManifestDigest)
	_, _ = w.Write(pck.DirectoryJSON)
}

func (a *Auth) cancelExport(w http.ResponseWriter, r *http.Request, p store.Principal) {
	id, ok := store.CanonicalID(r.PathValue("id"))
	if !ok {
		a.exportFailure(w, store.ErrNotFound)
		return
	}
	if err := a.Exports.Cancel(r.Context(), p, id); err != nil {
		a.exportFailure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
