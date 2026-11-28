package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

// recordsGuard refuses every lifecycle route when the records service is not
// configured in this slice (the operation then stays 501 after
// authorization, exactly as before C07).
func (a *Auth) recordsGuard(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		if a.Records == nil {
			notImplemented(w, r, p)
			return
		}
		h(w, r, p)
	}
}

type holdRequest struct {
	MatterID     string   `json:"matter_id"`
	CustodianIDs []string `json:"custodian_ids"`
	WindowStart  *string  `json:"window_start"`
	WindowEnd    *string  `json:"window_end"`
	Reason       string   `json:"reason"`
}

func parseWindow(v *string) (*time.Time, error) {
	if v == nil || *v == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339Nano, *v)
	if err != nil || t.IsZero() {
		return nil, store.ErrNotFound
	}
	u := t.UTC()
	return &u, nil
}

func (a *Auth) decode(r *http.Request, into any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return store.ErrForbidden
	}
	if len(body) == 0 {
		return store.ErrNotFound
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return store.ErrNotFound
	}
	if dec.More() {
		return store.ErrNotFound
	}
	return nil
}

func (a *Auth) placeHold(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var req holdRequest
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	ws, err := parseWindow(req.WindowStart)
	if err != nil {
		a.fail(w, err)
		return
	}
	we, err := parseWindow(req.WindowEnd)
	if err != nil {
		a.fail(w, err)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		deny(w, http.StatusBadRequest, "idempotency key required")
		return
	}
	h, err := a.Records.Place(r.Context(), p, records.Scope{
		MatterID: req.MatterID, CustodianIDs: req.CustodianIDs, WindowStart: ws, WindowEnd: we,
	}, req.Reason, key)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (a *Auth) getHold(w http.ResponseWriter, r *http.Request, p store.Principal) {
	h, err := a.Records.Store.GetHold(r.Context(), p, r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (a *Auth) listHolds(w http.ResponseWriter, r *http.Request, p store.Principal) {
	hs, err := a.Records.Store.ListHolds(r.Context(), p)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"holds": hs})
}

func (a *Auth) releaseHold(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	h, err := a.Records.Release(r.Context(), p, r.PathValue("id"), req.Reason)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, h)
}

func (a *Auth) changeHold(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var req holdRequest
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	ws, err := parseWindow(req.WindowStart)
	if err != nil {
		a.fail(w, err)
		return
	}
	we, err := parseWindow(req.WindowEnd)
	if err != nil {
		a.fail(w, err)
		return
	}
	h, err := a.Records.Store.ChangeScope(r.Context(), p, r.PathValue("id"), records.Scope{
		MatterID: req.MatterID, CustodianIDs: req.CustodianIDs, WindowStart: ws, WindowEnd: we,
	}, req.Reason)
	if err != nil {
		a.fail(w, err)
		return
	}
	// A changed scope re-establishes protection before it may report
	// effective for the new scope (same two-phase rule as placement).
	if h.State == records.HoldPending {
		report, err := a.Records.Reestablish(r.Context(), h)
		if err != nil {
			a.fail(w, err)
			return
		}
		_ = report
		h, err = a.Records.Store.GetHold(r.Context(), p, r.PathValue("id"))
		if err != nil {
			a.fail(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, h)
}

func (a *Auth) setPolicy(w http.ResponseWriter, r *http.Request, p store.Principal) {
	var req struct {
		RetentionSeconds int64 `json:"retention_seconds"`
		GraceSeconds     int64 `json:"grace_seconds"`
	}
	if err := a.decode(r, &req); err != nil {
		a.fail(w, err)
		return
	}
	if err := a.Records.Store.SetPolicy(r.Context(), p, req.RetentionSeconds, req.GraceSeconds); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) sweep(w http.ResponseWriter, r *http.Request, p store.Principal) {
	// The service-level sweep requires a verified terminal capture state for
	// disposal eligibility: an admitted, actively executing turn is never
	// swept (C07 review finding 6A).
	marked, err := a.Records.Sweep(r.Context(), p)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"swept": marked})
}

func (a *Auth) listItems(w http.ResponseWriter, r *http.Request, p store.Principal) {
	items, err := a.Records.Store.Items(r.Context(), p)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (a *Auth) purgeBegin(w http.ResponseWriter, r *http.Request, p store.Principal) {
	if !a.Records.Retained {
		deny(w, http.StatusConflict, "disposal not supported by this evidence backend")
		return
	}
	// Presence is classified, never guessed: a storage failure surfaces as
	// an error (never as proof of disposal) and only plan-verified absence
	// may complete a disposal (C07 review finding 4).
	outcome, err := a.Records.Store.BeginPurge(r.Context(), p, r.PathValue("turn"), func(ctx context.Context, tx pgx.Tx, turnID string) (bool, error) {
		// Classify presence through the transaction's connection: the
		// callback runs inside BeginPurge's transaction, and a second
		// pooled acquisition here deadlocks the pool under exhaustion
		// (the same defect the finisher fix removed).
		switch a.Records.PresenceClassifiedIn(ctx, tx, p.TenantID, turnID) {
		case records.PresencePresent, records.PresencePartial:
			return true, nil
		case records.PresenceAbsent:
			return false, nil
		default:
			return false, fmt.Errorf("records: presence unresolved for %s", turnID)
		}
	})
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outcome": outcome})
}

func (a *Auth) purgeFinish(w http.ResponseWriter, r *http.Request, p store.Principal) {
	outcome, versions, err := a.Records.FinishPurge(r.Context(), &p, r.PathValue("turn"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"outcome": outcome, "versions": versions})
}

// itemDetail returns lifecycle metadata (records officers may view evidence
// metadata; content access is a separate held-only endpoint).
func (a *Auth) itemDetail(w http.ResponseWriter, r *http.Request, p store.Principal) {
	items, err := a.Records.Store.Items(r.Context(), p)
	if err != nil {
		a.fail(w, err)
		return
	}
	for _, it := range items {
		if it.TurnID == r.PathValue("turn") {
			writeJSON(w, http.StatusOK, it)
			return
		}
	}
	deny(w, http.StatusNotFound, "not found")
}

// itemEvents returns the evidence event log of a HELD item for records
// officers only: non-held matters get metadata only, tombstoned and disposed
// items are unreadable, and hold administration never widens any other
// role's access.
func (a *Auth) itemEvents(w http.ResponseWriter, r *http.Request, p store.Principal) {
	held, it, err := a.Records.ItemHeld(r.Context(), p, r.PathValue("turn"))
	if err != nil {
		a.fail(w, err)
		return
	}
	if !held || it.State == records.ItemPurging || it.State == records.ItemDisposed {
		deny(w, http.StatusForbidden, "evidence content requires a held item")
		return
	}
	if a.Evidence == nil || a.Evidence.Backend == nil {
		deny(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	events, err := a.Evidence.Backend.Load(r.Context(), p.TenantID, it.TurnID)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (a *Auth) itemObject(w http.ResponseWriter, r *http.Request, p store.Principal) {
	held, it, err := a.Records.ItemHeld(r.Context(), p, r.PathValue("turn"))
	if err != nil {
		a.fail(w, err)
		return
	}
	if !held || it.State == records.ItemPurging || it.State == records.ItemDisposed {
		deny(w, http.StatusForbidden, "evidence content requires a held item")
		return
	}
	if a.Evidence == nil || a.Evidence.Backend == nil {
		deny(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	data, err := a.Evidence.Backend.Object(r.Context(), p.TenantID, "sha256:"+pathTail(r.PathValue("sha")))
	if err != nil {
		a.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(data)
}

func (a *Auth) deleteArtifact(w http.ResponseWriter, r *http.Request, p store.Principal) {
	if err := a.Store.DeleteArtifact(r.Context(), p, r.PathValue("id")); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *Auth) deleteProject(w http.ResponseWriter, r *http.Request, p store.Principal) {
	if err := a.Store.DeleteProject(r.Context(), p, r.PathValue("pid")); err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func pathTail(s string) string {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return s[i+1:]
		}
	}
	return s
}
