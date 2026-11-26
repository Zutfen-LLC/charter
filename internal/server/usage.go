package server

import (
	"errors"
	"net/http"

	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

func (a *Auth) projectUsage(w http.ResponseWriter, r *http.Request, p store.Principal) {
	id, valid := store.CanonicalID(r.PathValue("pid"))
	if !valid {
		deny(w, http.StatusNotFound, "not found")
		return
	}
	allowed, err := a.Store.MayReadUsage(r.Context(), p, id)
	if err != nil {
		deny(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if !allowed {
		deny(w, http.StatusNotFound, "not found")
		return
	}
	result, err := a.Budget(r.Context(), p.TenantID, id)
	if errors.Is(err, pgx.ErrNoRows) {
		deny(w, http.StatusNotFound, "not found")
		return
	}
	if err != nil {
		deny(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	allowed, err = a.Store.MayReadUsage(r.Context(), p, id)
	if err != nil {
		deny(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if !allowed {
		deny(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
