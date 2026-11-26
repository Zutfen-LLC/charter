package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// Option extends the base mux.
type Option func(*http.ServeMux)

// Auth is the authenticated API. Every /v1 route is registered through
// Auth.route, which wraps the handler in authentication; there is no other way
// to add a data route, and TestEveryRouteRequiresAuthentication enforces it.
type Auth struct {
	Verifier *oidc.Verifier
	Store    *store.Store
	// Work performs the (stub) model call. It runs with the caller's request
	// context. Default returns a fixed string; tests inject slow or revoking work.
	Work func(ctx context.Context, p store.Principal, projectID string) (string, error)
	// WorkTimeout is the deadline placed on Work's context. It is COOPERATIVE:
	// the handler cannot preempt Work, so a non-cooperating adapter can run
	// longer. What it does guarantee is that output produced after the deadline
	// (or after cancellation) is never released. Enforcing a real execution bound
	// is the adapter's job (#5). Default 60s.
	WorkTimeout time.Duration
	// ReleaseCheckTimeout bounds the single release-time authorization query.
	// If it cannot finish in time the call fails closed with no output. Default 2s.
	ReleaseCheckTimeout time.Duration
	Logf                func(format string, a ...any)
	// Evidence is the durable evidence write path (#4). Model calls REQUIRE it:
	// if it is nil the call is refused (503) before any model work, so a missing
	// or misconfigured evidence store can never produce an unrecorded answer.
	Evidence *evidence.Recorder
	Budget   func(context.Context, string, string) (evidence.BudgetSummary, error)
	// Model performs the outbound call with the exact sealed request bytes. If
	// nil, Work is used (the legacy stub, which ignores the request bytes).
	Model evidence.ModelFunc

	routes []string // every registered pattern, for tests
}

// WithAuth mounts the /v1 API.
func WithAuth(a *Auth) Option {
	if a.Work == nil {
		a.Work = func(context.Context, store.Principal, string) (string, error) {
			return "stub response: no model adapter in this slice (#5)", nil
		}
	}
	if a.WorkTimeout == 0 {
		a.WorkTimeout = 60 * time.Second
	}
	if a.ReleaseCheckTimeout == 0 {
		a.ReleaseCheckTimeout = 2 * time.Second
	}
	if a.Logf == nil {
		a.Logf = log.Printf
	}
	return func(mux *http.ServeMux) {
		a.route(mux, "GET /v1/me", a.me)
		a.route(mux, "GET /v1/projects", a.listProjects)
		a.route(mux, "GET /v1/search", a.search)
		a.route(mux, "GET /v1/projects/{pid}/artifacts", a.member(a.listArtifacts))
		a.route(mux, "POST /v1/projects/{pid}/model-calls", a.member(a.modelCall))
		if a.Budget != nil {
			a.route(mux, "GET /v1/projects/{pid}/usage", a.projectUsage)
		}
		a.route(mux, "GET /v1/artifacts/{id}", a.getArtifact)
		a.route(mux, "GET /v1/artifacts/{id}/content", a.getArtifact)

		// Tenant administration: membership and roles. No content access.
		a.route(mux, "PUT /v1/projects/{pid}/members/{uid}", a.admin(a.changeMember(true)))
		a.route(mux, "DELETE /v1/projects/{pid}/members/{uid}", a.admin(a.changeMember(false)))
		a.route(mux, "PUT /v1/users/{uid}/roles/{role}", a.admin(a.changeRole(true)))
		a.route(mux, "DELETE /v1/users/{uid}/roles/{role}", a.admin(a.changeRole(false)))
		a.route(mux, "POST /v1/users/{uid}/disable", a.admin(a.disableUser))

		// Records and export capabilities. Authorization is enforced now; the
		// operations themselves arrive with #7/#8 and answer 501 after authz.
		a.route(mux, "POST /v1/holds", a.role(store.RoleRecordsOfficer, notImplemented))
		a.route(mux, "POST /v1/holds/{id}/release", a.role(store.RoleRecordsOfficer, notImplemented))
		a.route(mux, "POST /v1/exports", a.role(store.RoleRecordsOfficer, notImplemented))
		a.route(mux, "POST /v1/exports/{id}/approve", a.role(store.RoleExportReviewer, notImplemented))
	}
}

type handler func(http.ResponseWriter, *http.Request, store.Principal)

func (a *Auth) route(mux *http.ServeMux, pattern string, h handler) {
	a.routes = append(a.routes, pattern)
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		p, ok := a.authenticate(w, r)
		if !ok {
			return
		}
		h(w, r, p)
	})
}

// authenticate trusts only a validated Bearer token. Identity headers, cookies,
// query parameters and email addresses are never consulted.
func (a *Auth) authenticate(w http.ResponseWriter, r *http.Request) (store.Principal, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		deny(w, http.StatusUnauthorized, "unauthenticated")
		return store.Principal{}, false
	}
	id, err := a.Verifier.Verify(r.Context(), strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		a.Logf("auth: %v", err)
		deny(w, http.StatusUnauthorized, "unauthenticated")
		return store.Principal{}, false
	}
	p, err := a.Store.Resolve(r.Context(), id.Issuer, id.TenantID, id.Subject)
	switch {
	case errors.Is(err, store.ErrNotProvisioned):
		deny(w, http.StatusForbidden, "forbidden")
		return store.Principal{}, false
	case err != nil:
		a.Logf("auth: resolve: %v", err)
		deny(w, http.StatusServiceUnavailable, "unavailable") // fail closed
		return store.Principal{}, false
	}
	return p, true
}

// member requires membership of the {pid} project, checked against the database.
func (a *Auth) member(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		ok, err := a.Store.IsMember(r.Context(), p, r.PathValue("pid"))
		if err != nil {
			a.fail(w, err)
			return
		}
		if !ok {
			deny(w, http.StatusNotFound, "not found") // same as nonexistent
			return
		}
		h(w, r, p)
	}
}

// role requires a tenant role, re-read from the database (not from the
// Principal snapshot) so a just-revoked role stops working immediately.
func (a *Auth) role(role string, h handler) handler {
	return func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		ok, err := a.Store.HasRole(r.Context(), p, role)
		if err != nil {
			a.fail(w, err)
			return
		}
		if !ok {
			deny(w, http.StatusForbidden, "forbidden")
			return
		}
		h(w, r, p)
	}
}

func (a *Auth) admin(h handler) handler { return a.role(store.RoleTenantAdmin, h) }

func (a *Auth) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		deny(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrForbidden):
		deny(w, http.StatusForbidden, "forbidden")
	default:
		a.Logf("internal: %v", err)
		deny(w, http.StatusServiceUnavailable, "unavailable")
	}
}

func deny(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func notImplemented(w http.ResponseWriter, _ *http.Request, _ store.Principal) {
	deny(w, http.StatusNotImplemented, "not implemented in this slice")
}

func (a *Auth) me(w http.ResponseWriter, _ *http.Request, p store.Principal) {
	roles := []string{}
	for r := range p.Roles {
		roles = append(roles, r)
	}
	writeJSON(w, 200, map[string]any{"user_id": p.UserID, "tenant_id": p.TenantID, "roles": roles})
}

func (a *Auth) listProjects(w http.ResponseWriter, r *http.Request, p store.Principal) {
	v, err := a.Store.ListProjects(r.Context(), p)
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *Auth) listArtifacts(w http.ResponseWriter, r *http.Request, p store.Principal) {
	v, err := a.Store.ListArtifacts(r.Context(), p, r.PathValue("pid"), r.URL.Query().Get("q"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *Auth) search(w http.ResponseWriter, r *http.Request, p store.Principal) {
	v, err := a.Store.Search(r.Context(), p, r.URL.Query().Get("q"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *Auth) getArtifact(w http.ResponseWriter, r *http.Request, p store.Principal) {
	v, err := a.Store.GetArtifact(r.Context(), p, r.PathValue("id"))
	if err != nil {
		a.fail(w, err)
		return
	}
	writeJSON(w, 200, v)
}

func (a *Auth) changeMember(add bool) handler {
	return func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		var err error
		if add {
			err = a.Store.AddMember(r.Context(), p, r.PathValue("pid"), r.PathValue("uid"))
		} else {
			err = a.Store.RemoveMember(r.Context(), p, r.PathValue("pid"), r.PathValue("uid"))
		}
		a.done(w, err)
	}
}

func (a *Auth) changeRole(grant bool) handler {
	return func(w http.ResponseWriter, r *http.Request, p store.Principal) {
		var err error
		if grant {
			err = a.Store.GrantRole(r.Context(), p, r.PathValue("uid"), r.PathValue("role"))
		} else {
			err = a.Store.RevokeRole(r.Context(), p, r.PathValue("uid"), r.PathValue("role"))
		}
		a.done(w, err)
	}
}

func (a *Auth) disableUser(w http.ResponseWriter, r *http.Request, p store.Principal) {
	a.done(w, a.Store.DisableUser(r.Context(), p, r.PathValue("uid")))
}

func (a *Auth) done(w http.ResponseWriter, err error) {
	if err != nil {
		a.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
