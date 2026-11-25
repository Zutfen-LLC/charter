package server

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

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

// modelCall guarantees, in order:
//
//  1. Entry: authenticated and a project member (route wrapper + a.member).
//  2. Work runs under a deadline derived from the request context. The deadline
//     is COOPERATIVE: the handler cannot preempt Work, so a non-cooperating
//     adapter can still run past it. The real execution bound must come from the
//     adapter's own enforced timeouts (#5). No goroutine is started; Work runs
//     on the request goroutine.
//  3. First gate: if the work context is already done the output is dropped.
//  4. Authorization (the linearization point): ONE authoritative query,
//     "user active AND member of project", on committed state. It runs on its
//     own context bounded by ReleaseCheckTimeout, so cancelling the request can
//     neither abort the check into an implicit allow nor leave it unbounded.
//     Revocations committed before the query reads are honoured; ones committed
//     after it are not reflected in this response. Any failure, including an
//     unavailable or too-slow database, returns no output.
//  5. Final gate, immediately before the output is written: the work context is
//     checked again. A cancellation or deadline that occurred while the query
//     was running therefore still prevents release (504 deadline / 503
//     cancelled), whatever the query returned.
//
// Between step 5 and the response write only the in-process write remains; the
// guarantee is "no output is released once the work context is known to be
// done", not hard preemption. Output the adapter already disclosed to a provider
// cannot be recalled; ADR 0001 R1/R2 (durable intent before send, durable output
// record before release) attach to this same gate in #4/#5.
func (a *Auth) modelCall(w http.ResponseWriter, r *http.Request, p store.Principal) {
	pid := r.PathValue("pid")
	ctx, cancel := context.WithTimeout(r.Context(), a.WorkTimeout)
	defer cancel()
	out, err := a.Work(ctx, p, pid)
	if err != nil {
		a.fail(w, err)
		return
	}
	if workContextDone(w, ctx) {
		return
	}
	rc, rcancel := context.WithTimeout(context.Background(), a.ReleaseCheckTimeout)
	member, err := a.Store.IsMember(rc, p, pid) // includes the active-account predicate
	rcancel()
	if err != nil {
		a.Logf("model call release check: %v", err)
		deny(w, http.StatusServiceUnavailable, "unavailable")
		return
	}
	if !member {
		deny(w, http.StatusForbidden, "access revoked during request")
		return
	}
	if workContextDone(w, ctx) { // final gate: expiry/cancellation during the query
		return
	}
	writeJSON(w, 200, map[string]string{"output": out})
}

// workContextDone writes the refusal and returns true if the work context has
// expired (504) or been cancelled (503).
func workContextDone(w http.ResponseWriter, ctx context.Context) bool {
	cerr := ctx.Err()
	if cerr == nil {
		return false
	}
	if errors.Is(cerr, context.DeadlineExceeded) {
		deny(w, http.StatusGatewayTimeout, "work deadline exceeded")
	} else {
		deny(w, http.StatusServiceUnavailable, "request cancelled")
	}
	return true
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
