package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

const idpTenant, audience = "tenant-a", "charter-test"

// env is two isolated projects (P1, P2) in one tenant, distinct users, and the
// privileged roles. Synthetic data only.
type env struct {
	t        *testing.T
	idp      *syntheticidp.IdP
	st       *store.Store
	auth     *Auth
	h        http.Handler
	tenant   string
	p1, p2   string
	a1, a2   string // artifacts in P1 / P2
	users    map[string]string
	otherTen string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool := testdb.New(t)
	idp := syntheticidp.New(audience, idpTenant)
	t.Cleanup(idp.Server.Close)
	st := &store.Store{DB: pool}
	ctx := context.Background()
	e := &env{t: t, idp: idp, st: st, users: map[string]string{}}
	must := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	e.tenant = must(st.CreateTenant(ctx, idp.Issuer, idpTenant, "tenant-a"))
	e.otherTen = must(st.CreateTenant(ctx, idp.Issuer, "tenant-b", "tenant-b"))
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin", "frank"} {
		e.users[n] = must(st.CreateUser(ctx, e.tenant, "sub-"+n, n))
	}
	e.users["zed"] = must(st.CreateUser(ctx, e.otherTen, "sub-zed", "zed (other tenant)"))
	e.p1 = must(st.CreateProject(ctx, e.tenant, "P1"))
	e.p2 = must(st.CreateProject(ctx, e.tenant, "P2"))
	e.a1 = must(st.CreateArtifact(ctx, e.tenant, e.p1, "P1 memo", "needle-one alpha"))
	e.a2 = must(st.CreateArtifact(ctx, e.tenant, e.p2, "P2 memo", "needle-two secret-beta"))
	for u, p := range map[string]string{"alice": e.p1, "bob": e.p2} {
		if err := st.SeedMember(ctx, e.tenant, p, e.users[u]); err != nil {
			t.Fatal(err)
		}
	}
	for u, r := range map[string]string{"carol": store.RoleTenantAdmin, "dave": store.RoleRecordsOfficer,
		"erin": store.RoleExportReviewer, "frank": store.RoleOperator} {
		if err := st.SeedRole(ctx, e.tenant, e.users[u], r); err != nil {
			t.Fatal(err)
		}
	}
	v, err := oidc.NewVerifier(oidc.Config{Issuer: idp.Issuer, Audience: audience, TenantID: idpTenant, RequiredScope: idp.Scope,
		Keys: &oidc.JWKSFetcher{URL: idp.JWKSURL(), AllowLoopbackHTTP: true}})
	if err != nil {
		t.Fatal(err)
	}
	e.auth = &Auth{Verifier: v, Store: st, Logf: func(string, ...any) {},
		Evidence: &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: StubPolicy()}}
	e.h = New(pool, TestFixtureBackend(), WithAuth(e.auth))
	return e
}

func (e *env) do(method, path, token string, hdr ...string) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func (e *env) as(user, method, path string) (int, string) {
	return e.do(method, path, e.idp.Token("sub-"+user))
}

func (e *env) want(user, method, path string, code int) string {
	e.t.Helper()
	got, body := e.as(user, method, path)
	if got != code {
		e.t.Fatalf("%s %s %s: got %d want %d (%s)", user, method, path, got, code, body)
	}
	return body
}

func TestProjectIsolation(t *testing.T) {
	e := newEnv(t)
	// Own project works.
	e.want("alice", "GET", "/v1/projects/"+e.p1+"/artifacts", 200)
	e.want("alice", "GET", "/v1/artifacts/"+e.a1, 200)
	e.want("bob", "GET", "/v1/artifacts/"+e.a2, 200)

	// Direct IDs, artifact URLs, project-scoped lists and model calls into the
	// other project are indistinguishable from nonexistent.
	e.want("alice", "GET", "/v1/artifacts/"+e.a2, 404)
	e.want("alice", "GET", "/v1/artifacts/"+e.a2+"/content", 404)
	e.want("alice", "GET", "/v1/projects/"+e.p2+"/artifacts", 404)
	e.want("alice", "POST", "/v1/projects/"+e.p2+"/model-calls", 404)
	e.want("bob", "GET", "/v1/artifacts/"+e.a1, 404)
	e.want("alice", "GET", "/v1/artifacts/00000000-0000-0000-0000-000000000000", 404)
	e.want("alice", "GET", "/v1/artifacts/not-a-uuid", 404)
	e.want("alice", "GET", "/v1/projects/'%20OR%201=1--/artifacts", 404)
	_, nonexist := e.as("alice", "GET", "/v1/artifacts/00000000-0000-0000-0000-000000000000")
	_, forbidden := e.as("alice", "GET", "/v1/artifacts/"+e.a2)
	if nonexist != forbidden {
		t.Fatalf("existence oracle: %q vs %q", nonexist, forbidden)
	}

	// Lists and search are filtered, not just guarded.
	if b := e.want("alice", "GET", "/v1/projects", 200); strings.Contains(b, e.p2) || !strings.Contains(b, e.p1) {
		t.Fatalf("project list leaks or misses: %s", b)
	}
	if b := e.want("alice", "GET", "/v1/search?q=needle", 200); strings.Contains(b, e.a2) || !strings.Contains(b, e.a1) {
		t.Fatalf("search not filtered: %s", b)
	}
	if b := e.want("alice", "GET", "/v1/search?q=secret-beta", 200); strings.Contains(b, e.a2) {
		t.Fatalf("search matched other project's body: %s", b)
	}
	if b := e.want("alice", "GET", "/v1/search?q=%25", 200); strings.Contains(b, e.a2) {
		t.Fatalf("LIKE wildcard widened results: %s", b)
	}
	if b := e.want("alice", "GET", "/v1/projects/"+e.p1+"/artifacts?q=secret-beta", 200); strings.Contains(b, e.a2) {
		t.Fatal("scoped search leaked")
	}
}

func TestPrivilegedRolesHaveNoImplicitReadThrough(t *testing.T) {
	e := newEnv(t)
	for _, u := range []string{"carol", "dave", "erin", "frank"} { // admin, records, export, operator
		e.want(u, "GET", "/v1/artifacts/"+e.a1, 404)
		e.want(u, "GET", "/v1/projects/"+e.p1+"/artifacts", 404)
		e.want(u, "POST", "/v1/projects/"+e.p1+"/model-calls", 404)
		if b := e.want(u, "GET", "/v1/search?q=needle", 200); strings.Contains(b, "memo") {
			t.Fatalf("%s sees content through search: %s", u, b)
		}
		if b := e.want(u, "GET", "/v1/projects", 200); strings.Contains(b, e.p1) {
			t.Fatalf("%s lists projects without membership", u)
		}
	}
}

func TestRoleSeparationAndNegativePaths(t *testing.T) {
	e := newEnv(t)
	// Ordinary member: no hold/export/admin operation.
	for _, c := range [][2]string{
		{"POST", "/v1/holds"}, {"POST", "/v1/holds/x/release"}, {"POST", "/v1/exports"},
		{"POST", "/v1/exports/x/approve"},
		{"PUT", "/v1/projects/" + e.p2 + "/members/" + e.users["alice"]},
		{"PUT", "/v1/users/" + e.users["alice"] + "/roles/records_officer"},
		{"POST", "/v1/users/" + e.users["bob"] + "/disable"},
	} {
		e.want("alice", c[0], c[1], 403)
	}
	// Each capability is its own role: records can hold/request, not approve; export approves, not holds.
	e.want("dave", "POST", "/v1/holds", 501) // authorized; operation lands in #7
	e.want("dave", "POST", "/v1/exports", 501)
	e.want("dave", "POST", "/v1/exports/x/approve", 403)
	e.want("erin", "POST", "/v1/exports/x/approve", 501)
	e.want("erin", "POST", "/v1/holds", 403)
	e.want("erin", "POST", "/v1/exports", 403)
	// Admin has neither records nor export capability, and operator has no approvals.
	e.want("carol", "POST", "/v1/holds", 403)
	e.want("carol", "POST", "/v1/exports/x/approve", 403)
	e.want("frank", "POST", "/v1/holds", 403)
	e.want("frank", "PUT", "/v1/users/"+e.users["frank"]+"/roles/tenant_admin", 403)

	// Admin cannot self-grant records/export roles, but may grant others.
	e.want("carol", "PUT", "/v1/users/"+e.users["carol"]+"/roles/records_officer", 403)
	e.want("carol", "PUT", "/v1/users/"+e.users["carol"]+"/roles/export_reviewer", 403)
	e.want("carol", "PUT", "/v1/users/"+e.users["alice"]+"/roles/records_officer", 204)
	e.want("alice", "POST", "/v1/holds", 501)
	// The last tenant_admin cannot be removed; unknown roles are rejected.
	e.want("carol", "DELETE", "/v1/users/"+e.users["carol"]+"/roles/tenant_admin", 403)
	e.want("carol", "PUT", "/v1/users/"+e.users["alice"]+"/roles/god", 404)
}

func TestForgedIdentityAndTenantClaimsAreRefused(t *testing.T) {
	e := newEnv(t)
	attacker, _ := rsa.GenerateKey(rand.Reader, 2048)
	path := "/v1/artifacts/" + e.a1
	cases := map[string]string{
		"wrong-tenant claim for alice's subject": e.idp.Mint(syntheticidp.Claims{Subject: "sub-alice", Tenant: "tenant-b"}),
		"alice's subject, attacker key":          e.idp.Mint(syntheticidp.Claims{Subject: "sub-alice", SignWith: attacker}),
		"alice's subject, alg none":              e.idp.Mint(syntheticidp.Claims{Subject: "sub-alice", Alg: "none"}),
		"alice's subject, wrong issuer":          e.idp.Mint(syntheticidp.Claims{Subject: "sub-alice", Issuer: "https://evil.example"}),
		"tid smuggled via extra claim":           e.idp.Mint(syntheticidp.Claims{Subject: "sub-alice", Extra: map[string]any{"tid": "tenant-b"}}),
	}
	for name, tok := range cases {
		if code, _ := e.do("GET", path, tok); code != 401 {
			t.Errorf("%s: got %d want 401", name, code)
		}
	}
	// A valid token for the other tenant's user, minted for the wrong tenant id, is refused;
	// and a user who exists only in tenant-b cannot be reached through tenant-a's claim.
	if code, _ := e.do("GET", path, e.idp.Token("sub-zed")); code != 403 {
		t.Errorf("tenant-b subject presented with tenant-a claim: got %d want 403", code)
	}
	// Unknown subject, even carrying alice's email, is not provisioned.
	if code, _ := e.do("GET", path, e.idp.Mint(syntheticidp.Claims{Subject: "sub-mallory", Email: "alice@example.test"})); code != 403 {
		t.Errorf("email spoof: got %d want 403", code)
	}
	// User-supplied identity headers and query parameters are ignored entirely.
	if code, _ := e.do("GET", path, "", "X-User-Id", e.users["alice"], "X-Forwarded-User", "sub-alice",
		"X-Forwarded-Email", "alice@example.test", "X-Tenant-Id", e.tenant); code != 401 {
		t.Errorf("identity headers accepted: %d", code)
	}
	if code, _ := e.do("GET", path+"?user_id="+e.users["alice"]+"&tenant_id="+e.tenant, ""); code != 401 {
		t.Errorf("identity query params accepted: %d", code)
	}
	// Headers cannot upgrade a real token's identity either.
	code, body := e.do("GET", "/v1/artifacts/"+e.a2, e.idp.Token("sub-alice"), "X-User-Id", e.users["bob"])
	if code != 404 {
		t.Errorf("header override: %d %s", code, body)
	}
}

func TestEveryRouteRequiresAuthentication(t *testing.T) {
	e := newEnv(t)
	if len(e.auth.routes) < 10 {
		t.Fatalf("route registry looks empty: %v", e.auth.routes)
	}
	for _, pat := range e.auth.routes {
		parts := strings.SplitN(pat, " ", 2)
		path := strings.NewReplacer("{pid}", e.p1, "{id}", e.a1, "{uid}", e.users["alice"], "{role}", "operator").Replace(parts[1])
		for _, tok := range []string{"", "garbage", "a.b.c"} {
			if code, _ := e.do(parts[0], path, tok); code != 401 {
				t.Errorf("%s with token %q: got %d want 401", pat, tok, code)
			}
		}
	}
	// Anything not registered is not served (no accidental fall-through routes).
	if code, _ := e.do("GET", "/v1/unregistered", e.idp.Token("sub-alice")); code != 404 {
		t.Errorf("unregistered route: %d", code)
	}
}

func TestRevocationBlocksNextReadAndModelCall(t *testing.T) {
	e := newEnv(t)
	tok := e.idp.Token("sub-alice") // one still-valid token ("cached session") throughout
	get := func(path string) int { c, _ := e.do("GET", path, tok); return c }
	post := func(path string) int { c, _ := e.do("POST", path, tok); return c }

	if get("/v1/artifacts/"+e.a1) != 200 || post("/v1/projects/"+e.p1+"/model-calls") != 200 {
		t.Fatal("baseline access failed")
	}
	// Membership removed by the admin: the very next call is denied with the same token.
	e.want("carol", "DELETE", "/v1/projects/"+e.p1+"/members/"+e.users["alice"], 204)
	if c := get("/v1/artifacts/" + e.a1); c != 404 {
		t.Fatalf("read after membership revoke: %d", c)
	}
	if c := post("/v1/projects/" + e.p1 + "/model-calls"); c != 404 {
		t.Fatalf("model call after membership revoke: %d", c)
	}
	if _, b := e.do("GET", "/v1/search?q=needle", tok); strings.Contains(b, e.a1) {
		t.Fatal("search after revoke")
	}
	// Re-add, then disable the account: everything is refused, including /me.
	e.want("carol", "PUT", "/v1/projects/"+e.p1+"/members/"+e.users["alice"], 204)
	if get("/v1/artifacts/"+e.a1) != 200 {
		t.Fatal("re-add failed")
	}
	e.want("carol", "POST", "/v1/users/"+e.users["alice"]+"/disable", 204)
	for _, p := range []string{"/v1/me", "/v1/artifacts/" + e.a1, "/v1/projects"} {
		if c := get(p); c != 403 {
			t.Fatalf("disabled user %s: %d", p, c)
		}
	}
	// A role revoked is gone at once for the next request.
	e.want("carol", "DELETE", "/v1/users/"+e.users["dave"]+"/roles/records_officer", 204)
	e.want("dave", "POST", "/v1/holds", 403)
}

func TestRevocationDuringLongRunningModelCallDiscardsOutput(t *testing.T) {
	e := newEnv(t)
	e.auth.Work = func(ctx context.Context, p store.Principal, pid string) (string, error) {
		// Admin revokes while the call is in flight.
		admin, _ := e.st.Resolve(ctx, e.idp.Issuer, idpTenant, "sub-carol")
		if err := e.st.RemoveMember(ctx, admin, pid, p.UserID); err != nil {
			t.Error(err)
		}
		return "SENSITIVE-OUTPUT", nil
	}
	code, body := e.as("alice", "POST", "/v1/projects/"+e.p1+"/model-calls")
	if code != 403 || strings.Contains(body, "SENSITIVE") {
		t.Fatalf("output released after revocation: %d %s", code, body)
	}
}

func TestCrossTenantIsolationInDatabaseAndAdminAPI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Composite FKs refuse cross-tenant rows regardless of application bugs.
	if err := e.st.SeedMember(ctx, e.tenant, e.p1, e.users["zed"]); err == nil {
		t.Fatal("cross-tenant membership accepted by the database")
	}
	if _, err := e.st.CreateArtifact(ctx, e.otherTen, e.p1, "x", "y"); err == nil {
		t.Fatal("cross-tenant artifact accepted by the database")
	}
	// Admin API cannot reach other-tenant users.
	e.want("carol", "PUT", "/v1/projects/"+e.p1+"/members/"+e.users["zed"], 404)
	e.want("carol", "PUT", "/v1/users/"+e.users["zed"]+"/roles/operator", 404)
	e.want("carol", "POST", "/v1/users/"+e.users["zed"]+"/disable", 404)
}

func TestAuditTrailRecordsChangesAndIsAppendOnly(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.want("carol", "PUT", "/v1/projects/"+e.p1+"/members/"+e.users["bob"], 204)
	e.want("carol", "PUT", "/v1/users/"+e.users["bob"]+"/roles/operator", 204)
	e.want("carol", "DELETE", "/v1/users/"+e.users["bob"]+"/roles/operator", 204)
	rows, err := e.st.DB.Query(ctx, `SELECT action, actor_id::text, detail FROM audit_log ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var actions []string
	for rows.Next() {
		var a, actor string
		var d json.RawMessage
		if err := rows.Scan(&a, &actor, &d); err != nil {
			t.Fatal(err)
		}
		if actor != e.users["carol"] {
			t.Fatalf("actor %s", actor)
		}
		actions = append(actions, a)
	}
	rows.Close()
	if strings.Join(actions, ",") != "project_member.add,tenant_role.grant,tenant_role.revoke" {
		t.Fatalf("audit actions: %v", actions)
	}
	for _, q := range []string{`UPDATE audit_log SET action='x'`, `DELETE FROM audit_log`, `TRUNCATE audit_log`} {
		if _, err := e.st.DB.Exec(ctx, q); err == nil {
			t.Fatalf("audit_log allowed: %s", q)
		}
	}
	// Denied attempts leave no audit rows or state changes.
	e.want("alice", "PUT", "/v1/users/"+e.users["alice"]+"/roles/records_officer", 403)
	if ok, _ := e.st.HasRole(ctx, store.Principal{UserID: e.users["alice"], TenantID: e.tenant}, store.RoleRecordsOfficer); ok {
		t.Fatal("denied grant took effect")
	}
}

func TestUnconfiguredServerServesNoDataRoutes(t *testing.T) {
	h := New(fakeDB{}, TestFixtureBackend())
	for _, p := range []string{"/v1/projects", "/v1/search?q=x", "/v1/me"} {
		if rec := get(t, h, p); rec.Code != 404 {
			t.Errorf("%s served without auth wiring: %d", p, rec.Code)
		}
	}
}
