package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

const issuer = "https://idp.test"

type fx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	st     *store.Store
	tenant string
	other  string // second tenant
	u      map[string]string
	p1, p2 string
	a1, a2 string
	pOther string
	aOther string
}

// newFx: tenant A has admins carol/dave, users alice/bob, projects P1/P2;
// tenant B has zed with its own project and artifact. Synthetic data only.
func newFx(t *testing.T) *fx {
	t.Helper()
	pool := testdb.New(t)
	ctx := context.Background()
	st := &store.Store{DB: pool}
	f := &fx{t: t, pool: pool, st: st, u: map[string]string{}}
	ok := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	f.tenant = ok(st.CreateTenant(ctx, issuer, "tid-a", "A"))
	f.other = ok(st.CreateTenant(ctx, issuer, "tid-b", "B"))
	for _, n := range []string{"alice", "bob", "carol", "dave", "erin"} {
		f.u[n] = ok(st.CreateUser(ctx, f.tenant, "sub-"+n, n))
	}
	f.u["zed"] = ok(st.CreateUser(ctx, f.other, "sub-zed", "zed"))
	f.p1 = ok(st.CreateProject(ctx, f.tenant, "P1"))
	f.p2 = ok(st.CreateProject(ctx, f.tenant, "P2"))
	f.pOther = ok(st.CreateProject(ctx, f.other, "PB"))
	f.a1 = ok(st.CreateArtifact(ctx, f.tenant, f.p1, "P1 memo", "needle alpha"))
	f.a2 = ok(st.CreateArtifact(ctx, f.tenant, f.p2, "P2 memo", "needle beta"))
	f.aOther = ok(st.CreateArtifact(ctx, f.other, f.pOther, "PB memo", "needle gamma"))
	for _, m := range [][2]string{{"alice", f.p1}, {"bob", f.p2}} {
		if err := st.SeedMember(ctx, f.tenant, m[1], f.u[m[0]]); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SeedMember(ctx, f.other, f.pOther, f.u["zed"]); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"carol", "dave"} {
		if err := st.SeedRole(ctx, f.tenant, f.u[n], store.RoleTenantAdmin); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *fx) principal(name string) store.Principal {
	f.t.Helper()
	tid := "tid-a"
	if name == "zed" {
		tid = "tid-b"
	}
	p, err := f.st.Resolve(context.Background(), issuer, tid, "sub-"+name)
	if err != nil {
		f.t.Fatalf("resolve %s: %v", name, err)
	}
	return p
}

func (f *fx) exec(q string, a ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), q, a...); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fx) count(q string, a ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, a...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fx) activeAdmins() int {
	return f.count(`SELECT count(*) FROM tenant_roles r JOIN users u ON u.id=r.user_id
		WHERE r.tenant_id=$1 AND r.role='tenant_admin' AND u.disabled_at IS NULL`, f.tenant)
}

func (f *fx) grantAudits() int {
	return f.count(`SELECT count(*) FROM audit_log WHERE action='tenant_role.grant'`)
}

func mixedCase(s string) string {
	var b strings.Builder
	n := 0
	for _, c := range s {
		if c >= 'a' && c <= 'f' {
			if n%2 == 0 {
				c -= 'a' - 'A'
			}
			n++
		}
		b.WriteRune(c)
	}
	return b.String()
}

// ---- Finding 1: UUID representation ----------------------------------------

func TestUUIDRepresentationCannotBypassSelfGrant(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	carol := f.principal("carol")
	forms := map[string]string{
		"lower": f.u["carol"], "upper": strings.ToUpper(f.u["carol"]), "mixed": mixedCase(f.u["carol"]),
	}
	if forms["upper"] == forms["lower"] || forms["mixed"] == forms["lower"] {
		t.Fatal("fixture UUID has no letters to vary; regenerate")
	}
	for _, role := range []string{store.RoleRecordsOfficer, store.RoleExportReviewer} {
		for name, id := range forms {
			err := f.st.GrantRole(ctx, carol, id, role)
			if !errors.Is(err, store.ErrForbidden) {
				t.Errorf("self-grant %s as %s UUID: got %v, want ErrForbidden", role, name, err)
			}
		}
		if ok, _ := f.st.HasRole(ctx, carol, role); ok {
			t.Errorf("carol obtained %s by self-grant", role)
		}
	}
	if n := f.grantAudits(); n != 0 {
		t.Errorf("denied self-grants left %d successful-grant audit events", n)
	}

	// Legitimate grants still work: to another user, and by a different admin.
	if err := f.st.GrantRole(ctx, carol, mixedCase(f.u["alice"]), store.RoleRecordsOfficer); err != nil {
		t.Fatalf("grant to other user: %v", err)
	}
	dave := f.principal("dave")
	if err := f.st.GrantRole(ctx, dave, strings.ToUpper(f.u["carol"]), store.RoleExportReviewer); err != nil {
		t.Fatalf("grant to carol by a different admin: %v", err)
	}
	if n := f.grantAudits(); n != 2 {
		t.Errorf("want 2 audit events, got %d", n)
	}
	// Audit detail carries the canonical lowercase id even if the caller used uppercase.
	if n := f.count(`SELECT count(*) FROM audit_log WHERE detail->>'user_id' <> lower(detail->>'user_id')`); n != 0 {
		t.Errorf("%d audit rows with non-lowercase ids", n)
	}
}

func TestUUIDRepresentationsBehaveIdenticallyAcrossOperations(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	alice := f.principal("alice")
	for name, tr := range map[string]func(string) string{"lower": func(s string) string { return s },
		"upper": strings.ToUpper, "mixed": mixedCase} {
		if ok, err := f.st.IsMember(ctx, alice, tr(f.p1)); err != nil || !ok {
			t.Errorf("%s IsMember: %v %v", name, ok, err)
		}
		list, err := f.st.ListArtifacts(ctx, alice, tr(f.p1), "")
		if err != nil || len(list) != 1 {
			t.Errorf("%s ListArtifacts: %v %v", name, list, err)
		}
		if a, err := f.st.GetArtifact(ctx, alice, tr(f.a1)); err != nil || a.ID != f.a1 {
			t.Errorf("%s GetArtifact: %+v %v", name, a, err)
		}
		// Not a member of P2 in any representation.
		if ok, _ := f.st.IsMember(ctx, alice, tr(f.p2)); ok {
			t.Errorf("%s: alice is member of P2", name)
		}
		if list, _ := f.st.ListArtifacts(ctx, alice, tr(f.p2), ""); len(list) != 0 {
			t.Errorf("%s: P2 artifacts leaked", name)
		}
		if _, err := f.st.GetArtifact(ctx, alice, tr(f.a2)); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("%s: P2 artifact: %v", name, err)
		}
	}
	// Admin operations accept any representation and act on the same rows.
	carol := f.principal("carol")
	if err := f.st.AddMember(ctx, carol, strings.ToUpper(f.p2), strings.ToUpper(f.u["alice"])); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.st.IsMember(ctx, alice, f.p2); !ok {
		t.Fatal("upper-case AddMember did not create membership")
	}
	if err := f.st.RemoveMember(ctx, carol, mixedCase(f.p2), mixedCase(f.u["alice"])); err != nil {
		t.Fatal(err)
	}
	if ok, _ := f.st.IsMember(ctx, alice, f.p2); ok {
		t.Fatal("mixed-case RemoveMember did not remove membership")
	}
	if err := f.st.GrantRole(ctx, carol, strings.ToUpper(f.u["erin"]), store.RoleOperator); err != nil {
		t.Fatal(err)
	}
	if err := f.st.RevokeRole(ctx, carol, mixedCase(f.u["erin"]), store.RoleOperator); err != nil {
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM tenant_roles WHERE user_id=$1`, f.u["erin"]); n != 0 {
		t.Fatalf("erin retains %d roles", n)
	}
}

// ---- Finding 2: administrative invariants ----------------------------------

func TestSoleActiveAdminCannotBeDisabledOrRevoked(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.exec(`DELETE FROM tenant_roles WHERE user_id=$1`, f.u["dave"]) // carol is the only admin
	carol := f.principal("carol")
	if err := f.st.DisableUser(ctx, carol, f.u["carol"]); !errors.Is(err, store.ErrForbidden) {
		t.Errorf("disable sole admin: %v", err)
	}
	if err := f.st.RevokeRole(ctx, carol, f.u["carol"], store.RoleTenantAdmin); !errors.Is(err, store.ErrForbidden) {
		t.Errorf("revoke sole admin: %v", err)
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d", n)
	}
}

func TestDisabledAdminsDoNotCountTowardsLastAdmin(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.exec(`UPDATE users SET disabled_at=now() WHERE id=$1`, f.u["dave"]) // dave keeps the role row
	carol := f.principal("carol")
	if err := f.st.RevokeRole(ctx, carol, f.u["carol"], store.RoleTenantAdmin); !errors.Is(err, store.ErrForbidden) {
		t.Errorf("revoke last ACTIVE admin while a disabled admin keeps its role row: %v", err)
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d", n)
	}
	// Removing the disabled admin's role is fine.
	if err := f.st.RevokeRole(ctx, carol, f.u["dave"], store.RoleTenantAdmin); err != nil {
		t.Errorf("revoke disabled admin's role: %v", err)
	}
}

func TestValidAdminRemovalWhenAnotherActiveAdminRemains(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	carol := f.principal("carol")
	if err := f.st.RevokeRole(ctx, carol, f.u["dave"], store.RoleTenantAdmin); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d", n)
	}
	// Re-add and disable instead.
	if err := f.st.GrantRole(ctx, carol, f.u["dave"], store.RoleTenantAdmin); err != nil {
		t.Fatal(err)
	}
	if err := f.st.DisableUser(ctx, carol, f.u["dave"]); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d", n)
	}
}

// lockTenant holds the tenant-scoped synchronization boundary (the tenants row)
// so a test can queue several administrative operations behind it and release
// them in a known order. It is the same boundary the store takes; no sleeps.
func lockTenant(t *testing.T, pool *pgxpool.Pool, tenant string) func() {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, tenant); err != nil {
		t.Fatal(err)
	}
	done := false
	release := func() {
		if done {
			return
		}
		done = true
		if err := tx.Commit(ctx); err != nil {
			t.Error(err)
		}
	}
	// If the test fails before releasing, do not leave the lock held: schema
	// cleanup would block on it.
	t.Cleanup(release)
	return release
}

// waitBlocked polls pg_stat_activity until n backends wait on a lock.
func waitBlocked(t *testing.T, pool *pgxpool.Pool, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var got int
		if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock' AND pid <> pg_backend_pid()`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("administrative operations did not queue on the tenant lock (blocked=%d, want %d): no tenant-scoped serialization", got, n)
		}
		time.Sleep(time.Millisecond)
	}
}

type op func(ctx context.Context) error

// runQueued starts ops in order, each confirmed blocked on the tenant lock
// before the next starts (row-lock waiters are served FIFO), then releases.
func runQueued(t *testing.T, f *fx, ops ...op) []error {
	t.Helper()
	release := lockTenant(t, f.pool, f.tenant)
	errs := make([]error, len(ops))
	var wg sync.WaitGroup
	for i, o := range ops {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = o(context.Background())
		}()
		waitBlocked(t, f.pool, i+1)
	}
	release()
	wg.Wait()
	return errs
}

func TestConcurrentMutualAdminRevocationKeepsAnAdmin(t *testing.T) {
	f := newFx(t)
	carol, dave := f.principal("carol"), f.principal("dave")
	errs := runQueued(t, f,
		func(ctx context.Context) error {
			return f.st.RevokeRole(ctx, carol, f.u["dave"], store.RoleTenantAdmin)
		},
		func(ctx context.Context) error {
			return f.st.RevokeRole(ctx, dave, f.u["carol"], store.RoleTenantAdmin)
		},
	)
	if errs[0] != nil || !errors.Is(errs[1], store.ErrForbidden) {
		t.Fatalf("want first ok / second forbidden, got %v / %v", errs[0], errs[1])
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d, want 1", n)
	}
}

func TestConcurrentDeactivationAndRevocationKeepsAnAdmin(t *testing.T) {
	f := newFx(t)
	carol, dave := f.principal("carol"), f.principal("dave")
	errs := runQueued(t, f,
		func(ctx context.Context) error { return f.st.DisableUser(ctx, carol, f.u["dave"]) },
		func(ctx context.Context) error {
			return f.st.RevokeRole(ctx, dave, f.u["carol"], store.RoleTenantAdmin)
		},
	)
	if errs[0] != nil || !errors.Is(errs[1], store.ErrForbidden) {
		t.Fatalf("want first ok / second forbidden (actor was disabled), got %v / %v", errs[0], errs[1])
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d, want 1", n)
	}
}

func TestConcurrentSelfDeactivationsKeepAnAdmin(t *testing.T) {
	f := newFx(t)
	carol, dave := f.principal("carol"), f.principal("dave")
	errs := runQueued(t, f,
		func(ctx context.Context) error { return f.st.DisableUser(ctx, carol, f.u["carol"]) },
		func(ctx context.Context) error { return f.st.DisableUser(ctx, dave, f.u["dave"]) },
	)
	if errs[0] != nil || !errors.Is(errs[1], store.ErrForbidden) {
		t.Fatalf("got %v / %v", errs[0], errs[1])
	}
	if n := f.activeAdmins(); n != 1 {
		t.Fatalf("active admins = %d, want 1", n)
	}
}

func TestStaleActorCannotCommitAfterConcurrentRevocation(t *testing.T) {
	f := newFx(t)
	carol, dave := f.principal("carol"), f.principal("dave")
	// dave revokes carol first (queued first); carol's grant (queued second)
	// must then fail: authority is evaluated after the synchronization boundary.
	errs := runQueued(t, f,
		func(ctx context.Context) error {
			return f.st.RevokeRole(ctx, dave, f.u["carol"], store.RoleTenantAdmin)
		},
		func(ctx context.Context) error { return f.st.GrantRole(ctx, carol, f.u["alice"], store.RoleOperator) },
	)
	if errs[0] != nil || !errors.Is(errs[1], store.ErrForbidden) {
		t.Fatalf("got %v / %v", errs[0], errs[1])
	}
	if ok, _ := f.st.HasRole(context.Background(), f.principal("alice"), store.RoleOperator); ok {
		t.Fatal("stale administrator's grant committed")
	}
	if n := f.grantAudits(); n != 0 {
		t.Fatalf("audit events for a refused grant: %d", n)
	}
}

func TestAdminMutationsRollBackWhenAuditWriteFails(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	f.exec(`CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected audit failure'; END $$`)
	f.exec(`CREATE TRIGGER fail_audit_t BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_audit()`)
	carol := f.principal("carol")

	if err := f.st.GrantRole(ctx, carol, f.u["alice"], store.RoleOperator); err == nil {
		t.Error("grant succeeded without audit")
	}
	if err := f.st.AddMember(ctx, carol, f.p2, f.u["alice"]); err == nil {
		t.Error("add member succeeded without audit")
	}
	if err := f.st.RevokeRole(ctx, carol, f.u["dave"], store.RoleTenantAdmin); err == nil {
		t.Error("revoke succeeded without audit")
	}
	if err := f.st.RemoveMember(ctx, carol, f.p1, f.u["alice"]); err == nil {
		t.Error("remove member succeeded without audit")
	}
	if err := f.st.DisableUser(ctx, carol, f.u["bob"]); err == nil {
		t.Error("disable succeeded without audit")
	}
	if n := f.count(`SELECT count(*) FROM tenant_roles WHERE user_id=$1`, f.u["alice"]); n != 0 {
		t.Error("role row survived a failed audit write")
	}
	if n := f.count(`SELECT count(*) FROM project_members WHERE user_id=$1 AND project_id=$2`, f.u["alice"], f.p2); n != 0 {
		t.Error("membership row survived a failed audit write")
	}
	if n := f.count(`SELECT count(*) FROM tenant_roles WHERE user_id=$1 AND role='tenant_admin'`, f.u["dave"]); n != 1 {
		t.Error("revocation survived a failed audit write")
	}
	if n := f.count(`SELECT count(*) FROM project_members WHERE user_id=$1 AND project_id=$2`, f.u["alice"], f.p1); n != 1 {
		t.Error("removal survived a failed audit write")
	}
	if n := f.count(`SELECT count(*) FROM users WHERE id=$1 AND disabled_at IS NOT NULL`, f.u["bob"]); n != 0 {
		t.Error("disable survived a failed audit write")
	}
}

// Additional defect: no-op changes must not be audited as changes.
func TestNoOpMembershipChangesAreNotAudited(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	carol := f.principal("carol")
	before := f.count(`SELECT count(*) FROM audit_log`)
	_ = f.st.RemoveMember(ctx, carol, f.p2, f.u["alice"])                  // alice is not in P2
	if err := f.st.AddMember(ctx, carol, f.p1, f.u["alice"]); err != nil { // already a member
		t.Fatal(err)
	}
	if n := f.count(`SELECT count(*) FROM audit_log`); n != before {
		t.Fatalf("%d audit rows recorded for operations that changed nothing", n-before)
	}
}

// ---- Finding 3: active-account checks at the data-access boundary ----------

func TestStalePrincipalOfDisabledUserSeesNothing(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	alice := f.principal("alice") // resolved while active
	if ps, _ := f.st.ListProjects(ctx, alice); len(ps) != 1 {
		t.Fatal("baseline: alice should see P1")
	}
	f.exec(`UPDATE users SET disabled_at=now() WHERE id=$1`, f.u["alice"]) // memberships retained
	if n := f.count(`SELECT count(*) FROM project_members WHERE user_id=$1`, f.u["alice"]); n != 1 {
		t.Fatal("membership rows must be retained for this test")
	}
	if ps, err := f.st.ListProjects(ctx, alice); err != nil || len(ps) != 0 {
		t.Errorf("ListProjects leaks for a disabled user: %v %v", ps, err)
	}
	if as, err := f.st.ListArtifacts(ctx, alice, f.p1, ""); err != nil || len(as) != 0 {
		t.Errorf("ListArtifacts leaks: %v %v", as, err)
	}
	if as, err := f.st.Search(ctx, alice, "needle"); err != nil || len(as) != 0 {
		t.Errorf("Search leaks: %v %v", as, err)
	}
	if a, err := f.st.GetArtifact(ctx, alice, f.a1); !errors.Is(err, store.ErrNotFound) || a.Title != "" {
		t.Errorf("GetArtifact leaks: %+v %v", a, err)
	}
	if ok, _ := f.st.IsMember(ctx, alice, f.p1); ok {
		t.Error("IsMember true for disabled user")
	}
}

func TestStalePrincipalOfDisabledAdminCannotAdminister(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	carol := f.principal("carol")
	f.exec(`UPDATE users SET disabled_at=now() WHERE id=$1`, f.u["carol"])
	if ok, _ := f.st.HasRole(ctx, carol, store.RoleTenantAdmin); ok {
		t.Error("HasRole true for a disabled user")
	}
	if err := f.st.GrantRole(ctx, carol, f.u["alice"], store.RoleOperator); !errors.Is(err, store.ErrForbidden) {
		t.Errorf("disabled admin granted a role: %v", err)
	}
}

func TestCrossTenantControls(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	alice, zed := f.principal("alice"), f.principal("zed")
	// Positive: each sees exactly its own tenant's artifact.
	if as, _ := f.st.Search(ctx, alice, "needle"); len(as) != 1 || as[0].ID != f.a1 {
		t.Errorf("alice search: %+v", as)
	}
	if as, _ := f.st.Search(ctx, zed, "needle"); len(as) != 1 || as[0].ID != f.aOther {
		t.Errorf("zed search: %+v", as)
	}
	if a, err := f.st.GetArtifact(ctx, zed, f.aOther); err != nil || a.ID != f.aOther {
		t.Errorf("zed own artifact: %+v %v", a, err)
	}
	// Negative: no crossing in either direction, by direct id, list or project check.
	if _, err := f.st.GetArtifact(ctx, alice, f.aOther); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("alice read tenant B artifact: %v", err)
	}
	if _, err := f.st.GetArtifact(ctx, zed, f.a1); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("zed read tenant A artifact: %v", err)
	}
	if as, _ := f.st.ListArtifacts(ctx, alice, f.pOther, ""); len(as) != 0 {
		t.Error("alice listed tenant B project")
	}
	if ok, _ := f.st.IsMember(ctx, zed, f.p1); ok {
		t.Error("zed member of tenant A project")
	}
	// Even if a membership row were forced across tenants it is rejected by FKs.
	if err := f.st.SeedMember(ctx, f.tenant, f.p1, f.u["zed"]); err == nil {
		t.Error("cross-tenant membership accepted")
	}
	// Stale principal in tenant B after disabling stays confined.
	f.exec(`UPDATE users SET disabled_at=now() WHERE id=$1`, f.u["zed"])
	if as, _ := f.st.Search(ctx, zed, "needle"); len(as) != 0 {
		t.Error("disabled zed still sees artifacts")
	}
	if as, _ := f.st.Search(ctx, alice, "needle"); len(as) != 1 {
		t.Error("disabling a tenant B user affected tenant A")
	}
}

// Unforced race: both revocations start together with no coordination. With
// tenant-scoped serialization the outcome is always exactly one admin left; the
// count-based check can leave none. (The deterministic tests above are the gate;
// this one guards against an interleaving the coordination might not model.)
func TestRacingMutualRevocationStress(t *testing.T) {
	f := newFx(t)
	carol, dave := f.principal("carol"), f.principal("dave")
	for i := 0; i < 25; i++ {
		f.exec(`INSERT INTO tenant_roles(tenant_id,user_id,role) VALUES ($1,$2,'tenant_admin'),($1,$3,'tenant_admin') ON CONFLICT DO NOTHING`,
			f.tenant, f.u["carol"], f.u["dave"])
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, c := range [][2]any{{carol, f.u["dave"]}, {dave, f.u["carol"]}} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_ = f.st.RevokeRole(context.Background(), c[0].(store.Principal), c[1].(string), store.RoleTenantAdmin)
			}()
		}
		close(start)
		wg.Wait()
		if n := f.activeAdmins(); n != 1 {
			t.Fatalf("iteration %d: active admins = %d, want 1", i, n)
		}
	}
}
