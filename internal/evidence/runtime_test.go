package evidence_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The full write path, replay and recovery work with the ACTUAL restricted
// evidence login (a real LOGIN role, not SET ROLE from an owner connection).
func TestWritePathWorksUnderTheRestrictedEvidenceLogin(t *testing.T) {
	f := newFx(t, nil)
	c := testdb.Runtime(t, f.pool)
	f.rec.Backend = evidence.PG{DB: c.Evidence}
	ctx := context.Background()
	res, err := f.rec.Process(ctx, f.req("k", "in"), f.model("answer"), nil)
	if err != nil || string(res.Output) != "answer" {
		t.Fatalf("admission/append/object storage as the restricted login: %+v %v", res, err)
	}
	if r2, err := f.rec.Process(ctx, f.req("k", "in"), f.model("x"), nil); err != nil || !r2.Replayed {
		t.Fatalf("replay: %+v %v", r2, err)
	}
	// Recovery as the restricted login: leave one turn open, then resolve it.
	crash := func() {
		defer func() { _ = recover() }()
		_, _ = f.rec.Process(ctx, f.req("k2", "in2"), func(context.Context, []byte) (evidence.ModelOutcome, error) { panic("crash") }, nil)
	}
	crash()
	if n, err := f.rec.Recover(ctx, time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("recover as the restricted login: n=%d err=%v", n, err)
	}
	var turns int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM evidence_turns`).Scan(&turns)
	if turns != 2 {
		t.Fatalf("turns = %d", turns)
	}
	f.verified(res.TurnID)
}

// Qualification of the real serving credentials: every attack REFUSED, identity
// verified, target present, positive control passing. Direct logins qualify.
func TestRuntimeCredentialsQualify(t *testing.T) {
	f, turn, obj := sample(t)
	c := testdb.Runtime(t, f.pool)
	for name, p := range map[string]*evidence.PGProber{
		"evidence login":  {DB: c.Evidence, Identity: c.EvidenceRole, Admin: f.pool},
		"workspace login": {DB: c.Workspace, Identity: c.WorkspaceRole, Admin: f.pool},
	} {
		rep := evidence.QualifyProtection(context.Background(), p, f.tenant, turn, obj)
		if !rep.Qualified() || rep.Count(evidence.Refused) != len(evidence.AllAttacks) {
			t.Errorf("%s not qualified:\n%s", name, rep)
		}
	}
	if err := evidence.CheckEvidenceRuntime(context.Background(), c.Evidence); err != nil {
		t.Errorf("evidence login rejected: %v", err)
	}
	if err := evidence.CheckWorkspaceRuntime(context.Background(), c.Workspace); err != nil {
		t.Errorf("workspace login rejected: %v", err)
	}
	// The workspace login cannot even read evidence, and the evidence login
	// cannot read workspace data.
	if _, err := c.Workspace.Exec(context.Background(), `SELECT count(*) FROM evidence_events`); err == nil {
		t.Error("workspace login can read evidence")
	}
	if _, err := c.Evidence.Exec(context.Background(), `SELECT count(*) FROM artifacts`); err == nil {
		t.Error("evidence login can read workspace tables")
	}
}

// Unsafe serving credentials are detected, not trusted.
func TestUnsafeServingCredentialsAreRejected(t *testing.T) {
	f := newFx(t, nil)
	c := testdb.Runtime(t, f.pool)
	ctx := context.Background()
	mustErr := func(name string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want it to mention %q", name, err, want)
		}
	}
	// The schema owner (here also a superuser) is unsafe for both uses.
	mustErr("owner as evidence login", evidence.CheckEvidenceRuntime(ctx, f.pool), "SUPERUSER")
	mustErr("owner as workspace login", evidence.CheckWorkspaceRuntime(ctx, f.pool), "SUPERUSER")
	// Each login is wrong for the other job.
	mustErr("workspace login as evidence login", evidence.CheckEvidenceRuntime(ctx, c.Workspace), "lacks")
	mustErr("evidence login as workspace login", evidence.CheckWorkspaceRuntime(ctx, c.Evidence), "holds")
	// Extra privileges and role memberships on a login that is otherwise fine.
	bad := func(name, grant, want string, check func(context.Context, *pgxpool.Pool) error) {
		role := c.EvidenceRole
		if _, err := f.pool.Exec(ctx, grant); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		mustErr(name, check(ctx, c.Evidence), want)
		_ = role
	}
	bad("extra UPDATE on evidence", "GRANT UPDATE ON evidence_events TO "+c.EvidenceRole, "holds UPDATE",
		func(ctx context.Context, p *pgxpool.Pool) error { return evidence.CheckEvidenceRuntime(ctx, p) })
	bad("extra TRUNCATE on evidence", "GRANT TRUNCATE ON evidence_objects TO "+c.EvidenceRole, "holds TRUNCATE",
		func(ctx context.Context, p *pgxpool.Pool) error { return evidence.CheckEvidenceRuntime(ctx, p) })
	bad("member of both runtime roles", "GRANT charter_workspace_app TO "+c.EvidenceRole, "workspace table",
		func(ctx context.Context, p *pgxpool.Pool) error { return evidence.CheckEvidenceRuntime(ctx, p) })
	if _, err := f.pool.Exec(ctx, `GRANT charter_evidence_app TO `+c.WorkspaceRole); err != nil {
		t.Fatal(err)
	}
	mustErr("workspace login that can also write evidence", evidence.CheckWorkspaceRuntime(ctx, c.Workspace), "holds")
	// A login that can become the owner (SET ROLE) is unsafe even if it holds no
	// other privilege.
	var owner string
	_ = f.pool.QueryRow(ctx, `SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = to_regclass('evidence_events')`).Scan(&owner)
	if _, err := f.pool.Exec(ctx, `GRANT `+owner+` TO `+c.WorkspaceRole); err != nil {
		t.Skipf("cannot grant the owner role in this environment: %v", err)
	}
	mustErr("member of the owner role", evidence.CheckWorkspaceRuntime(ctx, c.Workspace), "owner role")
}

func TestRuntimeChecksRejectTransitiveMembershipAndSchemaOwnership(t *testing.T) {
	f := newFx(t, nil)
	c := testdb.Runtime(t, f.pool)
	ctx := context.Background()
	role := "charter_indirect_" + strings.ReplaceAll(evidence.NewUUID()[:8], "-", "")
	mid := role + "_mid"
	for _, q := range []string{"CREATE ROLE " + role + " NOLOGIN", "CREATE ROLE " + mid + " NOLOGIN", "GRANT " + mid + " TO " + c.EvidenceRole, "GRANT " + role + " TO " + mid} {
		if _, err := f.pool.Exec(ctx, q); err != nil { t.Fatal(err) }
	}
	t.Cleanup(func(){
		_, _ = f.pool.Exec(ctx, "REVOKE "+mid+" FROM "+c.EvidenceRole)
		_, _ = f.pool.Exec(ctx, "REVOKE "+role+" FROM "+mid)
		_, _ = f.pool.Exec(ctx, "DROP ROLE IF EXISTS "+mid)
		_, _ = f.pool.Exec(ctx, "DROP ROLE IF EXISTS "+role)
	})
	if err := evidence.CheckEvidenceRuntime(ctx, c.Evidence); err == nil {
		t.Fatal("checker accepted an indirect membership chain into a privileged role")
	}
}

func TestRuntimeChecksRejectEffectiveColumnPrivilege(t *testing.T) {
	f := newFx(t, nil)
	c := testdb.Runtime(t, f.pool)
	if _, err := f.pool.Exec(context.Background(), `GRANT UPDATE (body) ON evidence_events TO `+c.EvidenceRole); err != nil { t.Fatal(err) }
	t.Cleanup(func() { _, _ = f.pool.Exec(context.Background(), `REVOKE UPDATE (body) ON evidence_events FROM `+c.EvidenceRole) })
	if err := evidence.CheckEvidenceRuntime(context.Background(), c.Evidence); err == nil {
		t.Fatal("checker accepted an effective column-level UPDATE grant")
	}
}

func TestInstanceFenceAllowsOneLiveInstance(t *testing.T) {
	f := newFx(t, nil)
	other := testdb.Clone(t, f.pool)
	a, err := f.pg.AcquireFence(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (evidence.PG{DB: other}).AcquireFence(context.Background()); !errors.Is(err, evidence.ErrFenceHeld) {
		t.Fatalf("second instance got the fence: %v", err)
	}
	a.Release()
	b, err := (evidence.PG{DB: other}).AcquireFence(context.Background())
	if err != nil {
		t.Fatalf("fence not released: %v", err)
	}
	b.Release()
}

// Overlapping recovery attempts (two starts, or a start racing a live
// request) leave each turn with exactly one terminal event and a log that
// verifies.
func TestOverlappingRecoveryTerminalizesEachTurnOnce(t *testing.T) {
	fb := &faulty{failTypes: map[string]bool{"policy_decision": true}, forever: true}
	f := newFx(t, func(b evidence.Backend) evidence.Backend { fb.Backend = b; return fb })
	ctx := context.Background()
	for i := 0; i < 6; i++ { // admitted, then the store fails: left open
		_, _ = f.rec.Process(ctx, f.req(string(rune('a'+i)), "in"), f.model("x"), nil)
	}
	f.rec.Backend = f.pg
	other := &evidence.Recorder{Backend: f.pg, Policy: f.rec.Policy}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, r := range []*evidence.Recorder{f.rec, other} {
		wg.Add(1)
		go func(r *evidence.Recorder) {
			defer wg.Done()
			_, err := r.Recover(ctx, time.Now().Add(time.Hour))
			errs <- err
		}(r)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("overlapping recovery failed: %v", err)
		}
	}
	rows, _ := f.pool.Query(ctx, `SELECT turn_id::text, count(*) FILTER (WHERE type IN ('turn_completed','turn_interrupted')) FROM evidence_events GROUP BY turn_id`)
	n := 0
	for rows.Next() {
		var id string
		var terms int
		_ = rows.Scan(&id, &terms)
		if terms != 1 {
			t.Errorf("turn %s has %d terminal events", id, terms)
		}
		f.verified(id)
		n++
	}
	rows.Close()
	if n != 6 {
		t.Fatalf("turns = %d", n)
	}
}
