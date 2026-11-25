package evidence_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// sample is a completed turn plus the identifiers a prober needs.
func sample(t *testing.T) (*fx, string, string) {
	t.Helper()
	f := newFx(t, nil)
	res, err := f.rec.Process(context.Background(), f.req("k", "in"), f.model("ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return f, res.TurnID, evidence.SHA256([]byte("ok"))
}

func currentUser(t *testing.T, f *fx) string {
	t.Helper()
	var u string
	if err := f.pool.QueryRow(context.Background(), `SELECT current_user`).Scan(&u); err != nil {
		t.Fatal(err)
	}
	return u
}

func outcomes(r evidence.Report) map[string]evidence.Outcome {
	m := map[string]evidence.Outcome{}
	for _, f := range r.Findings {
		m[f.Attack] = f.Outcome
	}
	return m
}

// The restricted evidence role, tried via SET ROLE from the privileged test
// connection, is refused on every privilege-layer attack for a target that
// exists. It cannot QUALIFY: role-switching from a privileged session says
// nothing about escalation, so that attack is INCONCLUSIVE. The direct-login
// qualification of the actual runtime credentials is in runtime_test.go.
func TestRestrictedRoleIsRefusedButCannotQualifyViaSetRole(t *testing.T) {
	f, turn, obj := sample(t)
	p := &evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: "charter_evidence_app"}
	rep := evidence.QualifyProtection(context.Background(), p, f.tenant, turn, obj)
	o := outcomes(rep)
	for _, a := range evidence.AllAttacks {
		want := evidence.Refused
		if a == evidence.AttackAssumeOwner || a == evidence.AttackIndirectAuthority {
			want = evidence.Inconclusive
		}
		if o[a] != want {
			t.Errorf("%s: %s, want %s\n%s", a, o[a], want, rep)
		}
	}
	if rep.Qualified() {
		t.Fatalf("SET ROLE from a privileged session must not qualify:\n%s", rep)
	}
	f.verified(turn) // the attacks were rolled back: evidence is intact
}

// The table OWNER is only stopped by the triggers: update/delete/truncate are
// refused, but it can disable them and drop the table. This is the recorded
// gap, asserted so nobody can claim retention enforcement for this backend.
func TestOwnerCredentialIsNotQualified_RecordedGap(t *testing.T) {
	f, turn, obj := sample(t)
	if info := f.pg.Info(); info.RetentionEnforced || info.Notice == "" {
		t.Fatalf("backend must not claim retention enforcement: %+v", info)
	}
	p := &evidence.PGProber{DB: f.pool, Admin: f.pool, Identity: currentUser(t, f)}
	rep := evidence.QualifyProtection(context.Background(), p, f.tenant, turn, obj)
	o := outcomes(rep)
	for _, a := range []string{evidence.AttackRewriteEvent, evidence.AttackDeleteEvent, evidence.AttackRewriteObject,
		evidence.AttackDeleteObject, evidence.AttackDeleteTurn, evidence.AttackTruncate} {
		if o[a] != evidence.Refused {
			t.Errorf("owner %s: %s (the triggers should refuse it)\n%s", a, o[a], rep)
		}
	}
	if rep.Qualified() || o[evidence.AttackDisableGuards] != evidence.Allowed || o[evidence.AttackDropTable] != evidence.Allowed || o[evidence.AttackDropSchema] != evidence.Allowed {
		t.Fatalf("owner must be reported as able to disable protections:\n%s", rep)
	}
	t.Log("gap confirmed: an owner/superuser can disable the append-only triggers; real WORM storage is required for qualification")
}

// Every way a run can be meaningless must yield INCONCLUSIVE for every attack
// and never qualify. (On the original harness each of these "passed".)
func TestQualificationIsNotVacuous(t *testing.T) {
	f, turn, obj := sample(t)
	ctx := context.Background()
	closed := testdb.Clone(t, f.pool)
	closed.Close()
	absent := evidence.NewUUID()
	cases := map[string]struct {
		p      *evidence.PGProber
		tenant string
		turn   string
		sha    string
		why    string
	}{
		"unreachable storage": {&evidence.PGProber{DB: closed, Admin: f.pool, AsRole: "charter_evidence_app"}, f.tenant, turn, obj, "connect"},
		"failed SET ROLE":     {&evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: "no_such_role_xyz"}, f.tenant, turn, obj, "SET ROLE"},
		"absent turn":         {&evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: "charter_evidence_app"}, f.tenant, absent, obj, "target absent"},
		"absent object":       {&evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: "charter_evidence_app"}, f.tenant, turn, evidence.SHA256([]byte("nope")), "target absent"},
		"wrong tenant":        {&evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: "charter_evidence_app"}, absent, turn, obj, "target absent"},
		"identity mismatch":   {&evidence.PGProber{DB: f.pool, Admin: f.pool, Identity: "somebody_else"}, f.tenant, turn, obj, "identity"},
		"no identity claimed": {&evidence.PGProber{DB: f.pool, Admin: f.pool}, f.tenant, turn, obj, "identity"},
		"nonexistent tables": {&evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: "charter_evidence_app",
			Tables: evidence.TableNames{Turns: "no_turns", Events: "no_events", Objects: "no_objects"}}, f.tenant, turn, obj, "target lookup"},
		"no admin connection": {&evidence.PGProber{DB: f.pool, AsRole: "charter_evidence_app"}, f.tenant, turn, obj, "admin"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			rep := evidence.QualifyProtection(ctx, c.p, c.tenant, c.turn, c.sha)
			if rep.Qualified() || rep.Count(evidence.Refused) != 0 || rep.Count(evidence.Inconclusive) != len(evidence.AllAttacks) {
				t.Fatalf("meaningless run was not INCONCLUSIVE:\n%s", rep)
			}
			if !strings.Contains(rep.Findings[0].Detail, c.why) {
				t.Errorf("detail %q does not explain %q", rep.Findings[0].Detail, c.why)
			}
		})
	}
	var empty evidence.Report
	if empty.Qualified() {
		t.Fatal("an empty report must never qualify")
	}
	partial := evidence.Report{Findings: []evidence.Finding{{Attack: evidence.AttackRewriteEvent, Outcome: evidence.Refused}}}
	if partial.Qualified() {
		t.Fatal("a partial report must never qualify")
	}
}

// A deliberately unprotected copy: the harness must see ALLOWED, proving the
// probes would succeed without protection.
func TestHarnessSeesAnUnprotectedTarget(t *testing.T) {
	f, turn, obj := sample(t)
	ctx := context.Background()
	role := fmt.Sprintf("charter_unprot_%s", strings.ReplaceAll(evidence.NewUUID()[:8], "-", ""))
	steps := []string{
		`CREATE TABLE unprot_turns  (LIKE evidence_turns  INCLUDING ALL)`,
		`CREATE TABLE unprot_events (LIKE evidence_events INCLUDING ALL)`,
		`CREATE TABLE unprot_objects(LIKE evidence_objects INCLUDING ALL)`,
		`INSERT INTO unprot_turns  SELECT * FROM evidence_turns`,
		`INSERT INTO unprot_events SELECT * FROM evidence_events`,
		`INSERT INTO unprot_objects SELECT * FROM evidence_objects`,
		`CREATE ROLE ` + role + ` NOLOGIN`,
		fmt.Sprintf(`DO $$ BEGIN EXECUTE format('GRANT USAGE ON SCHEMA %%I TO %s', current_schema()); END $$`, role),
		`GRANT ALL ON unprot_turns, unprot_events, unprot_objects TO ` + role,
	}
	for _, s := range steps {
		if _, err := f.pool.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = f.pool.Exec(context.Background(), `REVOKE ALL ON unprot_turns, unprot_events, unprot_objects FROM `+role)
		_, _ = f.pool.Exec(context.Background(), `DO $$ BEGIN EXECUTE format('REVOKE ALL ON SCHEMA %I FROM `+role+`', current_schema()); END $$`)
		_, _ = f.pool.Exec(context.Background(), `DROP ROLE IF EXISTS `+role)
	})
	p := &evidence.PGProber{DB: f.pool, Admin: f.pool, AsRole: role,
		Tables: evidence.TableNames{Turns: "unprot_turns", Events: "unprot_events", Objects: "unprot_objects"}}
	rep := evidence.QualifyProtection(ctx, p, f.tenant, turn, obj)
	o := outcomes(rep)
	for _, a := range []string{evidence.AttackRewriteEvent, evidence.AttackDeleteEvent, evidence.AttackRewriteObject,
		evidence.AttackDeleteObject, evidence.AttackDeleteTurn, evidence.AttackTruncate} {
		if o[a] != evidence.Allowed {
			t.Errorf("%s on an unprotected target: %s, want ALLOWED\n%s", a, o[a], rep)
		}
	}
	if rep.Qualified() {
		t.Fatal("unprotected target qualified")
	}
	var n int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM unprot_events`).Scan(&n)
	if n == 0 {
		t.Fatal("attacks were not rolled back")
	}
}
