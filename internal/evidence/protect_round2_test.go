package evidence_test

import (
	"context"
	"net/url"
	"os"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestProtectionSelfGrantUsesExactQuotedLoginAndRollsBack(t *testing.T) {
	ctx := context.Background()
	owner := testdb.New(t)
	schema := owner.Config().ConnConfig.RuntimeParams["search_path"]
	role := "Synthetic Grant " + evidence.NewUUID()[:8]
	mustSQL(t, owner, "CREATE ROLE "+ident(role)+" LOGIN PASSWORD 'synthetic-probe'")
	t.Cleanup(func() { mustSQL(t, owner, "DROP ROLE "+ident(role)) })
	mustSQL(t, owner, "GRANT USAGE ON SCHEMA "+ident(schema)+" TO "+ident(role))
	t.Cleanup(func() { mustSQL(t, owner, "REVOKE USAGE ON SCHEMA "+ident(schema)+" FROM "+ident(role)) })
	mustSQL(t, owner, "CREATE TABLE self_grant_target (body text)")
	t.Cleanup(func() { mustSQL(t, owner, "DROP TABLE self_grant_target") })
	mustSQL(t, owner, "ALTER TABLE self_grant_target OWNER TO "+ident(role))
	// Owners retain the right to grant, even after revoking their ordinary DML.
	mustSQL(t, owner, "REVOKE UPDATE, DELETE, TRUNCATE ON self_grant_target FROM "+ident(role))
	u, err := url.Parse(os.Getenv("CHARTER_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(role, "synthetic-probe")
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	login, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer login.Close()
	checkNoUpdate := func() {
		var update bool
		if err := login.QueryRow(ctx, `SELECT has_table_privilege(current_user,'self_grant_target','UPDATE')`).Scan(&update); err != nil || update {
			t.Fatalf("UPDATE leaked across probe: %v %v", update, err)
		}
	}
	p := &evidence.PGProber{DB: login, Identity: role, Tables: evidence.TableNames{Turns: "evidence_turns", Events: "self_grant_target", Objects: "evidence_objects"}}
	checkNoUpdate()
	got, why := p.Attempt(ctx, evidence.AttackGrantSelf, "", "", "")
	if got != evidence.Allowed {
		t.Errorf("valid self-grant did not run for quoted identity: %s %s", got, why)
	}
	checkNoUpdate()
}

func TestProtectionAttemptMustMatchQualifiedRowsAndRelations(t *testing.T) {
	f, turn, object := sample(t)
	c := testdb.Runtime(t, f.pool)
	ctx := context.Background()
	p := &evidence.PGProber{DB: c.Workspace, Admin: f.pool, Identity: c.WorkspaceRole}
	if err := p.Preflight(ctx, f.tenant, turn, object); err != nil {
		t.Fatal(err)
	}
	if got, why := p.Attempt(ctx, evidence.AttackDeleteTurn, f.tenant, evidence.NewUUID(), object); got != evidence.Inconclusive {
		t.Errorf("unverified turn counted as a refusal: %s %s", got, why)
	}
	// The intent is an exact target relation, not whatever later resolves at
	// the same name. The replacement in this disposable schema is protected
	// too: a 42501 against it must nevertheless not count.
	mustSQL(t, f.pool, "ALTER TABLE evidence_objects RENAME TO evidence_objects_original")
	mustSQL(t, f.pool, "CREATE TABLE evidence_objects (LIKE evidence_objects_original INCLUDING ALL)")
	mustSQL(t, f.pool, "INSERT INTO evidence_objects SELECT * FROM evidence_objects_original")
	if got, why := p.Attempt(ctx, evidence.AttackDeleteObject, f.tenant, turn, object); got != evidence.Inconclusive {
		t.Errorf("replacement relation counted as a refusal: %s %s", got, why)
	}
}

func TestProtectionQualificationRejectsDuplicateOrUnexpectedFindings(t *testing.T) {
	for _, bad := range []evidence.Finding{{Attack: evidence.AttackGrantSelf, Outcome: evidence.Inconclusive}, {Attack: "unexpected", Outcome: evidence.Refused}} {
		rep := evidence.Report{Findings: []evidence.Finding{bad}}
		for _, attack := range evidence.AllAttacks {
			rep.Findings = append(rep.Findings, evidence.Finding{Attack: attack, Outcome: evidence.Refused})
		}
		if rep.Qualified() {
			t.Errorf("report with extra finding qualified: %s", bad.Attack)
		}
	}
}
