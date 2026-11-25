package migrate_test

import (
	"context"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// Migrations are safe to run repeatedly: a second run applies nothing, the
// runtime roles exist with exactly the intended privileges, and Pending agrees.
func TestMigrationsAreIdempotentAndCreateRuntimeRoles(t *testing.T) {
	pool := testdb.New(t) // applied once, fresh
	ctx := context.Background()
	again, err := migrate.Up(ctx, pool)
	if err != nil || len(again) != 0 {
		t.Fatalf("second run: applied=%v err=%v", again, err)
	}
	if p, err := migrate.Pending(ctx, pool); err != nil || len(p) != 0 {
		t.Fatalf("pending after migrating: %v %v", p, err)
	}
	for _, r := range []string{"charter_workspace_app", "charter_evidence_app"} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1 AND NOT rolcanlogin)`, r).Scan(&ok); err != nil || !ok {
			t.Errorf("role %s missing or can log in: %v", r, err)
		}
	}
	var ws, ev bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('charter_workspace_app','evidence_events','SELECT'),
		has_table_privilege('charter_evidence_app','artifacts','SELECT')`).Scan(&ws, &ev); err != nil {
		t.Fatal(err)
	}
	if ws || ev {
		t.Fatalf("roles overlap: workspace reads evidence=%v evidence reads workspace=%v", ws, ev)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version='0003_evidence.sql'`); err != nil {
		t.Fatal(err)
	}
	if p, _ := migrate.Pending(ctx, pool); len(p) != 1 || p[0] != "0003_evidence.sql" {
		t.Fatalf("pending = %v", p)
	}
}
