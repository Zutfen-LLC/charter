package migrate_test

import (
	"context"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

func TestC08MigrationPreservesC07HeldCatalog(t *testing.T) {
	const migration = "0010_scoped_exports.sql"
	pool := testdb.New(t)
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	var exists bool
	must(pool.QueryRow(ctx, `SELECT to_regclass('scoped_exports') IS NOT NULL`).Scan(&exists))
	if !exists {
		t.Fatal("fresh migration did not create the export table")
	}
	// Remove only C08-owned objects and its ledger row. No CASCADE: an
	// unexpected predecessor dependency on C08 must fail this fixture.
	_, err := pool.Exec(ctx, `DROP INDEX scoped_export_authority_audit; DROP TABLE scoped_exports; DROP FUNCTION scoped_exports_guard(); DELETE FROM schema_migrations WHERE version='0010_scoped_exports.sql'`)
	must(err)
	st := store.Store{DB: pool}
	tenant, err := st.CreateTenant(ctx, "https://synthetic.invalid", "c07", "legacy C07")
	must(err)
	user, err := st.CreateUser(ctx, tenant, "c07-user", "legacy C07 user")
	must(err)
	project, err := st.CreateProject(ctx, tenant, "legacy project")
	must(err)
	_, err = st.CreateArtifact(ctx, tenant, project, "legacy workspace", "synthetic workspace bytes")
	must(err)
	var item, before string
	must(pool.QueryRow(ctx, `INSERT INTO retention_items(tenant_id,turn_id,matter_id,project_id,custodian_id,recorded_at,retention_expires_at)
		SELECT $1,gen_random_uuid(),matter_id,id,$2,now(),now()+interval '1 day' FROM projects WHERE id=$3 RETURNING turn_id::text, row_to_json(retention_items)::text`, tenant, user, project).Scan(&item, &before))
	pending, err := migrate.Pending(ctx, pool)
	must(err)
	if len(pending) != 1 || pending[0] != migration {
		t.Fatalf("expected 0009 predecessor shape, pending=%v", pending)
	}
	applied, err := migrate.Up(ctx, pool)
	must(err)
	if len(applied) != 1 || applied[0] != migration {
		t.Fatalf("expected only C08 extension, applied=%v", applied)
	}
	applied, err = migrate.Up(ctx, pool)
	must(err)
	if len(applied) != 0 {
		t.Fatalf("repeated migration changed state: %v", applied)
	}
	var after string
	must(pool.QueryRow(ctx, `SELECT row_to_json(r)::text FROM retention_items r WHERE tenant_id=$1 AND turn_id=$2`, tenant, item).Scan(&after))
	if before != after {
		t.Fatal("predecessor catalog row changed")
	}
	var rows int
	var wsRead, wsWrite, wsDelete, evRead, budgetRead bool
	must(pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM scoped_exports),
		has_table_privilege('charter_workspace_app','scoped_exports','SELECT'),
		has_table_privilege('charter_workspace_app','scoped_exports','UPDATE'),
		has_table_privilege('charter_workspace_app','scoped_exports','DELETE'),
		has_table_privilege('charter_evidence_app','scoped_exports','SELECT'),
		has_table_privilege('charter_budget_app','scoped_exports','SELECT')`).Scan(&rows, &wsRead, &wsWrite, &wsDelete, &evRead, &budgetRead))
	if rows != 0 || !wsRead || !wsWrite || wsDelete || evRead || budgetRead {
		t.Fatal("fresh export rows or runtime grants did not match the intended boundary")
	}
}
