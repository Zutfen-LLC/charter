package migrate_test

import (
	"context"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// The C07 lifecycle migration is additive over a legacy (pre-0008) database:
// with the holds tables absent but C03-C06 data present, applying 0008
// preserves every existing row and brings the lifecycle API's tables up
// functional. (Simulates a C06-era deployment migrating forward.)
func TestC07MigrationIsAdditiveOverLegacySchema(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	st := &store.Store{DB: pool}
	tenant, err := st.CreateTenant(ctx, "https://idp.test", "tid", "legacy")
	if err != nil {
		t.Fatal(err)
	}
	user, err := st.CreateUser(ctx, tenant, "sub", "legacy user")
	if err != nil {
		t.Fatal(err)
	}
	project, err := st.CreateProject(ctx, tenant, "legacy project")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateArtifact(ctx, tenant, project, "legacy chat", "legacy body"); err != nil {
		t.Fatal(err)
	}
	// Rewind to the pre-C07 shape: the 0008 and 0009 tables are gone and
	// the migration ledger no longer records them.
	if _, err := pool.Exec(ctx, `DROP TABLE hold_version_claims, disposal_plans, tenant_protection CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DROP TABLE hold_custodians, holds, matter_hold_epochs, retention_items, retention_policies CASCADE`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version IN ('0008_hold_lifecycle.sql','0009_protection_ownership.sql')`); err != nil {
		t.Fatal(err)
	}
	pending, err := migrate.Pending(ctx, pool)
	if err != nil || len(pending) != 2 || pending[0] != "0008_hold_lifecycle.sql" || pending[1] != "0009_protection_ownership.sql" {
		t.Fatalf("pending after rewind: %v (err %v)", pending, err)
	}
	applied, err := migrate.Up(ctx, pool)
	if err != nil || len(applied) != 2 || applied[0] != "0008_hold_lifecycle.sql" || applied[1] != "0009_protection_ownership.sql" {
		t.Fatalf("forward migration: %v (err %v)", applied, err)
	}
	// Legacy data survived untouched.
	var chats int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM artifacts`).Scan(&chats); err != nil || chats != 1 {
		t.Fatalf("legacy artifacts: %d (err %v)", chats, err)
	}
	// The lifecycle tables are functional: a hold places, the epoch
	// interlock and the catalog operate, and the runtime-role grants hold.
	if err := st.SeedRole(ctx, tenant, user, store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	p, err := st.Resolve(ctx, "https://idp.test", "tid", "sub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO matter_hold_epochs(tenant_id, matter_id) VALUES ($1, (SELECT matter_id FROM projects WHERE id=$2))`, tenant, project); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO retention_items(tenant_id, turn_id, matter_id, project_id, custodian_id, recorded_at, retention_expires_at)
		SELECT $1, gen_random_uuid(), matter_id, id, $2, now(), now() FROM projects WHERE id=$3`, tenant, user, project); err != nil {
		t.Fatal(err)
	}
	var hasPrivilege bool
	if err := pool.QueryRow(ctx, `SELECT has_table_privilege('charter_workspace_app','retention_items','UPDATE')`).Scan(&hasPrivilege); err != nil || !hasPrivilege {
		t.Fatalf("runtime role lacks lifecycle grant: %v (err %v)", hasPrivilege, err)
	}
	// The 0009 protection-ownership tables are functional and granted.
	for _, table := range []string{"tenant_protection", "hold_version_claims", "disposal_plans"} {
		var ok bool
		if err := pool.QueryRow(ctx, `SELECT has_table_privilege('charter_workspace_app',$1,'UPDATE')`, table).Scan(&ok); err != nil || !ok {
			t.Fatalf("runtime role lacks %s grant: %v (err %v)", table, ok, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_protection(tenant_id) VALUES ($1) ON CONFLICT DO NOTHING`, tenant); err != nil {
		t.Fatal(err)
	}
	_ = p
}
