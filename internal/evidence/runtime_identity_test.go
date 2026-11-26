package evidence_test

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func ident(s string) string { return pgx.Identifier{s}.Sanitize() }

func mustSQL(t *testing.T, pool *pgxpool.Pool, query string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), query); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeRejectsUnsafeRealLogins(t *testing.T) {
	ctx := context.Background()
	for _, test := range []string{"noninherited-update", "workspace-assumable-writer", "concealed-session-owner", "schema-owner-without-create"} {
		t.Run(test, func(t *testing.T) {
			owner := testdb.New(t)
			c := testdb.Runtime(t, owner)
			var err error
			switch test {
			case "noninherited-update":
				role := ident("charter_red_" + strings.ReplaceAll(evidence.NewUUID(), "-", ""))
				mustSQL(t, owner, "CREATE ROLE "+role+" NOLOGIN")
				t.Cleanup(func() { mustSQL(t, owner, "DROP OWNED BY "+role); mustSQL(t, owner, "DROP ROLE "+role) })
				mustSQL(t, owner, "GRANT UPDATE ON evidence_events TO "+role)
				mustSQL(t, owner, fmt.Sprintf("GRANT %s TO %s WITH INHERIT FALSE", role, ident(c.EvidenceRole)))
				var inherited bool
				if err := c.Evidence.QueryRow(ctx, `SELECT has_table_privilege(current_user, 'evidence_events', 'UPDATE')`).Scan(&inherited); err != nil || inherited {
					t.Fatalf("fixture did not isolate inheritance: %v %v", inherited, err)
				}
				err = evidence.CheckEvidenceRuntime(ctx, c.Evidence)
			case "workspace-assumable-writer":
				mustSQL(t, owner, "GRANT charter_evidence_app TO "+ident(c.WorkspaceRole)+" WITH INHERIT FALSE")
				err = evidence.CheckWorkspaceRuntime(ctx, c.Workspace)
			case "concealed-session-owner":
				cfg := owner.Config()
				cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
					_, err := conn.Exec(ctx, "SET ROLE "+ident(c.EvidenceRole))
					return err
				}
				pool, e := pgxpool.NewWithConfig(ctx, cfg)
				if e != nil {
					t.Fatal(e)
				}
				defer pool.Close()
				var session, current string
				if e := pool.QueryRow(ctx, `SELECT session_user,current_user`).Scan(&session, &current); e != nil || session == current || current != c.EvidenceRole {
					t.Fatalf("not a concealed real session: %q %q %v", session, current, e)
				}
				err = evidence.CheckEvidenceRuntime(ctx, pool)
			case "schema-owner-without-create":
				cfg := owner.Config().ConnConfig
				schema := ident(cfg.RuntimeParams["search_path"])
				mustSQL(t, owner, "ALTER SCHEMA "+schema+" OWNER TO "+ident(c.EvidenceRole))
				t.Cleanup(func() { mustSQL(t, owner, "ALTER SCHEMA "+schema+" OWNER TO "+ident(cfg.User)) })
				mustSQL(t, owner, "REVOKE CREATE ON SCHEMA "+schema+" FROM "+ident(c.EvidenceRole))
				err = evidence.CheckEvidenceRuntime(ctx, c.Evidence)
			}
			if err == nil {
				t.Fatalf("unsafe configuration %q accepted", test)
			}
		})
	}
}

func TestRuntimeRefusesAPortableDatabaseProfileWithIndirectSQLObjects(t *testing.T) {
	owner := testdb.New(t)
	c := testdb.Runtime(t, owner)
	ctx := context.Background()
	// No evidence access is performed; the runtime profile requires an audited
	// base-table-only surface, even if this test view returns a harmless value.
	mustSQL(t, owner, `CREATE VIEW synthetic_indirection AS SELECT 'fixture'::text AS value`)
	mustSQL(t, owner, `GRANT SELECT (value) ON synthetic_indirection TO `+ident(c.WorkspaceRole))
	if err := evidence.CheckWorkspaceRuntime(ctx, c.Workspace); err == nil {
		t.Fatal("workspace login with an application view grant passed runtime validation")
	}
}

func TestRuntimeRejectsDatabaseOwnerWithoutTableOwnership(t *testing.T) {
	admin := testdb.New(t)
	ctx := context.Background()
	name := "charter_rt_db_" + strings.ReplaceAll(evidence.NewUUID(), "-", "")
	mustSQL(t, admin, "CREATE DATABASE "+ident(name))
	t.Cleanup(func() { mustSQL(t, admin, "DROP DATABASE "+ident(name)) })
	u, err := url.Parse(os.Getenv("CHARTER_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	t.Setenv("CHARTER_TEST_DATABASE_URL", u.String())
	owner := testdb.New(t)
	c := testdb.Runtime(t, owner)
	mustSQL(t, admin, "ALTER DATABASE "+ident(name)+" OWNER TO "+ident(c.EvidenceRole))
	t.Cleanup(func() {
		mustSQL(t, admin, "ALTER DATABASE "+ident(name)+" OWNER TO "+ident(admin.Config().ConnConfig.User))
	})
	if err := evidence.CheckEvidenceRuntime(ctx, c.Evidence); err == nil {
		t.Fatal("database owner can pass runtime validation")
	}
}
