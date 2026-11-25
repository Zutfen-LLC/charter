// Package testdb gives tests an isolated, migrated schema in the database named
// by CHARTER_TEST_DATABASE_URL. It only ever creates and drops its own
// uniquely named charter_test_* schema.
package testdb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/migrate"
	"github.com/jackc/pgx/v5/pgxpool"
)

// New returns a pool bound to a fresh migrated schema, or skips the test when
// no test database is configured.
func New(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("CHARTER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CHARTER_TEST_DATABASE_URL not set; skipping DB test")
	}
	ctx := context.Background()
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	schema := "charter_test_" + hex.EncodeToString(b[:])
	admin, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+schema); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	// Lets a test count ITS OWN lock waiters (pg_stat_activity.application_name)
	// without seeing those of other tests running in parallel in the same database.
	cfg.ConnConfig.RuntimeParams["application_name"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(context.Background(), `DROP SCHEMA `+schema+` CASCADE`); err != nil {
			t.Errorf("cleanup of schema %s failed: %v", schema, err)
		}
		admin.Close()
	})
	if _, err := migrate.Up(ctx, pool); err != nil {
		t.Fatal(err)
	}
	return pool
}

// Clone opens another pool onto the same database and schema as pool, so a test
// can make the authorization pool and the evidence pool fail independently.
func Clone(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.NewWithConfig(context.Background(), pool.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p
}

// Creds are REAL login credentials for the two serving roles, as a deployment
// would provision them: the workspace login is a member of charter_workspace_app
// only, the evidence login a member of charter_evidence_app only. Tests that
// claim anything about runtime protection must use these, not SET ROLE from an
// owner connection.
type Creds struct {
	WorkspaceRole, EvidenceRole string
	WorkspaceURL, EvidenceURL   string
	// OwnerURL authenticates as the schema owner (a superuser in tests) on the
	// same schema: the credential the server must refuse to serve with.
	OwnerURL            string
	Workspace, Evidence *pgxpool.Pool
}

// Runtime creates the two login roles (random names, cluster-wide) for the
// schema behind owner, connects as them, and drops everything on cleanup.
func Runtime(t *testing.T, owner *pgxpool.Pool) Creds {
	t.Helper()
	base := os.Getenv("CHARTER_TEST_DATABASE_URL")
	u, err := url.Parse(base)
	if err != nil || base == "" {
		t.Fatalf("bad CHARTER_TEST_DATABASE_URL: %v", err)
	}
	schema := owner.Config().ConnConfig.RuntimeParams["search_path"]
	ctx := context.Background()
	var b [5]byte
	_, _ = rand.Read(b[:])
	sfx := hex.EncodeToString(b[:])
	c := Creds{WorkspaceRole: "charter_rt_ws_" + sfx, EvidenceRole: "charter_rt_ev_" + sfx}
	pw := "pw-" + sfx
	for role, member := range map[string]string{c.WorkspaceRole: "charter_workspace_app", c.EvidenceRole: "charter_evidence_app"} {
		if _, err := owner.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD '`+pw+`'`); err != nil {
			t.Fatal(err)
		}
		if _, err := owner.Exec(ctx, `GRANT `+member+` TO `+role); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(role string) (string, *pgxpool.Pool) {
		v := *u
		v.User = url.UserPassword(role, pw)
		q := v.Query()
		q.Set("search_path", schema)
		v.RawQuery = q.Encode()
		p, err := pgxpool.New(ctx, v.String())
		if err != nil {
			t.Fatal(err)
		}
		return v.String(), p
	}
	ov := *u
	oq := ov.Query()
	oq.Set("search_path", schema)
	ov.RawQuery = oq.Encode()
	c.OwnerURL = ov.String()
	c.WorkspaceURL, c.Workspace = mk(c.WorkspaceRole)
	c.EvidenceURL, c.Evidence = mk(c.EvidenceRole)
	t.Cleanup(func() {
		c.Workspace.Close()
		c.Evidence.Close()
		for _, r := range []string{c.WorkspaceRole, c.EvidenceRole} {
			_, _ = owner.Exec(context.Background(), `DROP OWNED BY `+r)
			if _, err := owner.Exec(context.Background(), `DROP ROLE `+r); err != nil {
				t.Errorf("cleanup of role %s failed: %v", r, err)
			}
		}
	})
	return c
}
