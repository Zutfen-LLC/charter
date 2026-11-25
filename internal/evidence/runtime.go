package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// The control plane serves with two least-privilege logins, never with the
// credential that owns the schema. These checks run at startup and refuse
// unsafe configuration; they inspect the ACTUAL connection (current_user), so a
// URL that happens to authenticate as the owner or a superuser is rejected.

var evidenceTables = []string{"evidence_turns", "evidence_events", "evidence_objects"}

type roleInfo struct {
	user                                                string
	super, createRole, createDB, bypassRLS, replication bool
}

func inspectRole(ctx context.Context, db *pgxpool.Pool) (roleInfo, error) {
	var r roleInfo
	err := db.QueryRow(ctx, `SELECT current_user, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication
		FROM pg_roles WHERE rolname = current_user`).Scan(&r.user, &r.super, &r.createRole, &r.createDB, &r.bypassRLS, &r.replication)
	return r, err
}

func (r roleInfo) problems() []string {
	var p []string
	for name, on := range map[string]bool{"SUPERUSER": r.super, "CREATEROLE": r.createRole, "CREATEDB": r.createDB,
		"BYPASSRLS": r.bypassRLS, "REPLICATION": r.replication} {
		if on {
			p = append(p, "role has "+name)
		}
	}
	return p
}

// ownerProblems: the credential must not own, or be able to become the owner
// of, the evidence tables (SET ROLE works for any role it is a member of).
func ownerProblems(ctx context.Context, db *pgxpool.Pool, tables []string) ([]string, error) {
	var p []string
	for _, t := range tables {
		var owner string
		var isOwner, isMember bool
		err := db.QueryRow(ctx, `SELECT pg_get_userbyid(c.relowner), pg_get_userbyid(c.relowner) = current_user,
			pg_has_role(current_user, c.relowner, 'MEMBER')
			FROM pg_class c WHERE c.oid = to_regclass($1)`, t).Scan(&owner, &isOwner, &isMember)
		if err != nil {
			return nil, fmt.Errorf("table %s not found (is the database migrated?): %w", t, err)
		}
		switch {
		case isOwner:
			p = append(p, "role owns "+t)
		case isMember:
			p = append(p, "role is a member of the owner role "+owner+" of "+t+" and can assume it")
		}
	}
	return p, nil
}

func hasPriv(ctx context.Context, db *pgxpool.Pool, table, priv string) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT has_table_privilege(current_user, $1, $2)`, table, priv).Scan(&ok)
	return ok, err
}

// workspaceTables are all other tables in the current schema.
func workspaceTables(ctx context.Context, db *pgxpool.Pool) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = current_schema()
		AND tablename NOT LIKE 'evidence\_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func canCreateInSchema(ctx context.Context, db *pgxpool.Pool) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT has_schema_privilege(current_user, current_schema(), 'CREATE')`).Scan(&ok)
	return ok, err
}

// CheckEvidenceRuntime verifies the evidence-writer credential: not a
// superuser/owner/owner-member, INSERT and SELECT on the evidence tables and
// nothing destructive, no CREATE in the schema and no access to workspace data.
func CheckEvidenceRuntime(ctx context.Context, db *pgxpool.Pool) error {
	r, err := inspectRole(ctx, db)
	if err != nil {
		return fmt.Errorf("evidence credential: %w", err)
	}
	p := r.problems()
	op, err := ownerProblems(ctx, db, evidenceTables)
	if err != nil {
		return fmt.Errorf("evidence credential: %w", err)
	}
	p = append(p, op...)
	for _, t := range evidenceTables {
		for _, want := range []string{"SELECT", "INSERT"} {
			if ok, err := hasPriv(ctx, db, t, want); err != nil || !ok {
				p = append(p, "role lacks "+want+" on "+t)
			}
		}
		for _, bad := range []string{"UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			if ok, err := hasPriv(ctx, db, t, bad); err != nil || ok {
				p = append(p, "role holds "+bad+" on "+t)
			}
		}
	}
	if ok, err := canCreateInSchema(ctx, db); err != nil || ok {
		p = append(p, "role can create objects in the schema")
	}
	ws, err := workspaceTables(ctx, db)
	if err != nil {
		return fmt.Errorf("evidence credential: %w", err)
	}
	for _, t := range ws {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
			if ok, err := hasPriv(ctx, db, t, priv); err != nil || ok {
				p = append(p, "role holds "+priv+" on workspace table "+t)
			}
		}
	}
	return unsafe("evidence", r.user, p)
}

// CheckWorkspaceRuntime verifies the workspace credential: same exclusions, and
// no privilege of any kind on the evidence tables, so a workspace bug or SQL
// injection cannot read, alter or delete evidence.
func CheckWorkspaceRuntime(ctx context.Context, db *pgxpool.Pool) error {
	r, err := inspectRole(ctx, db)
	if err != nil {
		return fmt.Errorf("workspace credential: %w", err)
	}
	p := r.problems()
	op, err := ownerProblems(ctx, db, evidenceTables)
	if err != nil {
		return fmt.Errorf("workspace credential: %w", err)
	}
	p = append(p, op...)
	for _, t := range evidenceTables {
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"} {
			if ok, err := hasPriv(ctx, db, t, priv); err != nil || ok {
				p = append(p, "role holds "+priv+" on "+t)
			}
		}
	}
	if ok, err := canCreateInSchema(ctx, db); err != nil || ok {
		p = append(p, "role can create objects in the schema")
	}
	if ok, err := hasPriv(ctx, db, "users", "SELECT"); err != nil || !ok {
		p = append(p, "role cannot read workspace tables")
	}
	return unsafe("workspace", r.user, p)
}

func unsafe(kind, user string, problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	return errors.New("unsafe " + kind + " database credential (role " + user + "): " + strings.Join(problems, "; "))
}
