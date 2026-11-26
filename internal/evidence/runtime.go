package evidence

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The authorization snapshot is checked on one authenticated physical session.
// Serving credentials may inherit only their designated leaf application role.
const (
	evidenceGroup  = "charter_evidence_app"
	workspaceGroup = "charter_workspace_app"
)

var evidenceTables = []string{"evidence_turns", "evidence_events", "evidence_objects"}

type roleInfo struct {
	user                                                string
	super, createRole, createDB, bypassRLS, replication bool
}

func inspectRole(ctx context.Context, db pgx.Tx, user string) (roleInfo, error) {
	var r roleInfo
	err := db.QueryRow(ctx, `SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolbypassrls, rolreplication
		FROM pg_catalog.pg_roles WHERE rolname = $1`, user).Scan(&r.user, &r.super, &r.createRole, &r.createDB, &r.bypassRLS, &r.replication)
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
func ownerProblems(ctx context.Context, db pgx.Tx, tables []string) ([]string, error) {
	var p []string
	for _, t := range tables {
		var owner string
		var isOwner, isMember bool
		err := db.QueryRow(ctx, `SELECT pg_catalog.pg_get_userbyid(c.relowner), pg_catalog.pg_get_userbyid(c.relowner) = current_user,
			pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER')
			FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass($1)`, t).Scan(&owner, &isOwner, &isMember)
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

func hasPriv(ctx context.Context, db pgx.Tx, table, priv string, includeColumns bool) (bool, error) {
	var ok bool
	err := db.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege(current_user, $1, $2)
  OR CASE WHEN $3::boolean AND $2 IN ('SELECT','INSERT','UPDATE','REFERENCES','SELECT WITH GRANT OPTION','INSERT WITH GRANT OPTION')
    THEN pg_catalog.has_any_column_privilege(current_user, $1, $2) ELSE false END`, table, priv, includeColumns).Scan(&ok)
	return ok, err
}

// workspaceTables are all other tables in the current schema.
func workspaceTables(ctx context.Context, db pgx.Tx) ([]string, error) {
	rows, err := db.Query(ctx, `SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname = pg_catalog.current_schema() AND c.relkind IN ('r','p','v','m','f')
  AND c.relname NOT LIKE 'evidence\_%'`)
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

// CheckEvidenceRuntime verifies the evidence-writer credential: not a
// superuser/owner/owner-member, INSERT and SELECT on the evidence tables and
// nothing destructive, no CREATE in the schema and no access to workspace data.
func CheckEvidenceRuntime(ctx context.Context, db *pgxpool.Pool) error {
	return checkRuntime(ctx, db, "evidence", evidenceGroup)
}

// CheckWorkspaceRuntime verifies that neither the authenticated login nor its
// sole assumable group has any evidence privilege.
func CheckWorkspaceRuntime(ctx context.Context, db *pgxpool.Pool) error {
	return checkRuntime(ctx, db, "workspace", workspaceGroup)
}

func checkRuntime(ctx context.Context, pool *pgxpool.Pool, kind, group string) error {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("%s credential: %w", kind, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	user := pool.Config().ConnConfig.User
	p, err := runtimeTopology(ctx, tx, user, group)
	if err != nil {
		return unsafe(kind, user, []string{err.Error()})
	}
	ep, version, err := runtimeEvidenceTables(ctx, tx)
	if err != nil {
		return fmt.Errorf("%s credential: %w", kind, err)
	}
	owners, err := ownerProblems(ctx, tx, ep)
	if err != nil {
		return fmt.Errorf("%s credential: %w", kind, err)
	}
	p = append(p, owners...)
	privs := []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
	if version >= 170000 {
		privs = append(privs, "MAINTAIN")
	}
	for _, t := range ep {
		for _, priv := range privs {
			want := kind == "evidence" && (priv == "SELECT" || priv == "INSERT")
			ok, err := hasPriv(ctx, tx, t, priv, !want)
			if err != nil {
				return fmt.Errorf("%s credential: %w", kind, err)
			}
			if want && !ok {
				p = append(p, "role lacks "+priv+" on "+t)
			}
			if !want && ok {
				p = append(p, "role holds "+priv+" on "+t)
			}
			if want {
				ok, err := hasPriv(ctx, tx, t, priv+" WITH GRANT OPTION", true)
				if err != nil {
					return fmt.Errorf("%s credential: %w", kind, err)
				}
				if ok {
					p = append(p, "role holds "+priv+" WITH GRANT OPTION on "+t)
				}
			}
		}
	}
	if kind == "evidence" {
		ws, err := workspaceTables(ctx, tx)
		if err != nil {
			return fmt.Errorf("%s credential: %w", kind, err)
		}
		for _, t := range ws {
			for _, priv := range privs {
				ok, err := hasPriv(ctx, tx, pgx.Identifier{t}.Sanitize(), priv, true)
				if err != nil {
					return fmt.Errorf("%s credential: %w", kind, err)
				}
				if ok {
					p = append(p, "role holds "+priv+" on workspace table "+t)
				}
			}
		}
	} else {
		ok, err := hasPriv(ctx, tx, "users", "SELECT", false)
		if err != nil {
			return fmt.Errorf("%s credential: %w", kind, err)
		}
		if !ok {
			p = append(p, "role cannot read workspace tables")
		}
	}
	if err := unsafe(kind, user, p); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%s credential: %w", kind, err)
	}
	return nil
}

func unsafe(kind, user string, problems []string) error {
	if len(problems) == 0 {
		return nil
	}
	return errors.New("unsafe " + kind + " database credential (role " + user + "): " + strings.Join(problems, "; "))
}
