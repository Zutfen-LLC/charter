package evidence

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func runtimeTopology(ctx context.Context, tx pgx.Tx, expected, group string) ([]string, error) {
	var session, current string
	var inherit bool
	if err := tx.QueryRow(ctx, `SELECT session_user,current_user,rolinherit FROM pg_catalog.pg_roles WHERE rolname=session_user`).
		Scan(&session, &current, &inherit); err != nil {
		return nil, err
	}
	if session != current || session != expected {
		return nil, errors.New("session_user and current_user must match the authenticated login; role switching is not allowed")
	}
	login, err := inspectRole(ctx, tx, session)
	if err != nil {
		return nil, err
	}
	leaf, err := inspectRole(ctx, tx, group)
	if err != nil {
		return nil, fmt.Errorf("required application role %s: %w", group, err)
	}
	p := append(login.problems(), leaf.problems()...)
	var direct, invalid int
	var groupLogin bool
	// An undesired membership is rejected regardless of SET/INHERIT options.
	// to_jsonb permits checking the PG16+ per-membership inheritance option
	// without referencing a nonexistent column on older server versions.
	if err := tx.QueryRow(ctx, `SELECT g.rolcanlogin, count(m.*) FILTER (WHERE m.member = u.oid AND m.roleid = g.oid
		AND NOT m.admin_option AND COALESCE((pg_catalog.to_jsonb(m)->>'inherit_option')::boolean,true)),
		count(m.*) FILTER (WHERE m.member IS NOT NULL AND NOT (m.member = u.oid AND m.roleid = g.oid
		AND NOT m.admin_option AND COALESCE((pg_catalog.to_jsonb(m)->>'inherit_option')::boolean,true)))
		FROM pg_catalog.pg_roles u CROSS JOIN pg_catalog.pg_roles g
		LEFT JOIN pg_catalog.pg_auth_members m ON m.member IN (u.oid,g.oid)
		WHERE u.rolname = $1 AND g.rolname = $2 GROUP BY g.rolcanlogin`, session, group).Scan(&groupLogin, &direct, &invalid); err != nil {
		return nil, err
	}
	if groupLogin || !inherit || direct != 1 || invalid != 0 || session == group {
		p = append(p, "role lacks the required topology: an INHERIT login with exactly one non-admin membership in its designated NOLOGIN leaf group; no other memberships")
	}
	// Ordered pairs (login and group) are checked independently for effective
	// namespace privileges and assumable ownership. Some owner rights cannot
	// be detected by has_*_privilege (an owner can revoke its own ordinary ACL).
	for _, subject := range []string{session, group} {
		var schemaOwner, dbOwner, schemaCreate, dbCreate, privilegedFunctions, indirectRelations bool
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_has_role($1::name,n.nspowner,'MEMBER'),
			pg_catalog.pg_has_role($1::name,d.datdba,'MEMBER'),
			pg_catalog.has_schema_privilege($1::name,n.oid,'CREATE'),
			pg_catalog.has_database_privilege($1::name,d.oid,'CREATE'),
			EXISTS (SELECT 1 FROM pg_catalog.pg_proc f JOIN pg_catalog.pg_namespace fn ON f.pronamespace=fn.oid
			WHERE f.prosecdef AND fn.nspname NOT IN ('pg_catalog','information_schema')
			AND pg_catalog.has_schema_privilege($1::name,fn.oid,'USAGE')
			AND pg_catalog.has_function_privilege($1::name,f.oid,'EXECUTE')
            AND NOT ($2::boolean AND (f.proowner=fn.nspowner OR (fn.nspowner='pg_database_owner'::pg_catalog.regrole AND f.proowner=d.datdba)) AND
              pg_catalog.format('search_path=pg_catalog, %I, pg_temp',fn.nspname) = ANY(f.proconfig) AND
              (f.proname || '(' || pg_catalog.oidvectortypes(f.proargtypes) || ')') IN (
                'evidence_budget_reserve(uuid, uuid, uuid, text, text, text, text, text, bigint, bigint)',
                'evidence_budget_mark_dispatch(uuid)', 'evidence_budget_release_unmarked(uuid)',
                'evidence_budget_settle(uuid, bigint, boolean)', 'evidence_budget_note_overrun(uuid, bigint)', 'evidence_budget_hold_exposure(uuid)', 'evidence_budget_summary(uuid, uuid)'))),
			EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace rn ON c.relnamespace=rn.oid
			WHERE rn.nspname NOT IN ('pg_catalog','information_schema') AND rn.nspname NOT LIKE 'pg\_temp\_%'
			AND pg_catalog.has_schema_privilege($1::name,rn.oid,'USAGE')
			AND (c.relkind IN ('v','m','f') OR (c.relkind IN ('r','p') AND EXISTS
			(SELECT 1 FROM pg_catalog.pg_rewrite rw WHERE rw.ev_class=c.oid)))
			AND (pg_catalog.has_table_privilege($1::name,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
			OR pg_catalog.has_any_column_privilege($1::name,c.oid,'SELECT,INSERT,UPDATE,REFERENCES')))
			FROM pg_catalog.pg_namespace n CROSS JOIN pg_catalog.pg_database d
			WHERE n.nspname=pg_catalog.current_schema() AND d.datname=pg_catalog.current_database()`, subject, group == budgetGroup).
			Scan(&schemaOwner, &dbOwner, &schemaCreate, &dbCreate, &privilegedFunctions, &indirectRelations); err != nil {
			return nil, err
		}
		if schemaOwner {
			p = append(p, subject+" is or can assume the owner role of the evidence schema")
		}
		if dbOwner {
			p = append(p, subject+" is or can assume the owner role of the evidence database")
		}
		if schemaCreate {
			p = append(p, subject+" can CREATE in the evidence schema")
		}
		if dbCreate {
			p = append(p, subject+" can CREATE schemas in the evidence database")
		}
		if privilegedFunctions {
			p = append(p, subject+" can execute application SECURITY DEFINER code")
		}
		if indirectRelations {
			p = append(p, subject+" has table or column access through an application view, foreign table, or relation rule")
		}
	}
	return p, nil
}

func runtimeEvidenceTables(ctx context.Context, tx pgx.Tx) ([]string, int, error) {
	var schema string
	var version int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_schema(),pg_catalog.current_setting('server_version_num')::int`).Scan(&schema, &version); err != nil {
		return nil, 0, err
	}
	rows, err := tx.Query(ctx, `SELECT c.relname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
		WHERE n.nspname=$1 AND c.relkind IN ('r','p','v','m','f') AND c.relname LIKE 'evidence\_%'`, schema)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	found := map[string]bool{}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, 0, err
		}
		found[name] = true
		tables = append(tables, pgx.Identifier{schema, name}.Sanitize())
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	for _, t := range evidenceTables {
		if !found[t] {
			return nil, 0, fmt.Errorf("table %s not found (is the database migrated?)", t)
		}
	}
	return tables, version, nil
}
