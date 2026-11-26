package evidence

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type grantTarget struct {
	database, schema, table, owner string
	address, boot                  string
	port                           int
	dbOID, oid                     uint32
}

type grantTargetLookup interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func lookupGrantTarget(ctx context.Context, q grantTargetLookup, table string) (grantTarget, error) {
	var t grantTarget
	err := q.QueryRow(ctx, `SELECT d.datname,n.nspname,c.relname,pg_catalog.pg_get_userbyid(c.relowner),
		COALESCE(pg_catalog.inet_server_addr()::text,''), EXTRACT(epoch FROM pg_catalog.pg_postmaster_start_time())::text,
		COALESCE(pg_catalog.inet_server_port(),0),d.oid,c.oid
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
		JOIN pg_catalog.pg_database d ON d.datname=pg_catalog.current_database()
		WHERE c.oid=pg_catalog.to_regclass($1) AND n.nspname=pg_catalog.current_schema() AND c.relkind IN ('r','p')`, table).
		Scan(&t.database, &t.schema, &t.table, &t.owner, &t.address, &t.boot, &t.port, &t.dbOID, &t.oid)
	return t, err
}

func rollbackProbe(tx pgx.Tx) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return tx.Rollback(ctx)
}

func (p *PGProber) grantAttempt(ctx context.Context) (Outcome, string) {
	who := p.expected()
	if !validRoleIdent(who) || !p.tables().valid() {
		return Inconclusive, "invalid self-grant identifiers"
	}
	tx, err := p.begin(ctx)
	if err != nil {
		return Inconclusive, err.Error()
	}
	defer rollbackProbe(tx) //nolint:errcheck
	table := p.tables().Events
	if p.scope != nil {
		if err := p.scope.checkRuntime(ctx, tx); err != nil {
			return Inconclusive, "self-grant target changed: " + err.Error()
		}
		table = p.scope.events.qualified()
	}
	target, err := lookupGrantTarget(ctx, tx, table)
	if err != nil || (p.scope != nil && target != p.scope.events) {
		return Inconclusive, fmt.Sprintf("self-grant target did not resolve exactly: %v", err)
	}
	return runGrantAttempt(ctx, tx, target, who)
}

// runGrantAttempt is non-vacuous: only a valid GRANT (possibly with a warning
// and no effect) or a genuine SQL privilege error can reach the ACL check.
// The enclosing transaction is never committed, even when the probe succeeds.
func runGrantAttempt(ctx context.Context, tx pgx.Tx, target grantTarget, who string) (out Outcome, detail string) {
	defer func() {
		if err := rollbackProbe(tx); err != nil {
			out, detail = Inconclusive, "transaction rollback failed: "+err.Error()
		}
	}()
	if !validRoleIdent(who) || target.oid == 0 || !identRe.MatchString(target.table) || !validRoleIdent(target.schema) {
		return Inconclusive, "invalid self-grant target or role identifier"
	}
	sp, err := tx.Begin(ctx)
	if err != nil {
		return Inconclusive, "savepoint creation failed: " + err.Error()
	}
	qualified := target.qualified()
	tag, attemptErr := sp.Exec(ctx, `GRANT UPDATE, DELETE, TRUNCATE ON TABLE `+qualified+` TO `+pgx.Identifier{who}.Sanitize())
	if attemptErr != nil {
		if err := rollbackProbe(sp); err != nil {
			return Inconclusive, "failed GRANT savepoint rollback: " + err.Error()
		}
		var pe *pgconn.PgError
		if !errors.As(attemptErr, &pe) || pe.Code != "42501" {
			return Inconclusive, "unrelated GRANT failure: " + attemptErr.Error()
		}
	} else {
		if tag.String() != "GRANT" {
			return Inconclusive, "self-grant did not produce a GRANT command tag"
		}
		if err := sp.Commit(ctx); err != nil {
			return Inconclusive, "savepoint completion failed: " + err.Error()
		}
	}
	var upd, del, trunc bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege(current_user,$1::oid,'UPDATE'),
		pg_catalog.has_table_privilege(current_user,$1::oid,'DELETE'),pg_catalog.has_table_privilege(current_user,$1::oid,'TRUNCATE')`, target.oid).
		Scan(&upd, &del, &trunc); err != nil {
		return Inconclusive, "privilege readback failed: " + err.Error()
	}
	if upd || del || trunc {
		return Allowed, fmt.Sprintf("privileges held after self-grant: update=%v delete=%v truncate=%v", upd, del, trunc)
	}
	if attemptErr != nil {
		return Refused, "completed self-grant attempt received PostgreSQL insufficient_privilege"
	}
	return Refused, "completed GRANT held no destructive privilege (warning/no effect)"
}

// An indirect authority check is a catalog-backed boundary check: the sole
// allowed leaf group cannot lead to more privileged roles. An unexpected path
// never qualifies even if it happens not to have destructive ACLs today.
func (p *PGProber) indirectAttempt(ctx context.Context) (Outcome, string) {
	if p.AsRole != "" {
		return Inconclusive, "indirect authority requires a direct login"
	}
	tx, err := p.begin(ctx)
	if err != nil {
		return Inconclusive, err.Error()
	}
	defer rollbackProbe(tx) //nolint:errcheck
	if err := p.scope.checkRuntime(ctx, tx); err != nil {
		return Inconclusive, "indirect authority target changed: " + err.Error()
	}
	var ev, ws bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_has_role(current_user,$1,'USAGE'),pg_catalog.pg_has_role(current_user,$2,'USAGE')`, evidenceGroup, workspaceGroup).Scan(&ev, &ws); err != nil {
		return Inconclusive, "role topology lookup failed: " + err.Error()
	}
	out, detail := Refused, "no role-assumption or namespace authority outside the designated leaf role"
	switch {
	case ev && ws:
		out, detail = Allowed, "credential is a member of both runtime groups"
	case !ev && !ws:
		out, detail = Inconclusive, "credential is not a provisioned runtime login"
	default:
		group := workspaceGroup
		if ev {
			group = evidenceGroup
		}
		problems, err := runtimeTopology(ctx, tx, p.Identity, group)
		if err != nil {
			return Inconclusive, "role topology verification failed: " + err.Error()
		}
		if len(problems) > 0 {
			out, detail = Allowed, fmt.Sprintf("outside the required role and DDL boundary: %v", problems)
		}
	}
	if err := rollbackProbe(tx); err != nil {
		return Inconclusive, "transaction rollback failed: " + err.Error()
	}
	return out, detail
}
