package evidence

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Prober attempts to rewrite or delete protected evidence using the normal
// application credential. Every method returns nil if the destructive
// operation SUCCEEDED (protection failed) and an error if it was refused.
// Implementations must make the attempt non-destructive when it unexpectedly
// succeeds (the PG prober rolls back). A genuine retention-capable backend must
// provide its own Prober; running QualifyProtection against it is the
// qualification step the pilot still owes (docs/evidence-capture.md).
type Prober interface {
	Name() string
	RewriteEvent(ctx context.Context, tenantID, turnID string) error
	DeleteEvent(ctx context.Context, tenantID, turnID string) error
	RewriteObject(ctx context.Context, tenantID, sha string) error
	DeleteObject(ctx context.Context, tenantID, sha string) error
	DeleteTurn(ctx context.Context, tenantID, turnID string) error
	TruncateAll(ctx context.Context) error
}

// QualifyProtection runs every destructive attempt and returns the ones that
// were NOT refused. An empty result means the credential could not rewrite or
// delete protected evidence by any attempted route.
func QualifyProtection(ctx context.Context, p Prober, tenantID, turnID, objectSHA string) []string {
	var bad []string
	try := func(name string, err error) {
		if err == nil {
			bad = append(bad, name)
		}
	}
	try("rewrite event", p.RewriteEvent(ctx, tenantID, turnID))
	try("delete event", p.DeleteEvent(ctx, tenantID, turnID))
	try("rewrite object", p.RewriteObject(ctx, tenantID, objectSHA))
	try("delete object", p.DeleteObject(ctx, tenantID, objectSHA))
	try("delete turn", p.DeleteTurn(ctx, tenantID, turnID))
	try("truncate", p.TruncateAll(ctx))
	return bad
}

// PGProber attacks the PostgreSQL backend as AsRole (a role the connecting user
// may SET ROLE to, e.g. charter_evidence_app), or as the connection's own
// role when AsRole is empty (the table owner: only triggers stand in the way).
type PGProber struct {
	DB     *pgxpool.Pool
	AsRole string
}

func (p PGProber) Name() string {
	if p.AsRole == "" {
		return "postgres/table-owner"
	}
	return "postgres/" + p.AsRole
}

func (p PGProber) run(ctx context.Context, sql string, args ...any) error {
	conn, err := p.DB.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("probe setup: %w", err)
	}
	defer conn.Release()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // ALWAYS rolled back, even if the attack worked
	if p.AsRole != "" {
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE `+p.AsRole); err != nil {
			return fmt.Errorf("probe setup: %w", err) // setup failure must not read as "refused"
		}
	}
	tag, err := tx.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 && sql[:8] != "TRUNCATE" {
		return fmt.Errorf("probe matched no rows")
	}
	return nil
}

func (p PGProber) RewriteEvent(ctx context.Context, tenant, turn string) error {
	return p.run(ctx, `UPDATE evidence_events SET body = body || ' ' WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, tenant, turn)
}
func (p PGProber) DeleteEvent(ctx context.Context, tenant, turn string) error {
	return p.run(ctx, `DELETE FROM evidence_events WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, tenant, turn)
}
func (p PGProber) RewriteObject(ctx context.Context, tenant, sha string) error {
	return p.run(ctx, `UPDATE evidence_objects SET bytes = '\x00' WHERE tenant_id=$1::uuid AND sha256=$2`, tenant, sha)
}
func (p PGProber) DeleteObject(ctx context.Context, tenant, sha string) error {
	return p.run(ctx, `DELETE FROM evidence_objects WHERE tenant_id=$1::uuid AND sha256=$2`, tenant, sha)
}
func (p PGProber) DeleteTurn(ctx context.Context, tenant, turn string) error {
	return p.run(ctx, `DELETE FROM evidence_turns WHERE tenant_id=$1::uuid AND turn_id=$2::uuid`, tenant, turn)
}
func (p PGProber) TruncateAll(ctx context.Context) error {
	return p.run(ctx, `TRUNCATE evidence_events, evidence_objects, evidence_turns CASCADE`)
}
