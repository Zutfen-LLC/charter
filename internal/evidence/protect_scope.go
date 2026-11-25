package evidence

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// probeScope pins all three relations and the exact synthetic rows used by one
// qualification. A lookup and row-existence check share the admin transaction;
// runtime attempts use these qualified identifiers, not ambient search_path.
type probeScope struct {
	turns, events, objects grantTarget
	tenant, turn, object   string
}

func (s probeScope) tables() TableNames {
	return TableNames{s.turns.qualified(), s.events.qualified(), s.objects.qualified()}
}

func (t grantTarget) qualified() string { return pgx.Identifier{t.schema, t.table}.Sanitize() }

func resolveScope(ctx context.Context, tx pgx.Tx, tables TableNames, tenant, turn, object string) (probeScope, error) {
	s := probeScope{tenant: tenant, turn: turn, object: object}
	for _, target := range []struct {
		name string
		out  *grantTarget
	}{{tables.Turns, &s.turns}, {tables.Events, &s.events}, {tables.Objects, &s.objects}} {
		t, err := lookupGrantTarget(ctx, tx, target.name)
		if err != nil {
			return probeScope{}, fmt.Errorf("target lookup for %s: %w", target.name, err)
		}
		*target.out = t
	}
	return s, nil
}

func (p *PGProber) adminScope(ctx context.Context, tenant, turn, object string) (probeScope, error) {
	tx, err := p.Admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return probeScope{}, fmt.Errorf("admin context: %w", err)
	}
	defer rollbackProbe(tx) //nolint:errcheck
	s, err := resolveScope(ctx, tx, p.tables(), tenant, turn, object)
	if err != nil {
		return probeScope{}, err
	}
	t := s.tables()
	var ev, ob, tu int
	if err := tx.QueryRow(ctx, fmt.Sprintf(`SELECT
		(SELECT count(*) FROM %s WHERE tenant_id=$1::uuid AND turn_id=$2::uuid),
		(SELECT count(*) FROM %s WHERE tenant_id=$1::uuid AND sha256=$3),
		(SELECT count(*) FROM %s WHERE tenant_id=$1::uuid AND turn_id=$2::uuid)`, t.Events, t.Objects, t.Turns), tenant, turn, object).
		Scan(&ev, &ob, &tu); err != nil {
		return probeScope{}, fmt.Errorf("target lookup: %w", err)
	}
	if ev == 0 || ob == 0 || tu == 0 {
		return probeScope{}, fmt.Errorf("target absent (events=%d objects=%d turns=%d)", ev, ob, tu)
	}
	if err := rollbackProbe(tx); err != nil {
		return probeScope{}, fmt.Errorf("target verification transaction failed: %w", err)
	}
	return s, nil
}

func (s probeScope) checkRuntime(ctx context.Context, tx pgx.Tx) error {
	actual, err := resolveScope(ctx, tx, s.tables(), s.tenant, s.turn, s.object)
	if err != nil {
		return err
	}
	if actual != s {
		return fmt.Errorf("runtime relations do not match the verified PostgreSQL targets")
	}
	return nil
}
