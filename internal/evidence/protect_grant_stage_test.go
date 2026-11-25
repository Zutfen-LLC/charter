package evidence

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var grantProbeFault = errors.New("synthetic transaction fault")

type grantFaultTx struct {
	pgx.Tx
	mode      string
	readbacks int
}

func (tx *grantFaultTx) Begin(ctx context.Context) (pgx.Tx, error) {
	if tx.mode == "create-savepoint" {
		return nil, grantProbeFault
	}
	s, err := tx.Tx.Begin(ctx)
	if err != nil {
		return nil, err
	}
	return grantFaultSavepoint{s, tx.mode}, nil
}

func (tx *grantFaultTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	tx.readbacks++
	return tx.Tx.QueryRow(ctx, sql, args...)
}

func (tx *grantFaultTx) Rollback(ctx context.Context) error {
	if err := tx.Tx.Rollback(ctx); err != nil {
		return err
	}
	if tx.mode == "outer-rollback" {
		return grantProbeFault
	}
	return nil
}

type grantFaultSavepoint struct {
	pgx.Tx
	mode string
}

func (sp grantFaultSavepoint) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if sp.mode == "malformed-operation" {
		return sp.Tx.Exec(ctx, `GRANT`, args...)
	}
	if sp.mode == "unrelated-command" {
		return sp.Tx.Exec(ctx, `SELECT 1`, args...)
	}
	return sp.Tx.Exec(ctx, sql, args...)
}

func (sp grantFaultSavepoint) Commit(ctx context.Context) error {
	if err := sp.Tx.Commit(ctx); err != nil {
		return err
	}
	if sp.mode == "finish-savepoint" {
		return grantProbeFault
	}
	return nil
}

func TestProtectionGrantStagesAreNonVacuous(t *testing.T) {
	ctx := context.Background()
	owner := testdb.New(t)
	c := testdb.Runtime(t, owner)
	target, err := lookupGrantTarget(ctx, owner, "evidence_events")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		mode, detail string
		want         Outcome
		reads        int
	}{
		{"create-savepoint", "savepoint creation failed", Inconclusive, 0},
		{"malformed-operation", "unrelated GRANT failure", Inconclusive, 0},
		{"unrelated-command", "did not produce a GRANT command tag", Inconclusive, 0},
		{"finish-savepoint", "savepoint completion failed", Inconclusive, 0},
		{"outer-rollback", "transaction rollback failed", Inconclusive, 1},
		{"warning-or-no-effect", "warning/no effect", Refused, 1},
		{"genuine-privilege-refusal", "insufficient_privilege", Refused, 1},
	} {
		t.Run(test.mode, func(t *testing.T) {
			pool, role := c.Evidence, c.EvidenceRole
			if test.mode == "genuine-privilege-refusal" {
				pool, role = c.Workspace, c.WorkspaceRole
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			probe := &grantFaultTx{Tx: tx, mode: test.mode}
			got, why := runGrantAttempt(ctx, probe, target, role)
			if got != test.want || !strings.Contains(why, test.detail) || probe.readbacks != test.reads {
				t.Fatalf("got %s (%s), reads=%d, expected %s (%s), reads=%d", got, why, probe.readbacks, test.want, test.detail, test.reads)
			}
		})
	}
}
