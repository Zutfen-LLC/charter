package evidence_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestC05BudgetRuntimePrivilegesAndOverrun(t *testing.T) {
	ctx := context.Background()
	owner := testdb.New(t)
	creds := testdb.Runtime(t, owner)
	suffix := strings.ReplaceAll(evidence.NewUUID(), "-", "")
	name := "charter_c05_" + suffix
	if _, err := owner.Exec(ctx, "CREATE ROLE "+name+" LOGIN PASSWORD '"+suffix+"'; GRANT charter_budget_app TO "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := owner.Exec(ctx, "DROP ROLE "+name); err != nil {
			t.Error(err)
		}
	})
	cfg := owner.Config()
	cfg.ConnConfig.User = name
	cfg.ConnConfig.Password = suffix
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := evidence.CheckBudgetRuntime(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := evidence.CheckWorkspaceRuntime(ctx, creds.Workspace); err != nil {
		t.Fatal(err)
	}
	if err := evidence.CheckEvidenceRuntime(ctx, creds.Evidence); err != nil {
		t.Fatal(err)
	}
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, "issuer", "synthetic", "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	create := func() string {
		p, err := st.CreateProject(ctx, tenant, "synthetic")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p1, p2 := create(), create()
	a, b := evidence.PG{DB: owner}, evidence.PG{DB: pool}
	capT := int64(100)
	for _, p := range []string{p1, p2} {
		pol := evidence.BudgetPolicy{TenantID: tenant, ProjectID: p, ProjectCap: 100, AllowedModels: []string{"det-a"}, LocalOnly: true}
		if p == p1 {
			pol.TenantCap = &capT
		}
		if err := a.SetPolicy(ctx, pol); err != nil {
			t.Fatal(err)
		}
		if err := b.SetPolicy(ctx, pol); err == nil {
			t.Fatal("budget runtime mutated policy")
		}
	}
	r := func(p, key string, n int64) evidence.BudgetReservation {
		return evidence.BudgetReservation{TenantID: tenant, ProjectID: p, TurnID: evidence.NewUUID(), IdempotencyKey: key, ModelID: "det-a", Destination: evidence.Destination{Provider: "s", EndpointID: "local", ModelID: "a"}, Amount: n}
	}
	claim := r(p1, "stable", 100)
	receipt, err := b.Reserve(ctx, claim)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := b.Reserve(ctx, claim)
	if err != nil || copy.ID != receipt.ID || !copy.Replayed {
		t.Fatalf("bad replay: %+v %v", copy, err)
	}
	claim.TurnID = evidence.NewUUID()
	if _, err := b.Reserve(ctx, claim); err == nil {
		t.Fatal("conflict reserved again")
	}
	if _, err := b.Reserve(ctx, r(p2, "other", 1)); err == nil {
		t.Fatal("uncapped sibling bypassed tenant cap")
	}
	for _, pool := range []*pgxpool.Pool{creds.Workspace, creds.Evidence} {
		for _, q := range []string{"SELECT * FROM evidence_budget_reservations", "DELETE FROM evidence_budget_reservations", "SELECT evidence_budget_settle($1::uuid,0,false)"} {
			var err error
			if strings.Contains(q, "$1") {
				_, err = pool.Exec(ctx, q, receipt.ID)
			} else {
				_, err = pool.Exec(ctx, q)
			}
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "42501" {
				t.Fatalf("ordinary credential %q should lack budget access: %v", pool.Config().ConnConfig.User, err)
			}
		}
	}
	if err := b.MarkDispatchPossible(ctx, receipt.ID); err != nil {
		t.Fatal(err)
	}
	if err := b.MarkDispatchPossible(ctx, receipt.ID); !errors.Is(err, evidence.ErrBudgetTransition) {
		t.Fatal("dispatch marker not one-shot")
	}
	if err := b.ReleaseUnmarked(ctx, receipt.ID); err == nil {
		t.Fatal("armed obligation erased")
	}
	cost := int64(110)
	for range 2 {
		if err := b.Settle(ctx, receipt.ID, &cost); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Settle(ctx, receipt.ID, nil); err == nil {
		t.Fatal("conflicting settlement accepted")
	}
	s, err := b.Summary(ctx, tenant, p1)
	if err != nil || s.Settled != 110 || !s.Frozen || s.Remaining != 0 {
		t.Fatalf("overrun: %+v %v", s, err)
	}
	if _, err := b.Reserve(ctx, r(p2, "after", 0)); err == nil {
		t.Fatal("tenant overrun freeze bypassed")
	}
	if _, err := creds.Workspace.Exec(ctx, `DELETE FROM projects WHERE id=$1`, p1); err != nil {
		t.Fatal(err)
	}
	if s, err := b.Summary(ctx, tenant, p1); err != nil || s.Settled != 110 {
		t.Fatal("workspace deletion erased the obligation")
	}
	if _, err := b.Summary(ctx, evidence.NewUUID(), p1); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("cross scope summary: %v", err)
	}
}
