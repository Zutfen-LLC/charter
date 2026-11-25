package evidence_test

import (
	"context"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

// Normal application credentials cannot rewrite or delete protected evidence.
// Two layers are checked separately so a loss of either is visible:
// privileges (the evidence role) and triggers (even the table owner).
func TestApplicationCredentialsCannotRewriteOrDeleteEvidence(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	res, err := f.rec.Process(ctx, f.req("k", "in"), f.model("ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	obj := evidence.SHA256([]byte("ok"))
	for _, p := range []evidence.PGProber{
		{DB: f.pool, AsRole: "charter_evidence_app"}, // privilege layer
		{DB: f.pool}, // trigger layer (table owner)
	} {
		if bad := evidence.QualifyProtection(ctx, p, f.tenant, res.TurnID, obj); len(bad) != 0 {
			t.Errorf("%s: destructive operations succeeded: %v", p.Name(), bad)
		}
	}
	// The probes ran in rolled-back transactions: evidence is intact.
	f.verified(res.TurnID)
}

func TestEvidenceRoleCanAppendAndReadOnly(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	res, _ := f.rec.Process(ctx, f.req("k", "in"), f.model("ok"), nil)
	conn, err := f.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, sql := range []string{
		`ALTER TABLE evidence_events DISABLE TRIGGER evidence_events_rowguard`,
		`DROP TRIGGER evidence_events_rowguard ON evidence_events`,
		`ALTER TABLE evidence_events DISABLE TRIGGER ALL`,
		`DROP TABLE evidence_events CASCADE`,
	} {
		tx, _ := conn.Begin(ctx)
		_, _ = tx.Exec(ctx, `SET LOCAL ROLE charter_evidence_app`)
		if _, err := tx.Exec(ctx, sql); err == nil {
			t.Errorf("evidence role could run: %s", sql)
		}
		_ = tx.Rollback(ctx)
	}
	// GRANT by a non-owner only warns; assert the effect instead.
	tx, _ := conn.Begin(ctx)
	defer tx.Rollback(ctx) //nolint:errcheck
	_, _ = tx.Exec(ctx, `SET LOCAL ROLE charter_evidence_app`)
	_, _ = tx.Exec(ctx, `GRANT UPDATE, DELETE, TRUNCATE ON evidence_events TO charter_evidence_app`)
	var upd, del, trunc bool
	if err := tx.QueryRow(ctx, `SELECT has_table_privilege('charter_evidence_app','evidence_events','UPDATE'),
		has_table_privilege('charter_evidence_app','evidence_events','DELETE'),
		has_table_privilege('charter_evidence_app','evidence_events','TRUNCATE')`).Scan(&upd, &del, &trunc); err != nil {
		t.Fatal(err)
	}
	if upd || del || trunc {
		t.Errorf("evidence role holds destructive privileges: update=%v delete=%v truncate=%v", upd, del, trunc)
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM evidence_events WHERE turn_id=$1::uuid`, res.TurnID).Scan(&n); err != nil || n == 0 {
		t.Fatalf("evidence role cannot read: %v", err)
	}
	// It must not see or touch workspace tables.
	if _, err := tx.Exec(ctx, `SELECT 1 FROM artifacts`); err == nil {
		t.Error("evidence role can read workspace tables")
	}
}

// RECORDED GAP, asserted so nobody can claim otherwise: the table owner (a
// database administrator credential) can still disable the protection in
// PostgreSQL. This backend is therefore NOT retention-enforced and must not be
// used to qualify preservation. A genuine retention-capable backend must pass
// QualifyProtection with its own Prober before the pilot is qualified.
func TestPostgresBackendIsNotRetentionEnforced_RecordedGap(t *testing.T) {
	f := newFx(t, nil)
	if info := f.pg.Info(); info.RetentionEnforced || info.Notice == "" {
		t.Fatalf("backend must not claim retention enforcement: %+v", info)
	}
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `ALTER TABLE evidence_events DISABLE TRIGGER evidence_events_rowguard`); err != nil {
		t.Skipf("owner could not disable the trigger (stronger than expected): %v", err)
	}
	t.Log("gap confirmed: an owner/superuser can disable the append-only triggers; real WORM storage is required for qualification")
}
