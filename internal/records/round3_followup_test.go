package records_test

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Round-3 follow-up review findings (independent adversarial review,
// lanes 3 and 4):
//
//  1. Repeated recovery with an UNCHANGED repair condition appends
//     duplicate identical audit rows (recovery is not audit-idempotent).
//  2. The repair-audit insert and the repair-state update are separate
//     operations: an audit failure is logged while the state change
//     still lands, so repair state can exist without its audit event.
//
// Both are pinned here; the corrections make a repair-state transition a
// single atomic transaction (state + audit row commit together) that is
// written only when the stored state actually changes.

// Repeated recovery of the same persistent uncovered condition must not
// append another identical audit row: the repair state is recorded once
// per transition, and unchanged states are idempotent no-ops (the
// append-only trail keeps every genuine transition).
func TestRecoveryRepairAuditIsIdempotent(t *testing.T) {
	f := newRfx(t)
	h := f.placeHold("carol", f.m1, "effective hold with a persistent repair gap")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	id := f.seedTurn("T-R3P", f.p1, f.m1, f.u["alice"])
	f.fb.failEnum[id] = &transportErr{}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	n1, err := countAudit(f, "hold.protection_repair_pending")
	if err != nil || n1 == 0 {
		t.Fatalf("setup: the first recovery recorded no pending-repair audit row (n=%d err=%v)", n1, err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	n2, err := countAudit(f, "hold.protection_repair_pending")
	if err != nil {
		t.Fatal(err)
	}
	if n2 != n1 {
		t.Fatalf("REVIEW FINDING: repeated recovery of an UNCHANGED repair condition appended duplicate audit rows (n1=%d n2=%d)", n1, n2)
	}
	// A genuine transition still audits: resolving the gap records the
	// verified repair exactly once.
	f.fb.failEnum[id] = nil
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	nComplete, err := countAudit(f, "hold.protection_repair_complete")
	if err != nil || nComplete != 1 {
		t.Fatalf("the verified-repair transition must be audited exactly once (n=%d err=%v)", nComplete, err)
	}
}

// The repair-state write and its audit row are atomic: when the audit
// insert is refused, the repair state must NOT change (no state without
// its audit event), and a subsequent successful retry records both.
func TestRecoveryRepairStateIsAtomicWithItsAuditRow(t *testing.T) {
	f := newRfx(t)
	h := f.placeHold("carol", f.m1, "effective hold with a refused audit insert")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	id := f.seedTurn("T-R3Q", f.p1, f.m1, f.u["alice"])
	f.fb.failEnum[id] = &transportErr{}

	// Fault injection at the storage boundary: the audit insert for the
	// pending-repair action is refused while every other write succeeds.
	if _, err := f.pool.Exec(f.ctx(), `CREATE OR REPLACE FUNCTION charter_refuse_repair_pending() RETURNS trigger AS $$
BEGIN
	IF NEW.action = 'hold.protection_repair_pending' THEN
		RAISE EXCEPTION 'audit insert refused by test trigger';
	END IF;
	RETURN NEW;
END $$ LANGUAGE plpgsql`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(f.ctx(), `CREATE TRIGGER refuse_repair_pending BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION charter_refuse_repair_pending()`); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatalf("recovery must surface the audit failure without aborting other recovery work: %v", err)
	}
	var reportRaw []byte
	if err := f.pool.QueryRow(f.ctx(), `SELECT report FROM holds WHERE id=$1`, h.ID).Scan(&reportRaw); err != nil {
		t.Fatal(err)
	}
	stored := map[string]any{}
	if err := json.Unmarshal(reportRaw, &stored); err != nil {
		t.Fatal(err)
	}
	if pending, ok := stored["repair_pending"].([]any); ok && len(pending) > 0 {
		t.Fatalf("REVIEW FINDING: the repair state changed although its audit insert was refused (repair_pending=%v)", pending)
	}

	// The retry after the audit subsystem recovers records BOTH the state
	// and the audit row (the condition is never silently lost).
	if _, err := f.pool.Exec(f.ctx(), `DROP TRIGGER refuse_repair_pending ON audit_log`); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx(), `SELECT report FROM holds WHERE id=$1`, h.ID).Scan(&reportRaw); err != nil {
		t.Fatal(err)
	}
	stored = map[string]any{}
	if err := json.Unmarshal(reportRaw, &stored); err != nil {
		t.Fatal(err)
	}
	if pending, _ := stored["repair_pending"].([]any); len(pending) == 0 {
		t.Fatalf("the retried recovery did not record the pending repair state (%v)", stored)
	}
	if n, err := countAudit(f, "hold.protection_repair_pending"); err != nil || n != 1 {
		t.Fatalf("the retried recovery did not record the audit row (n=%d err=%v)", n, err)
	}
}

// Concurrent finish retries against a CI-class SMALL pool: the finisher
// must never acquire a SECOND pooled connection while its fence
// transaction is open (the round-3 hosted-CI deadlock - every
// catalog/plan read inside the deleter and verify callbacks reuses the
// transaction's connection). The buggy shape hangs; this test fails fast
// through the watchdog instead.
func TestConcurrentFinishRetriesUnderExhaustedPool(t *testing.T) {
	f := newRfx(t)
	ctx := context.Background()
	schema := f.pool.Config().ConnConfig.RuntimeParams["search_path"]
	cfg, err := pgxpool.ParseConfig(os.Getenv("CHARTER_TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	cfg.ConnConfig.RuntimeParams["application_name"] = schema + "-smallpool"
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer small.Close()
	f.rs.DB = small

	id := f.seedTurn("T-R3S", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-R3S"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	_ = id

	type result struct {
		outcome string
		err     error
	}
	results := make(chan result, 4)
	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-R3S"))
				results <- result{outcome: outcome, err: err}
			}()
		}
		wg.Wait()
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		// Unwedge the workers before failing so the schema cleanup does
		// not block on their locks: force-abort the small pool's
		// backends (the stuck row-lock waits error out, the blocked pool
		// acquires see the pool closed) and give them a moment to unwind.
		_, _ = f.pool.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name=$1`, schema+"-smallpool")
		small.Close()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
		}
		t.Fatal("REVIEW FINDING (CI): concurrent finishes deadlocked on the connection pool - a nested pooled acquisition runs inside the open fence transaction")
	}
	disposed := 0
	for i := 0; i < 4; i++ {
		r := <-results
		if r.err != nil && r.outcome != "disposed" && r.outcome != "stale_retry" {
			t.Fatalf("finish error: %v (outcome %q)", r.err, r.outcome)
		}
		if r.outcome == "disposed" {
			disposed++
		}
	}
	if disposed != 1 {
		t.Fatalf("exactly one finish must dispose, got %d", disposed)
	}
	if it := f.itemByID(f.turnID("T-R3S")); it.State != records.ItemDisposed {
		t.Fatalf("the purged item is not disposed: %s", it.State)
	}
}
