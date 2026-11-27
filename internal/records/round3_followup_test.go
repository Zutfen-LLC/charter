package records_test

import (
	"encoding/json"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/records"
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

