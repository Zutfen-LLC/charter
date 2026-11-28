package records_test

import (
	"errors"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/records"
)

// Round-5 review lane 1 (HIGH): an unreadable durable disposal plan is an
// UNKNOWN version set, never an absent one. Both sharedReferences and
// turnReferenceSet silently ignored a plan-read error whenever the live
// enumeration succeeded - and a SUCCEEDED enumeration can be truncated, so
// the unknown durable references were fenced by nothing while an
// irreversible operation proceeded.

// corruptPlanRow makes one planned version row unreadable (a scan failure
// for that turn's plan load) without touching any other turn's plan: the
// fault injection models a transient or corrupt plan read.
func corruptPlanRow(f *rfx, turn, key string) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx(), `ALTER TABLE disposal_plans ALTER COLUMN disposition DROP NOT NULL`); err != nil {
		f.t.Fatal(err)
	}
	tag, err := f.pool.Exec(f.ctx(), `UPDATE disposal_plans SET disposition=NULL WHERE tenant_id=$1 AND turn_id=$2 AND key=$3`, f.tenant, turn, key)
	if err != nil {
		f.t.Fatal(err)
	}
	if tag.RowsAffected() != 1 {
		f.t.Fatalf("plan row injection affected %d rows", tag.RowsAffected())
	}
}

// restorePlanRow repairs the corrupted plan row (storage recovered).
func restorePlanRow(f *rfx, turn, key string) {
	f.t.Helper()
	if _, err := f.pool.Exec(f.ctx(), `UPDATE disposal_plans SET disposition='planned' WHERE tenant_id=$1 AND turn_id=$2 AND key=$3`, f.tenant, turn, key); err != nil {
		f.t.Fatal(err)
	}
}

// The disposal of a record whose partially disposed sibling's durable plan
// is UNREADABLE must be REFUSED (fail closed): the sibling's reference set
// is unknown, so the shared version its truncated live enumeration no
// longer lists cannot be proven unshared. At the defective head the
// deletion proceeded and destroyed the shared version.
func TestUnreadableSiblingPlanRefusesSharedDeletion(t *testing.T) {
	f := newRfx(t)
	b2 := seedTurn4Commit(f, "T-R5B", f.p2, f.m2, f.u["bob"], "r5fwd")
	a2 := f.seedTurn3Commit("T-R5A", f.p1, f.m1, f.u["alice"], "r5fwd")
	shared := sharedRefOf(f, "r5fwd")
	b2Refs, err := interruptDisposal(f, b2)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/admissions/x"), false)
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/data/events/e0"), false)
	// The sibling's durable plan becomes unreadable for the shared version's
	// row while every live enumeration still succeeds.
	corruptPlanRow(f, b2, shared.Key)
	// Dispose A2.
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), a2, nil); err != nil || outcome != "purging" {
		f.t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	outcome, _, ferr := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), a2)
	if ferr == nil {
		t.Fatalf("FINDING: the disposal was not refused while the sibling's durable plan was unreadable (outcome %q)", outcome)
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("FINDING: the shared object version was deleted while the partially disposed sibling's durable plan was unreadable: the truncated live enumeration fenced nothing")
	}
	// Storage recovers: the ordinary retry converges with the shared version
	// retained (the sibling's plan still references it).
	restorePlanRow(f, b2, shared.Key)
	outcome, _, ferr = f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), a2)
	if ferr != nil || outcome != "disposed" {
		t.Fatalf("retry: outcome %q err %v", outcome, ferr)
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("retry: the shared object version did not survive the converged disposal")
	}
}

// The same fail-closed rule governs native legal-hold removal: releasing a
// hold must not clear the protection of a version that a partially disposed
// sibling's UNREADABLE durable plan may still reference. At the defective
// head the release cleared it.
func TestUnreadableSiblingPlanRefusesProtectionRemoval(t *testing.T) {
	f := newRfx(t)
	b2 := seedTurn4Commit(f, "T-R5B2", f.p2, f.m2, f.u["bob"], "r5rel")
	a2 := f.seedTurn3Commit("T-R5A2", f.p1, f.m1, f.u["alice"], "r5rel")
	shared := sharedRefOf(f, "r5rel")
	if !contains4(refsOf4(f, a2), shared) {
		t.Fatalf("setup: the live referencing record does not reference the shared object")
	}
	b2Refs, err := interruptDisposal(f, b2)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/admissions/x"), false)
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/data/events/e0"), false)
	// A hold over the live referencing record claims and protects the shared
	// version.
	h := f.placeHold("carol", f.m1, "round5 hold over the live referencing record")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("setup: the shared version is not protected (state %q)", state)
	}
	// The sibling's durable plan becomes unreadable.
	corruptPlanRow(f, b2, shared.Key)
	// The release must refuse to clear the shared version's protection.
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "release with an unreadable sibling plan"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("FINDING: the protection of the shared version was cleared while a partially disposed sibling's durable plan was unreadable (state %q)", state)
	}
	// The report durably records the outstanding cleanup (conservative:
	// pending means over-protection).
	stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Report.ReleaseCleanupPending) == 0 {
		t.Fatalf("FINDING: the refused cleanup was not recorded as pending: %+v", stored.Report)
	}
	// Storage recovers: the release retry converges (the sibling is not held
	// and the live record's hold is released, so the version's protection is
	// no longer required).
	restorePlanRow(f, b2, shared.Key)
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "retry after recovery"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state == "ON" {
		t.Fatalf("retry: the shared version's protection did not converge (state %q)", state)
	}
}

// Round-5 review lane 4 (HIGH): SetRepairState must bind the supplied tenant
// to the locked hold: a foreign tenant's identifier never authorizes a
// report mutation or an audit attribution for another tenant's hold.
func TestSetRepairStateRefusesForeignTenant(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-R5T", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "round5 repair state tenant binding")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold=%s", h.State)
	}
	// The foreign tenant (f.other) asks for a repair-state write on tenant
	// A's hold with the CURRENT epoch.
	if _, err := f.rs.SetRepairState(f.ctx(), f.other, h.ID, []string{"T-R5T"}, "foreign tenant write", h.Epoch); err == nil {
		t.Fatal("FINDING: a foreign tenant identifier authorized a repair-state publication for another tenant's hold")
	}
	stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Report.RepairPending) != 0 || stored.Report.RepairError != "" {
		t.Fatalf("FINDING: the foreign-tenant write mutated the hold's report: %+v", stored.Report)
	}
	var repairs int
	if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM audit_log WHERE action LIKE 'hold.protection_repair%' AND detail->>'hold_id'=$1`, h.ID).Scan(&repairs); err != nil {
		t.Fatal(err)
	}
	if repairs != 0 {
		t.Fatalf("FINDING: %d repair audit rows were attributed to the foreign tenant", repairs)
	}
	// The owning tenant's own write (control) still works after the guard.
	if changed, err := f.rs.SetRepairState(f.ctx(), f.tenant, h.ID, []string{"T-R5T"}, "", h.Epoch); err != nil || !changed {
		t.Fatalf("control: the owning tenant's repair-state write failed: changed=%v err=%v", changed, err)
	}
}
