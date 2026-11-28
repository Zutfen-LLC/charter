package records_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/records"
)

// Round-4 finding 2 (HIGH): a surviving admission marker whose event-zero
// data was deleted during an interrupted disposal wedges InventoryTurns - the
// whole tenant's lifecycle operations fail before the affected record can be
// reconciled against its durable catalog and disposal plan. Correct inventory
// reconciliation: live storage, durable lifecycle identities and exact-version
// disposal plans are reconciled, plan-backed recovery is permitted, unrelated
// valid lifecycle operations are never blocked, and ordinary disposal resumes
// after release and applicable retention expiry.
func TestSurvivingAdmissionWithDeletedEventZeroDoesNotWedgeLifecycle(t *testing.T) {
	f := newRfx(t)
	// A completed, expired record in matter m1, and an unrelated intact
	// record in matter m2.
	c := seedTurn4Commit(f, "T-R4W", f.p1, f.m1, f.u["alice"], "r4wedge")
	u := f.seedTurn("T-R4U", f.p2, f.m2, f.u["bob"])
	// Complete the disposal planning phase.
	f.sweepAs("carol")
	cRefs := refsOf4(f, c)
	admission := refByKey(f, cRefs, "ns/"+c+"/admissions/x")
	ev0 := refByKey(f, cRefs, "ns/"+c+"/data/events/e0")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), c, nil); err != nil || outcome != "purging" {
		f.t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	outcome := ""
	if err := f.rs.FinishPurgePlanTx(f.ctx(), ptrPrincipal(f.principal("erin")), f.tenant, c, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return f.fb.TurnDisposalRefs(ctx, f.tenant, c)
	}, &outcome); err != nil {
		f.t.Fatal(err)
	}
	// Arrange for the admission marker to remain protected while its
	// event-zero data is deletable, then execute FinishPurge and retain the
	// interrupted operation: the production deletion loop continues after
	// ErrObjectProtected, so the event-zero data and every subsequent event
	// marker are physically deleted while the admission survives.
	protectVersion(f, admission, true)
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), c); err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	// Confirm admission-marker presence and event-zero absence independently.
	if f.fs.isDeleted(admission.Key, admission.Version) {
		t.Fatal("setup: the protected admission marker was deleted")
	}
	if !f.fs.isDeleted(ev0.Key, ev0.Version) {
		t.Fatal("setup: the event-zero data was not deleted during the interrupted disposal")
	}
	// Hold placement over the UNRELATED intact record must not be blocked by
	// the interrupted sibling (the tenant-wide inventory wedge).
	hu, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m2}, "round4 hold over the unrelated record", "r4w-unrelated")
	if err != nil || hu.State != records.HoldEffective {
		t.Fatalf("FINDING 2: hold placement over the unrelated intact record failed (tenant wedge): err %v state %+v", err, hu)
	}
	// Hold placement over the interrupted record must succeed with plan-backed
	// coverage: the remaining in-scope version (the admission) is protected
	// and the historical loss is reported accurately.
	hc, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "round4 hold over the interrupted record", "r4w-interrupted")
	if err != nil || hc.State != records.HoldEffective {
		t.Fatalf("FINDING 2: hold placement over the interrupted record failed (wedge): err %v state %+v", err, hc)
	}
	var item *records.ReportedItem
	for i := range hc.Report.Items {
		if hc.Report.Items[i].TurnID == c {
			item = &hc.Report.Items[i]
		}
	}
	if item == nil || !item.PartiallyDisposed || item.MissingVersions < 6 {
		t.Fatalf("FINDING 2: the interrupted disposal's partial loss is not reported from the durable plan: %+v (want >= 6 missing)", item)
	}
	// Exercise release cleanup, recovery and the disposal retry. The hold
	// placement restored the interrupted record to ACTIVE (the hold-wins
	// rule), so ordinary disposal must resume through the ordinary path
	// after the release: recovery, retention re-expiry, sweep, begin and
	// finish.
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), hc.ID, "release the interrupted record"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), hu.ID, "release the unrelated record"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatalf("FINDING 2: recovery failed over the interrupted disposal: %v", err)
	}
	// The original temporary protection is gone (the hold's claims were
	// reconciled by the releases): the tenant must not remain wedged.
	time.Sleep(1100 * time.Millisecond) // retention (1s) re-expires
	if _, err := f.svc.Sweep(f.ctx(), f.principal("carol")); err != nil {
		t.Fatalf("FINDING 2: sweep remains wedged after the interrupted record converged: %v", err)
	}
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), c, nil); err != nil || outcome != "purging" {
		t.Fatalf("FINDING 2: the interrupted record never resumed disposal (begin outcome %s err %v)", outcome, err)
	}
	outcome, _, err = f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), c)
	if err != nil || outcome != "disposed" {
		t.Fatalf("FINDING 2: the interrupted record's disposal never completed after recovery (outcome %q err %v)", outcome, err)
	}
	if !f.fs.isDeleted(admission.Key, admission.Version) {
		t.Fatalf("FINDING 2: the admission marker was not deleted by the converged disposal")
	}
	// The unrelated intact record remains operational: its disposal
	// converges through the ordinary sweep/begin/finish path.
	time.Sleep(1100 * time.Millisecond) // retention (1s) re-expires
	if _, err := f.svc.Sweep(f.ctx(), f.principal("carol")); err != nil {
		t.Fatalf("FINDING 2: sweep remains wedged after the interrupted record converged: %v", err)
	}
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), u, nil); err != nil || outcome != "purging" {
		f.t.Fatalf("unrelated record: begin outcome %s err %v", outcome, err)
	}
	outcome, _, err = f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), u)
	if err != nil || outcome != "disposed" {
		t.Fatalf("FINDING 2: the unrelated record's disposal failed: outcome %q err %v", outcome, err)
	}
}

// Fail-closed control: an admission whose event-zero data is gone WITHOUT a
// durable disposal plan (an unplanned identity loss) must keep refusing
// lifecycle operations - arbitrary missing event-zero data is never treated
// as authorized disposal. This shape passes at the reviewed head and must
// keep passing.
func TestUnplannedEventZeroLossFailsClosed(t *testing.T) {
	f := newRfx(t)
	x := seedTurn4Commit(f, "T-R4X", f.p1, f.m1, f.u["alice"], "r4unplanned")
	xRefs := refsOf4(f, x)
	ev0 := refByKey(f, xRefs, "ns/"+x+"/data/events/e0")
	// Raw storage loss without any disposal authorization.
	if err := f.fs.DeleteVersion(f.ctx(), ev0.Key, ev0.Version); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "round4 unplanned loss", "r4-unplanned"); err == nil {
		t.Fatal("unplanned event-zero loss must fail closed (hold placement refused)")
	}
	if _, err := f.svc.Sweep(f.ctx(), f.principal("carol")); err == nil {
		t.Fatal("unplanned event-zero loss must fail closed (sweep refused)")
	}
}
