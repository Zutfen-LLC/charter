package records_test

import (
	"errors"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/records"
)

// Round-4 finding 3 (MEDIUM): release cleanup reports must converge to the
// actual committed ownership ledger, including zero claims. A transient
// native-clear failure durably records release_cleanup_pending; an idempotent
// release retry that subsequently clears every claim returns without updating
// the report, and recovery skips holds with zero ledger claims before
// refreshing their cleanup report - so the report stays stale forever despite
// verified clearance.
func TestReleaseCleanupFailureRemainsRetryableThroughRecovery(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-R4", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "round4 release cleanup retry")
	refs := refsOf(f, f.turns[0])
	if h.State != records.HoldEffective || len(refs) == 0 {
		t.Fatalf("setup: hold=%q refs=%d", h.State, len(refs))
	}
	// Inject a transient native-clear failure: the first release must persist
	// its outstanding claims as the durable release_cleanup_pending report.
	fired := false
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "cleanup" && !fired {
			fired = true
			return errors.New("injected transient native-clear failure")
		}
		return nil
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "faulted cleanup"); err != nil {
		t.Fatalf("release: %v", err)
	}
	f.svc.Hooks.StorageFault = nil
	stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Report.ReleaseCleanupPending) == 0 {
		t.Fatalf("setup: cleanup failure was not retained durably: %+v", stored.Report)
	}
	// Storage recovers. The idempotent release retry clears every claim: the
	// report must converge to the committed ledger (zero outstanding claims).
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "retry cleanup"); err != nil {
		t.Fatalf("release retry: %v", err)
	}
	// Verify the native protection state and the committed claims ledger.
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("retry did not clear the native legal hold for %s", r.Key)
		}
	}
	var claims int
	if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM hold_version_claims WHERE hold_id=$1`, h.ID).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if claims != 0 {
		t.Fatalf("retry left %d committed claims after verified clearance", claims)
	}
	// Repeated recovery must keep the report converged to the ledger: a
	// zero-claim hold is exactly the state whose stale report must clear.
	for i := 0; i < 2; i++ {
		if err := f.svc.Recover(f.ctx()); err != nil {
			t.Fatal(err)
		}
		stored, err = f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(stored.Report.ReleaseCleanupPending) != 0 {
			t.Fatalf("FINDING 3: release_cleanup_pending remains stale despite zero outstanding claims (recovery pass %d): %+v", i+1, stored.Report.ReleaseCleanupPending)
		}
	}
}

// Control: recovery alone (without a release retry) still converges a faulted
// release - the outstanding claims drive reconcileClaims and the report
// refresh. This shape passes at the reviewed head and must keep passing.
func TestRecoverConvergesFaultedReleaseCleanup(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-R4C", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "round4 recover cleanup control")
	fired := false
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "cleanup" && !fired {
			fired = true
			return errors.New("injected transient native-clear failure")
		}
		return nil
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "faulted cleanup"); err != nil {
		t.Fatal(err)
	}
	f.svc.Hooks.StorageFault = nil
	stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Report.ReleaseCleanupPending) == 0 {
		t.Fatalf("setup: cleanup failure was not retained durably: %+v", stored.Report)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	stored, err = f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Report.ReleaseCleanupPending) != 0 {
		t.Fatalf("control: recovery did not converge the faulted cleanup report: %+v", stored.Report.ReleaseCleanupPending)
	}
}

// Round-4 finding 3 follow-up: stale effective-hold repair results must never
// be published after release. A hold released between recovery's effective
// listing and its repair-state publication must not receive repair state: the
// released hold's report carries no repair obligation, and publishing one is
// a stale result that misrepresents the lifecycle state.
func TestSetRepairStateRefusesReleasedHold(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-R4R", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "round4 repair state after release")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold=%s", h.State)
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "released before repair"); err != nil {
		t.Fatal(err)
	}
	// The stale recovery result arrives for the hold's CURRENT epoch (no
	// scope change): only the lifecycle state (released) distinguishes it.
	changed, err := f.rs.SetRepairState(f.ctx(), f.tenant, h.ID, []string{"T-R4R"}, "stale repair failure", h.Epoch)
	if err != nil {
		t.Fatalf("SetRepairState: %v", err)
	}
	if changed {
		t.Fatal("FINDING 3: a released hold accepted a repair-state publication")
	}
	stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.Report.RepairPending) != 0 || stored.Report.RepairError != "" {
		t.Fatalf("FINDING 3: stale effective-hold repair result published after release: %+v", stored.Report)
	}
	var repairs int
	if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM audit_log WHERE action LIKE 'hold.protection_repair%' AND detail->>'hold_id'=$1`, h.ID).Scan(&repairs); err != nil {
		t.Fatal(err)
	}
	if repairs != 0 {
		t.Fatalf("FINDING 3: %d repair audit rows published for a released hold", repairs)
	}
	// The scope-revision guard (round-3) must keep refusing superseded epochs.
	if _, err := f.rs.SetRepairState(f.ctx(), f.tenant, h.ID, []string{"T-R4R"}, "", h.Epoch+1); err == nil {
		t.Fatal("a superseded scope revision must refuse the repair-state write")
	}
}
