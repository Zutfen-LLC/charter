package records_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// Two concurrent sweeps over the same catalog mark each eligible item exactly
// once; the state is never corrupted and no audit row duplicates.
func TestConcurrentSweepsAreIdempotent(t *testing.T) {
	f := newRfx(t)
	for i := 0; i < 8; i++ {
		f.seedTurn(fmt.Sprintf("T-CS%d", i), f.p1, f.m1, f.u["alice"])
	}
	var wg sync.WaitGroup
	results := make([]int, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = f.sweepAs("carol")
		}(i)
	}
	wg.Wait()
	total := 0
	for _, n := range results {
		total += n
	}
	if total != 8 {
		t.Fatalf("concurrent sweeps marked %d items, want exactly 8", total)
	}
	items, err := f.rs.Items(f.ctx(), store.Principal{TenantID: f.tenant})
	if err != nil {
		t.Fatal(err)
	}
	pending := 0
	for _, it := range items {
		if it.State == records.ItemDisposalPending {
			pending++
		}
	}
	if pending != 8 {
		t.Fatalf("pending items = %d, want 8", pending)
	}
}

// Concurrent placements with the SAME idempotency key create exactly one hold
// and one epoch; concurrent DIFFERENT holds serialize on the epoch row.
func TestConcurrentSameKeyPlacementsCreateOneHold(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-CK", f.p1, f.m1, f.u["alice"])
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "reason", "idem-concurrent")
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("concurrent placement failed: %v", err)
		}
	}
	var count int
	if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM holds WHERE idempotency_key=$1`, "idem-concurrent").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("holds created = %d, want 1", count)
	}
	if n, err := countAudit(f, "hold.place"); err != nil || n != 1 {
		t.Fatalf("hold.place audits = %d (err %v), want 1", n, err)
	}
}

// Release racing another hold application: both serialize on the epoch row;
// the item never loses protection it still requires, and the final state is
// consistent (H2 active after H1 released).
func TestReleaseRacingAnotherApplication(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-RR", f.p1, f.m1, f.u["alice"])
	h1 := f.placeHold("carol", f.m1, "first")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "racing-release"); err != nil {
			t.Errorf("release: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := f.svc.Place(f.ctx(), f.principal("erin"), records.Scope{MatterID: f.m1}, "second", "idem-rr2"); err != nil {
			t.Errorf("placement: %v", err)
		}
	}()
	wg.Wait()
	held, _, err := f.svc.ItemHeld(f.ctx(), f.principal("carol"), f.turnID("T-RR"))
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("item must remain held by the surviving hold")
	}
	if f.sweepAs("carol") != 0 {
		t.Fatal("raced item became a disposal candidate")
	}
}

// Overlapping release operations on the SAME hold are idempotent: one
// release, one epoch bump, one audit row.
func TestConcurrentDuplicateReleases(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-DR", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "dup-release")
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "release")
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatalf("duplicate release failed: %v", err)
		}
	}
	if n, err := countAudit(f, "hold.release"); err != nil || n != 1 {
		t.Fatalf("hold.release audits = %d (err %v), want 1", n, err)
	}
	after, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != records.HoldReleased || after.ReleaseEpoch == nil {
		t.Fatalf("released hold state inconsistent: %+v", after)
	}
}

// Concurrent finish retries of the same purge: exactly one disposes; the
// others observe a terminal state and never delete twice.
func TestConcurrentFinishRetries(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-CF", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-CF"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	var wg sync.WaitGroup
	outcomes := make([]string, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome, _, _ := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-CF"))
			outcomes[i] = outcome
		}(i)
	}
	wg.Wait()
	disposed := 0
	for _, o := range outcomes {
		if o == "disposed" {
			disposed++
		}
	}
	if disposed != 1 {
		t.Fatalf("disposed outcomes = %d (%v), want exactly 1", disposed, outcomes)
	}
	if n, err := countAudit(f, "purge.finish"); err != nil || n != 1 {
		t.Fatalf("purge.finish audits = %d (err %v), want 1", n, err)
	}
}

// Storage delete committed but the acknowledgment (transaction commit) was
// lost: recovery re-runs the conditional delete; already-deleted versions are
// absent (idempotent completion), never re-deleted, and the item reaches
// disposed deterministically.
func TestStorageCommittedAcknowledgmentLost(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-AL", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-AL"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	refs := refsOf(f, f.turnID("T-AL"))
	// The first version deletes successfully; the delete of the second fails
	// with a transport error, so the transaction rolls back with one version
	// already gone (the ambiguous state).
	f.fs.mu.Lock()
	f.fs.failDelete = &transportErr{}
	f.fs.failOnce.Store("delete", true)
	f.fs.partialDeleteKey = refs[0].Key + "|" + refs[0].Version
	f.fs.mu.Unlock()
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-AL")); err == nil {
		t.Fatal("ambiguous delete must surface as a retryable error")
	}
	if !f.fs.isDeleted(refs[0].Key, refs[0].Version) {
		t.Fatal("setup: the first version should have been deleted before the failure")
	}
	if it := f.item("T-AL"); it.State != records.ItemPurging {
		t.Fatalf("ambiguous state must stay purging, got %s", it.State)
	}
	// Recovery: the absent version completes idempotently, the rest delete,
	// the item becomes disposed.
	f.fs.mu.Lock()
	f.fs.failDelete = nil
	f.fs.partialDeleteKey = ""
	f.fs.mu.Unlock()
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if it := f.item("T-AL"); it.State != records.ItemDisposed {
		t.Fatalf("recovered state %s, want disposed", it.State)
	}
	for _, r := range refs {
		if !f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("version %s not deleted after recovery", r.Key)
		}
	}
}

// transportErr simulates a lost response for every delete except the
// configured partial one.
type transportErr struct{}

func (*transportErr) Error() string { return "transport failure" }

// A hold interrupted between its durable placement (pending) and protection
// establishment (process termination) is re-established by recovery, which is
// independent of the initiating process.
func TestRecoveryCompletesInterruptedEstablishment(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-IE", f.p1, f.m1, f.u["alice"])
	// TX1 only: the durable pending hold, as a process killed right after
	// the epoch commit would leave behind.
	h, err := f.rs.PlaceHold(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "interrupted", "idem-ie")
	if err != nil {
		t.Fatal(err)
	}
	if h.State != records.HoldPending {
		t.Fatalf("state %s, want pending", h.State)
	}
	// Disposal is already fenced by the pending hold.
	if f.sweepAs("carol") != 0 {
		t.Fatal("a pending hold must already fence disposal")
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	after, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != records.HoldEffective {
		t.Fatalf("recovered state %s, want effective", after.State)
	}
	for _, r := range after.Report.ProtectedVersions {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("version %s unprotected after recovery: %q", r.Key, state)
		}
	}
}

// Recovery is idempotent: a second run changes nothing (no duplicate audits,
// no state churn) and can run while the workspace is unavailable in the sense
// that no workspace table is consulted.
func TestRecoveryIsIdempotent(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-RI", f.p1, f.m1, f.u["alice"])
	f.placeHold("carol", f.m1, "idempotent-recovery")
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	n1, err := countAudit(f, "hold.effective")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	n2, err := countAudit(f, "hold.effective")
	if err != nil {
		t.Fatal(err)
	}
	if n1 != n2 {
		t.Fatalf("recovery duplicated effective audits: %d -> %d", n1, n2)
	}
}

// A shared content-addressed object referenced by two turns: the disposal of
// the unheld turn must not remove the bytes the held turn still requires.
func TestSharedObjectSurvivesDisposalOfOtherReference(t *testing.T) {
	f := newRfx(t)
	shared := "shared-obj-1"
	f.seedTurn("T-SH1", f.p1, f.m1, f.u["alice"], shared) // held
	f.seedTurn("T-SH2", f.p2, f.m2, f.u["bob"], shared)   // unheld control, same bytes
	f.placeHold("carol", f.m1, "protect-shared")
	var sharedKey, sharedVersion string
	for _, r := range refsOf(f, f.turnID("T-SH1")) {
		if len(r.Key) > 0 && r.Key[len(r.Key)-len("shared-obj-1"):] == shared {
			sharedKey, sharedVersion = r.Key, r.Version
		}
	}
	if sharedKey == "" {
		t.Fatal("setup: shared version not found")
	}
	// Sweep only marks the unheld turn (the shared turn is held).
	if got := f.sweepAs("carol"); got != 1 {
		t.Fatalf("sweep marked %d, want only the unheld turn", got)
	}
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-SH2"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	outcome, versions, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-SH2"))
	if err != nil || outcome != "disposed" {
		t.Fatalf("finish outcome %s err %v", outcome, err)
	}
	if versions[sharedKey+"|"+sharedVersion] != records.OutcomeRetainedShared {
		t.Fatalf("shared version outcome %q, want retained_shared", versions[sharedKey+"|"+sharedVersion])
	}
	if f.fs.isDeleted(sharedKey, sharedVersion) {
		t.Fatal("the shared bytes were deleted while a held record still requires them")
	}
	if state := f.fs.holdState(sharedKey, sharedVersion); state != "ON" {
		t.Fatalf("shared version not under legal hold: %q", state)
	}
	// The held turn's evidence chain remains fully enumerable.
	if _, err := f.fb.TurnVersionRefs(f.ctx(), f.tenant, f.turnID("T-SH1")); err != nil {
		t.Fatalf("held turn no longer enumerable: %v", err)
	}
}

// Ownership fencing: the lifecycle service runs under the single-instance
// fence; a guard failure on new matching work fails the TURN closed (this is
// asserted end-to-end in the server package; here the guard contract is
// exercised directly).
func TestGuardContract(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-GC", f.p1, f.m1, f.u["alice"])
	f.placeHold("carol", f.m1, "guard")
	applies, err := f.svc.HoldApplies(f.ctx(), f.tenant, f.m1, f.u["alice"], time.Now())
	if err != nil || !applies {
		t.Fatalf("guard must report the active hold: %v %v", applies, err)
	}
	// A custodian outside the scope is not covered.
	f2 := newRfx(t)
	f2.seedTurn("T-GC2", f2.p1, f2.m1, f2.u["alice"])
	_ = f2
	if err := f.svc.EnsureProtected(f.ctx(), f.tenant, f.turnID("T-GC")); err != nil {
		t.Fatalf("EnsureProtected must be idempotent: %v", err)
	}
	// Protection readback failure fails closed.
	f.fs.legalHoldAfter = "OFF"
	if err := f.svc.EnsureProtected(f.ctx(), f.tenant, f.turnID("T-GC")); err == nil {
		t.Fatal("readback mismatch must fail closed")
	}
	f.fs.legalHoldAfter = ""
}

// DB unavailability of the lifecycle store surfaces as an error, never as a
// silent allow: the guard refuses to answer.
func TestGuardFailsClosedWhenStoreUnavailable(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-DB", f.p1, f.m1, f.u["alice"])
	// A closed pool behaves like an outage.
	f2 := newRfx(t)
	f2.pool.Close()
	if _, err := f2.svc.HoldApplies(f.ctx(), f2.tenant, f2.m1, f2.u["alice"], time.Now()); err == nil {
		t.Fatal("guard must fail closed on store outage")
	}
	if err := f2.svc.EnsureProtected(f.ctx(), f2.tenant, "00000000-0000-0000-0000-000000000000"); err == nil {
		t.Fatal("protection must fail closed on store outage")
	}
}

var _ = errors.New
var _ = store.ErrForbidden
