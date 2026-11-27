package records_test

// C07 independent-review reproduction tests (RED at REVIEWED_HEAD
// b35948094d23c9e91624dc63448d373aab099f1e).
//
// Every test here asserts the PRESERVATION-correct behavior (the primary
// invariant), not the current implementation's observable behavior. Each one
// reproduces a specific finding of the C07 independent review and must fail
// at the reviewed head (RED evidence) and pass at the corrected head (GREEN
// evidence). Barriers are deterministic channels, never sleeps.

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
)

// ---------------- Finding 1: native legal-hold removal race ----------------

// Release cleanup paused after its remainingHolders snapshot: a newer hold
// that establishes native protection and becomes effective in the gap must
// keep that protection. Logical held state is NOT the assertion - the actual
// storage legal-hold state is.
func TestReleaseCleanupCannotClearNewerHoldProtection(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-R1", f.p1, f.m1, f.u["alice"])
	h1 := f.placeHold("carol", f.m1, "first")
	refs := refsOf(f, f.turnID("T-R1"))

	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "cleanup" {
			once.Do(func() {
				close(paused)
				<-resume
			})
		}
		return nil
	}
	released := make(chan error, 1)
	go func() {
		_, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "resolved")
		released <- err
	}()
	<-paused
	// The newer hold places, establishes native protection, reads back ON,
	// and becomes effective while the stale cleanup is paused. At the
	// corrected head its establishment serializes on the tenant protection
	// fence (it waits until the cleanup commits), which is exactly the
	// incompatible-snapshot interleaving the fence exists to prevent.
	h2err := make(chan error, 1)
	var h2 atomic.Value
	go func() {
		hh, err := f.svc.Place(f.ctx(), f.principal("erin"), records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}}, "second", "idem-race-newer")
		if hh != nil {
			h2.Store(hh)
		}
		h2err <- err
	}()
	waitPlacementProgress(f, "idem-race-newer")
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("second hold's required native protection lost before cleanup resumed: %s is %q", r.Key, state)
		}
	}
	close(resume)
	if err := <-released; err != nil {
		t.Fatalf("release failed: %v", err)
	}
	if err := <-h2err; err != nil {
		t.Fatalf("second hold placement failed: %v", err)
	}
	h2v, _ := h2.Load().(*records.Hold)
	if h2v == nil || h2v.State != records.HoldEffective {
		t.Fatalf("second hold state %s, want effective", stateOf(f, h2v))
	}
	after, err := f.rs.GetHold(f.ctx(), f.principal("erin"), h2v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != records.HoldEffective {
		t.Fatalf("second hold state after stale cleanup resumed: %s", after.State)
	}
	// THE invariant: an effective hold never loses required native protection.
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("FINDING 1: effective hold %s lost native protection on %s (state %q)", h2v.ID, r.Key, state)
		}
	}
}

// waitPlacementProgress blocks until the hold being placed in the background
// is either durably effective (the racy interleaving, possible at the
// reviewed head) or its establishment is waiting on the tenant protection
// fence (the serialized interleaving at the corrected head).
func waitPlacementProgress(f *rfx, idemKey string) {
	f.t.Helper()
	schema := f.pool.Config().ConnConfig.RuntimeParams["search_path"]
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var state *string
		if err := f.pool.QueryRow(f.ctx(), `SELECT state FROM holds WHERE idempotency_key=$1`, idemKey).Scan(&state); err == nil && state != nil && *state == records.HoldEffective {
			return
		}
		var waiters int
		if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'`, schema).Scan(&waiters); err == nil && waiters > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	f.t.Fatalf("placement of %s neither completed nor blocked on the protection fence", idemKey)
}

func stateOf(f *rfx, h *records.Hold) string {
	if h == nil {
		return "<nil>"
	}
	return h.State
}

// Cross-matter variant: the newer hold is on a different matter of the same
// tenant and references the same content-addressed object version. The
// released hold's stale cleanup must not clear the shared version.
func TestReleaseCleanupCannotClearCrossMatterNewerHold(t *testing.T) {
	f := newRfx(t)
	shared := "shared-cross-1"
	f.seedTurn("T-X1", f.p1, f.m1, f.u["alice"], shared)
	f.seedTurn("T-X2", f.p2, f.m2, f.u["bob"], shared)
	sharedRef := refsOf(f, f.turnID("T-X1"))[len(refsOf(f, f.turnID("T-X1")))-1]

	h1 := f.placeHold("carol", f.m1, "cross-matter-first")
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "cleanup" {
			once.Do(func() {
				close(paused)
				<-resume
			})
		}
		return nil
	}
	released := make(chan error, 1)
	go func() {
		_, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "resolved")
		released <- err
	}()
	<-paused
	h2err := make(chan error, 1)
	var h2 atomic.Value
	go func() {
		hh, err := f.svc.Place(f.ctx(), f.principal("erin"), records.Scope{MatterID: f.m2, CustodianIDs: []string{f.u["bob"]}}, "cross-matter-second", "idem-cross-newer")
		if hh != nil {
			h2.Store(hh)
		}
		h2err <- err
	}()
	waitPlacementProgress(f, "idem-cross-newer")
	close(resume)
	if err := <-released; err != nil {
		t.Fatalf("release failed: %v", err)
	}
	if err := <-h2err; err != nil {
		t.Fatalf("second hold placement failed: %v", err)
	}
	h2v, _ := h2.Load().(*records.Hold)
	if h2v == nil || h2v.State != records.HoldEffective {
		t.Fatalf("second hold state %s, want effective", stateOf(f, h2v))
	}
	if state := f.fs.holdState(sharedRef.Key, sharedRef.Version); state != "ON" {
		t.Fatalf("FINDING 1 (cross-matter): effective hold %s lost native protection on shared version %s (state %q)", h2v.ID, sharedRef.Key, state)
	}
}

// ---------------- Finding 2: incomplete protection acknowledged as effective ----------------

// Startup recovery of a PENDING hold must not acknowledge effectiveness
// while a matching record's required versions are unverifiable.
func TestRecoveryDoesNotAcknowledgeUncoveredProtection(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-U1", f.p1, f.m1, f.u["alice"])
	h, err := f.rs.PlaceHold(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "interrupted", "idem-uncovered-pending")
	if err != nil {
		t.Fatal(err)
	}
	// The matching record's required versions are missing/unverifiable.
	f.fb.missing[f.turnID("T-U1")] = true
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	after, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State == records.HoldEffective {
		t.Fatalf("FINDING 2: recovery acknowledged a hold as effective while %d uncovered records exist", len(after.Report.Uncovered))
	}
	if len(after.Report.Uncovered) == 0 {
		t.Fatal("the uncovered record must be reported")
	}
	// The disposal fence stands.
	if f.sweepAs("carol") != 0 {
		t.Fatal("a hold with uncovered records must still fence disposal")
	}
}

// Startup recovery of a FAILED hold must not acknowledge effectiveness while
// uncovered records exist.
func TestRecoveryOfFailedHoldDoesNotAcknowledgeUncovered(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-U2", f.p1, f.m1, f.u["alice"])
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "protect" {
			return errors.New("protect outage")
		}
		return nil
	}
	_, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "will-fail", "idem-uncovered-failed")
	if err == nil {
		t.Fatal("placement must fail while protection fails")
	}
	f.svc.Hooks.StorageFault = nil
	f.fb.missing[f.turnID("T-U2")] = true
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	h, err := f.rs.ListHolds(f.ctx(), f.principal("carol"))
	if err != nil {
		t.Fatal(err)
	}
	for _, hd := range h {
		if hd.State == records.HoldEffective && len(hd.Report.Uncovered) > 0 {
			t.Fatalf("FINDING 2: failed hold recovered to effective with %d uncovered records", len(hd.Report.Uncovered))
		}
	}
}

// Scope-change reestablishment must not acknowledge effectiveness while
// uncovered records exist.
func TestReestablishDoesNotAcknowledgeUncoveredProtection(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-U3a", f.p1, f.m1, f.u["alice"])
	f.seedTurn("T-U3b", f.p1, f.m1, f.u["bob"])
	h := f.placeHold("carol", f.m1, "reestablish-uncovered")
	changed, err := f.rs.ChangeScope(f.ctx(), f.principal("carol"), h.ID, records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"], f.u["bob"]}}, "widen")
	if err != nil {
		t.Fatal(err)
	}
	if changed.State != records.HoldPending {
		t.Fatalf("changed hold state %s, want pending", changed.State)
	}
	f.fb.missing[f.turnID("T-U3b")] = true
	report, err := f.svc.Reestablish(f.ctx(), changed)
	if err == nil && len(report.Uncovered) > 0 {
		// acceptable as long as effectiveness was NOT acknowledged
	} else if err != nil {
		t.Logf("reestablish refused: %v", err)
	}
	after, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State == records.HoldEffective && len(after.Report.Uncovered) > 0 {
		t.Fatalf("FINDING 2: reestablishment acknowledged effective with %d uncovered records", len(after.Report.Uncovered))
	}
	if f.sweepAs("carol") != 0 {
		t.Fatal("a hold with uncovered records must still fence disposal")
	}
}

// A stale establishment (enumerated under the prior scope) completing after a
// scope change must not mark the changed hold effective against the stale
// coverage report.
func TestStaleEstablishmentCannotMarkChangedScopeEffective(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-Sa", f.p1, f.m1, f.u["alice"])
	f.seedTurn("T-Sb", f.p1, f.m1, f.u["bob"])
	bobRefs := refsOf(f, f.turnID("T-Sb"))

	// Place with a pause inside establishment after the LAST version's
	// readback (bob's turn is seeded second, so its readbacks come last).
	aliceRefs := refsOf(f, f.turnID("T-Sa"))
	total := len(aliceRefs) + len(bobRefs)
	readbacks := 0
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "readback" {
			readbacks++
			if readbacks == total {
				once.Do(func() {
					close(paused)
					<-resume
				})
			}
		}
		return nil
	}
	placed := make(chan error, 1)
	go func() {
		_, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"], f.u["bob"]}}, "wide", "idem-stale-scope")
		placed <- err
	}()
	<-paused
	// A concurrent scope change narrows the hold while the stale wide
	// establishment is in flight.
	if _, err := f.rs.ChangeScope(f.ctx(), f.principal("carol"), mustHoldID(f, "idem-stale-scope"), records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}}, "narrow"); err != nil {
		t.Fatalf("scope change failed: %v", err)
	}
	close(resume)
	err := <-placed
	after, err2 := holdByIdem(f, "idem-stale-scope")
	if err2 != nil {
		t.Fatal(err2)
	}
	_ = err
	if after.State == records.HoldEffective && len(bobRefs) > 0 && containsVersion(after.Report.ProtectedVersions, bobRefs[0]) {
		t.Fatalf("FINDING 2: stale establishment marked the narrowed hold effective with a coverage report from the prior (wide) scope")
	}
	if after.State == records.HoldEffective && len(after.CustodianIDs) == 1 {
		// effective is only acceptable with a report matching the scope
		// revision it verified; at the corrected head this branch requires
		// the report to cover exactly the narrowed scope.
		for _, r := range bobRefs {
			if containsVersion(after.Report.ProtectedVersions, r) {
				t.Fatalf("effective report covers removed-scope version %s", r.Key)
			}
		}
	}
}

func mustHoldID(f *rfx, idem string) string {
	f.t.Helper()
	holds, err := f.rs.ListHolds(f.ctx(), f.principal("carol"))
	if err != nil {
		f.t.Fatal(err)
	}
	for _, h := range holds {
		if h.IdempotencyKey == idem {
			return h.ID
		}
	}
	f.t.Fatalf("no hold with idempotency key %s", idem)
	return ""
}

func holdByIdem(f *rfx, idem string) (*records.Hold, error) {
	holds, err := f.rs.ListHolds(f.ctx(), f.principal("carol"))
	if err != nil {
		return nil, err
	}
	for _, h := range holds {
		if h.IdempotencyKey == idem {
			return h, nil
		}
	}
	return nil, fmt.Errorf("no hold with idempotency key %s", idem)
}

func containsVersion(refs []records.VersionRef, v struct{ Key, Version string }) bool {
	for _, r := range refs {
		if r.Key == v.Key && r.Version == v.Version {
			return true
		}
	}
	return false
}

// ---------------- Finding 3: incomplete and non-durable release cleanup ----------------

// A: future matching work admitted after activation is protected by the
// recorder guard; releasing the final applicable hold must eventually clear
// that protection (no permanent leak).
func TestReleasedHoldClearsFutureWorkProtection(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-FW", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "future-work")
	// New matching turn admitted through the guard path after activation.
	f.seedTurn("T-FW2", f.p1, f.m1, f.u["alice"])
	if err := f.svc.EnsureProtected(f.ctx(), f.tenant, f.m1, f.u["alice"], f.turnID("T-FW2"), time.Now()); err != nil {
		t.Fatalf("guard protection failed: %v", err)
	}
	futureRefs := refsOf(f, f.turnID("T-FW2"))
	for _, r := range futureRefs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("future work must be protected while held: %s is %q", r.Key, state)
		}
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "done"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, r := range futureRefs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 3A: post-activation version %s leaked permanent protection after every applicable hold was released", r.Key)
		}
	}
	// And ordinary disposal after base retention expiry is no longer blocked.
	if got := f.sweepAs("carol"); got == 0 {
		t.Fatal("expired control must be eligible after release")
	}
}

// B: scope narrowing must eventually clear protection of removed-scope
// versions while preserving the remaining scope and any overlapping hold.
func TestScopeNarrowingEventuallyClearsRemovedScope(t *testing.T) {
	f := newRfx(t)
	shared := "narrow-shared-1"
	f.seedTurn("T-Na", f.p1, f.m1, f.u["alice"], shared)
	f.seedTurn("T-Nb", f.p1, f.m1, f.u["bob"], shared)
	bobRefs := refsOf(f, f.turnID("T-Nb"))
	aliceRefs := refsOf(f, f.turnID("T-Na"))

	h := f.placeHold("carol", f.m1, "wide-before-narrow")
	// Overlapping alice-scoped hold keeps requiring the shared object (via
	// alice's reference) but never bob's own versions.
	h2 := f.placeHold("erin", f.m1, "overlapping-narrow", f.u["alice"])
	changed, err := f.rs.ChangeScope(f.ctx(), f.principal("carol"), h.ID, records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}}, "narrow to alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Reestablish(f.ctx(), changed); err != nil {
		t.Fatalf("reestablish after narrowing failed: %v", err)
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "narrowed and released"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	// bob's own (non-shared) versions: no remaining hold requires them.
	bobOwn := bobRefs[:len(bobRefs)-1]
	for _, r := range bobOwn {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 3B: removed-scope version %s leaked protection after narrowing and release", r.Key)
		}
	}
	// The shared object stays protected while h2 (alice+bob scope) requires it,
	// and alice's versions stay protected while held.
	sharedRef := bobRefs[len(bobRefs)-1]
	if state := f.fs.holdState(sharedRef.Key, sharedRef.Version); state != "ON" {
		t.Fatalf("shared version lost protection while an overlapping hold requires it")
	}
	for _, r := range aliceRefs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("remaining-scope version %s lost protection while held", r.Key)
		}
	}
	_ = h2
}

// C: crash between the release transaction commit and cleanup: recovery must
// converge (clear the no-longer-required native protection).
func TestReleaseCrashBeforeCleanupRecovers(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-CR", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "crash-before-cleanup")
	refs := refsOf(f, f.turnID("T-CR"))
	// TX only: the durable release, as a process killed right after the
	// release commit would leave behind (no cleanup, no pending recording).
	if _, err := f.rs.ReleaseHold(f.ctx(), f.principal("carol"), h.ID, "crash"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 3C: released hold's version %s kept protection forever after a crash between release and cleanup", r.Key)
		}
	}
}

// D: overlapping protection on evidence whose base retention has expired:
// cleanup must tolerate expired references (disposal-tolerant enumeration)
// and converge after the final applicable release.
func TestReleaseCleanupToleratesExpiredReferences(t *testing.T) {
	f := newRfx(t)
	shared := "expired-shared-1"
	f.seedTurn("T-EA", f.p1, f.m1, f.u["alice"], shared)
	f.seedTurn("T-EB", f.p1, f.m1, f.u["bob"], shared)
	f.fb.expired[f.turnID("T-EA")] = true // base retention expired, still protected by legal hold
	bobRefs := refsOf(f, f.turnID("T-EB"))
	bobOwn := bobRefs[:len(bobRefs)-1]

	h1 := f.placeHold("carol", f.m1, "expired-overlap-1", f.u["alice"])
	h2 := f.placeHold("erin", f.m1, "expired-overlap-2", f.u["bob"])
	_ = h1
	if _, err := f.svc.Release(f.ctx(), f.principal("erin"), h2.ID, "final applicable release"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	sharedRef := bobRefs[len(bobRefs)-1]
	if state := f.fs.holdState(sharedRef.Key, sharedRef.Version); state != "ON" {
		t.Fatalf("shared version must stay protected while h1 (expired evidence) still holds it")
	}
	for _, r := range bobOwn {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 3D: cleanup never converged for version %s because strict enumeration refuses the expired reference", r.Key)
		}
	}
	// After the final release, everything converges.
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "final"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(sharedRef.Key, sharedRef.Version); state == "ON" {
		t.Fatalf("shared version leaked protection after every applicable hold was released")
	}
}

// ---------------- Finding 4: storage errors misclassified as disposal ----------------

// A storage outage during begin purge's presence check must never become
// proof of disposal.
func TestStorageOutageIsNotDisposalAtBeginPurge(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-O1", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	f.fb.failEnum[f.turnID("T-O1")] = errors.New("listing timeout")
	outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-O1"), func(ctx context.Context, _ pgx.Tx, turnID string) (bool, error) {
		return f.svc.VersionPresent(ctx, f.tenant, turnID), nil
	})
	if err == nil && outcome == "disposed_ambiguous" {
		t.Fatalf("FINDING 4: storage outage became proof of disposal (outcome %s)", outcome)
	}
	if it := f.item("T-O1"); it.State == records.ItemDisposed {
		t.Fatalf("FINDING 4: intact retained evidence marked disposed during a storage outage")
	}
}

// A storage outage during startup recovery must never mark intact evidence
// disposed.
func TestStorageOutageIsNotDisposalAtRecovery(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-O2", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	f.fb.failEnum[f.turnID("T-O2")] = errors.New("authorization failure")
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if it := f.item("T-O2"); it.State == records.ItemDisposed {
		t.Fatalf("FINDING 4: storage outage during recovery became proof of disposal")
	}
	// Recovery after storage access returns completes honestly.
	f.fb.failEnum[f.turnID("T-O2")] = nil
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if it := f.item("T-O2"); it.State != records.ItemDisposalPending {
		t.Fatalf("state %s, want disposal_pending (still present, still eligible)", it.State)
	}
}

// A missing admission marker while other versions of the turn are still
// present must not be classified as successful disposal.
func TestMissingAdmissionWithSurvivingVersionsIsNotDisposal(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-O3", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	refs := refsOf(f, f.turnID("T-O3"))
	// External interference deletes only the admission marker; the rest of
	// the turn's versions are still present.
	if err := f.fs.DeleteVersion(f.ctx(), refs[0].Key, refs[0].Version); err != nil {
		t.Fatal(err)
	}
	outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-O3"), func(ctx context.Context, _ pgx.Tx, turnID string) (bool, error) {
		return f.svc.VersionPresent(ctx, f.tenant, turnID), nil
	})
	if err == nil && outcome == "disposed_ambiguous" {
		t.Fatalf("FINDING 4: partial disappearance (admission gone, versions present) claimed as disposal")
	}
	if it := f.item("T-O3"); it.State == records.ItemDisposed {
		t.Fatalf("FINDING 4: partially present evidence marked disposed without proof of physical absence")
	}
	for _, r := range refs[1:] {
		if f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("surviving version %s was deleted", r.Key)
		}
	}
}

// ---------------- Finding 5: partial disposal recovery and gap reporting ----------------

// An interrupted deletion (first version deleted at storage, acknowledgment
// lost) must resume WITHOUT requiring already-deleted metadata: every exact
// original version receives a verified disposition and no bytes are
// orphaned.
func TestPartialDisposalResumesWithoutDeletedMetadata(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-PD", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-PD"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	refs := refsOf(f, f.turnID("T-PD"))
	// The first delete (the admission marker, key-sorted first) commits at
	// the storage; the second fails: the acknowledgment is lost.
	f.fs.mu.Lock()
	f.fs.failDelete = &transportErr{}
	f.fs.failOnce.Store("delete", true)
	f.fs.partialDeleteKey = refs[0].Key + "|" + refs[0].Version
	f.fs.mu.Unlock()
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-PD")); err == nil {
		t.Fatal("interrupted delete must surface as a retryable error")
	}
	f.fs.mu.Lock()
	f.fs.failDelete = nil
	f.fs.partialDeleteKey = ""
	f.fs.mu.Unlock()
	// Restart + retry: recovery must complete disposal of EVERY exact
	// original version, without the deleted admission marker.
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	if it := f.item("T-PD"); it.State != records.ItemDisposed {
		t.Fatalf("FINDING 5: interrupted disposal did not converge: state %s", it.State)
	}
	for _, r := range refs {
		if !f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("FINDING 5: version %s was orphaned (never dispositioned) after the enumeration root was deleted", r.Key)
		}
	}
}

// A fully disposed matching record must appear in a later hold's
// disposed_before_hold report (it is no longer enumerable from live storage).
func TestDisposedTurnsAppearInLaterHoldGapReport(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-GP", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-GP"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	if outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-GP")); err != nil || outcome != "disposed" {
		t.Fatalf("finish outcome %s err %v", outcome, err)
	}
	// The disposed turn disappears from the authoritative live inventory.
	f.fb.dropTurn(f.tenant, f.turnID("T-GP"))
	h := f.placeHold("carol", f.m1, "later-hold-over-disposed")
	found := false
	for _, id := range h.Report.DisposedBeforeHold {
		if id == f.turnID("T-GP") {
			found = true
		}
	}
	if !found {
		t.Fatalf("FINDING 5: previously disposed matching record missing from disposed_before_hold (report has %d entries, uncovered %d)", len(h.Report.DisposedBeforeHold), len(h.Report.Uncovered))
	}
	for _, id := range h.Report.Uncovered {
		if id == f.turnID("T-GP") {
			t.Fatal("disposed and uncovered records must remain distinguishable")
		}
	}
}

// ---------------- Finding 6A: in-flight capture versus ordinary expiry ----------------

// An admitted, actively executing (non-terminal) turn must not be swept into
// disposal eligibility by ordinary retention expiry.
func TestSweepRequiresTerminalTurn(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-IF", f.p1, f.m1, f.u["alice"])
	f.fb.nonterminal[f.turnID("T-IF")] = true
	if got := f.sweepAs("carol"); got != 0 {
		t.Fatalf("FINDING 6A: an in-flight (non-terminal) turn was swept: %d items marked", got)
	}
	if it := f.item("T-IF"); it.State != records.ItemActive {
		t.Fatalf("FINDING 6A: in-flight turn tombstone path opened: state %s", it.State)
	}
	// The turn completes; ordinary expiry now applies.
	f.fb.nonterminal[f.turnID("T-IF")] = false
	if got := f.sweepAs("carol"); got != 1 {
		t.Fatalf("terminal expired turn must be eligible, marked %d", got)
	}
}

// ---------------- Finding 7: audit and lifecycle consistency ----------------

// Exactly one hold.effective audit row per lifecycle: a concurrent duplicate
// establishment completing after the transition must not duplicate the audit.
func TestNoDuplicateEffectiveAuditRows(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-AD", f.p1, f.m1, f.u["alice"])
	h, err := f.rs.PlaceHold(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "audit", "idem-audit-dup")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = f.svc.Reestablish(f.ctx(), h)
		}()
	}
	wg.Wait()
	if n, err := countAudit(f, "hold.effective"); err != nil || n != 1 {
		t.Fatalf("FINDING 7: hold.effective audit rows = %d (err %v), want exactly 1", n, err)
	}
}

// Scope-change audit must attribute the prior and new scope with the
// time-window values.
func TestScopeChangeAuditRecordsScopeAttribution(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-SA", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "audit-scope")
	if _, err := f.rs.ChangeScope(f.ctx(), f.principal("carol"), h.ID, records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}}, "narrowed"); err != nil {
		t.Fatal(err)
	}
	var detail []byte
	if err := f.pool.QueryRow(f.ctx(), `SELECT detail FROM audit_log WHERE action='hold.change' ORDER BY at DESC, id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	detailStr := string(detail)
	for _, want := range []string{"prior", "new", "custodian"} {
		if !containsFold(detailStr, want) {
			t.Fatalf("FINDING 7: hold.change audit detail lacks %q scope attribution: %s", want, detailStr)
		}
	}
}

// Completed release cleanup must be durably and attributably recorded.
func TestCleanupCompletionIsAudited(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-CC", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "audit-cleanup")
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "done"); err != nil {
		t.Fatal(err)
	}
	n, err := countAuditActionLike(f, "hold.cleanup")
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("FINDING 7: completed release cleanup is not durably recorded in the audit trail")
	}
}

func countAuditActionLike(f *rfx, prefix string) (int, error) {
	var n int
	err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM audit_log WHERE action LIKE $1`, prefix+"%").Scan(&n)
	return n, err
}

func containsFold(s, sub string) bool {
	if len(sub) == 0 || len(s) < len(sub) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			a, b := s[i+j], sub[j]
			if 'A' <= a && a <= 'Z' {
				a += 'a' - 'A'
			}
			if 'A' <= b && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ---------------- Adversarial review findings ----------------

// A crash between the durable claim commit and the native protection must
// leave a RECOVERABLE ledger (pending claims), never untracked native
// protection: the release reconcile must find and clear every native hold
// the crashed establishment set, through the claims (adversarial review:
// nonconvergent claim state).
func TestCrashBetweenClaimCommitAndNativeProtectionConverges(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-C1", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, f.turnID("T-C1"))

	var readbacks int32
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "readback" && atomic.AddInt32(&readbacks, 1) == 1 {
			// The native set for the first version already happened; the
			// verification fails exactly like a process death in the window
			// between SetLegalHold and the claim transaction's commit.
			return errors.New("crash window: readback failed after the native set")
		}
		return nil
	}
	if _, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "crash window", "idem-crash-window"); err == nil {
		t.Fatal("placement must surface the crash-window failure")
	}
	f.svc.Hooks.StorageFault = nil
	holdID := mustHoldID(f, "idem-crash-window")

	claims, err := f.svc.Store.ClaimsOfHold(f.ctx(), holdID)
	if err != nil {
		t.Fatal(err)
	}
	if len(claims) == 0 {
		t.Fatalf("ADVERSARIAL FINDING: protection claims were not durable before the native mutation (%d claims); a crash after SetLegalHold would leak native protection forever", len(claims))
	}
	if claims[0].State != "pending" {
		t.Fatalf("crashed establishment's claims must be pending, got %q", claims[0].State)
	}
	// The crash window set the FIRST version's native hold before dying:
	// the leaked state exists and only the ledger can find it.
	if state := f.fs.holdState(refs[0].Key, refs[0].Version); state != "ON" {
		t.Fatalf("test choreography: first version must be ON in the crash window, got %q", state)
	}

	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), holdID, "resolved after crash"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("ADVERSARIAL FINDING: native protection leaked after the crashed establishment was released: %s is ON", r.Key)
		}
	}
	if remaining, err := f.svc.Store.ClaimsOfHold(f.ctx(), holdID); err != nil || len(remaining) != 0 {
		t.Fatalf("ADVERSARIAL FINDING: claims did not converge after release: %d remaining (%v)", len(remaining), err)
	}
}

// The purge finish serializes on the tenant protection fence exactly like a
// capture's reference acquisition, and the lock ORDER (tenants ->
// tenant_protection -> retention_items -> matter_hold_epochs) never inverts
// with the capture path (adversarial review: lock order).
func TestFinishPurgeSerializesWithCaptureReferenceFence(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-L1", f.p1, f.m1, f.u["alice"])
	turn := f.turnID("T-L1")
	if got := f.sweepAs("carol"); got == 0 {
		t.Fatal("expired control must be sweep-eligible")
	}
	terminal := func(context.Context, pgx.Tx, string) (bool, error) { return true, nil }
	if _, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), turn, terminal); err != nil {
		t.Fatalf("begin purge failed: %v", err)
	}

	fence, err := f.svc.AcquireReferenceFence(f.ctx(), f.tenant)
	if err != nil {
		t.Fatalf("reference fence: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		p := f.principal("erin")
		_, _, err := f.svc.FinishPurge(f.ctx(), &p, turn)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("purge finished while the capture reference fence was held: %v", err)
	case <-time.After(200 * time.Millisecond):
		// blocked on the protection fence: the delete cannot race a capture.
	}
	if err := fence(f.ctx()); err != nil {
		t.Fatalf("fence release: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("purge finish failed after fence release: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ADVERSARIAL FINDING: purge finish deadlocked against the capture reference fence (lock order inversion)")
	}
	if it := f.item("T-L1"); it.State != records.ItemDisposed {
		t.Fatalf("purge did not complete: state %s", it.State)
	}
}
