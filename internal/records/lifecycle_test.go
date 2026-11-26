package records_test

import (
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// Case A: hold placed, then sweep. The item is never a candidate.
func TestCaseAHoldBeforeSweep(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-A", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "litigation-hold")
	if h.State != records.HoldEffective {
		t.Fatalf("hold state %s, want effective (protection verified before acknowledgment)", h.State)
	}
	if got := f.sweepAs("carol"); got != 0 {
		t.Fatalf("sweep marked %d items; a held item is not a candidate", got)
	}
	if it := f.item("T-A"); it.State != records.ItemActive {
		t.Fatalf("item state %s, want active", it.State)
	}
}

// Case B: sweep marks pending, hold placed, purge attempted. The hold wins:
// begin_purge restores the item to active and refuses.
func TestCaseBHoldBetweenSweepAndPurge(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-B", f.p1, f.m1, f.u["alice"])
	if got := f.sweepAs("carol"); got != 1 {
		t.Fatalf("sweep marked %d, want 1", got)
	}
	if it := f.item("T-B"); it.State != records.ItemDisposalPending {
		t.Fatalf("state %s, want disposal_pending", it.State)
	}
	h := f.placeHold("erin", f.m1, "late-hold")
	if h.State != records.HoldEffective {
		t.Fatalf("hold state %s", h.State)
	}
	if it := f.item("T-B"); it.State != records.ItemActive {
		t.Fatalf("placement must restore pending items to active, got %s", it.State)
	}
	outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-B"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != "not_eligible" {
		t.Fatalf("purge outcome %s, want refusal", outcome)
	}
}

// Case C: sweep, purge, then hold placed. The item is disposed and the hold
// records the disposed_before_hold gap rather than silently assuming
// preservation.
func TestCaseCHoldAfterDisposalRecordsGap(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-C", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-C"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	if outcome, versions, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-C")); err != nil || outcome != "disposed" {
		t.Fatalf("finish outcome %s versions %v err %v", outcome, versions, err)
	}
	h := f.placeHold("carol", f.m1, "too-late-hold")
	if h.State != records.HoldEffective {
		t.Fatalf("hold state %s", h.State)
	}
	if len(h.Report.DisposedBeforeHold) != 1 || h.Report.DisposedBeforeHold[0] != f.turnID("T-C") {
		t.Fatalf("disposed_before_hold gap not reported: %+v", h.Report)
	}
}

// Case D: two overlapping holds, release one. The item stays held and is not
// a sweep candidate; the storage legal hold is NOT cleared while the other
// hold still requires it.
func TestCaseDOverlappingHoldsReleaseOne(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-D", f.p1, f.m1, f.u["alice"])
	h1 := f.placeHold("carol", f.m1, "first")
	h2 := f.placeHold("erin", f.m1, "second")
	rel, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "matter resolved for h1")
	if err != nil {
		t.Fatal(err)
	}
	if rel.State != records.HoldReleased {
		t.Fatalf("released hold state %s", rel.State)
	}
	if f.sweepAs("carol") != 0 {
		t.Fatal("item still held by h2 must not become a sweep candidate")
	}
	if it := f.item("T-D"); it.State != records.ItemActive {
		t.Fatalf("state %s, want active", it.State)
	}
	// The shared storage legal hold stays ON while h2 requires it.
	held, _, err := f.svc.ItemHeld(f.ctx(), f.principal("carol"), f.turnID("T-D"))
	if err != nil || !held {
		t.Fatal("item must still be held after releasing one of two holds")
	}
	rel2, err := f.svc.Release(f.ctx(), f.principal("erin"), h2.ID, "matter resolved for h2")
	if err != nil {
		t.Fatal(err)
	}
	if len(rel2.Report.ReleaseCleanupPending) != 0 {
		t.Fatalf("cleanup pending after full release: %+v", rel2.Report.ReleaseCleanupPending)
	}
	// After the last hold is released, base retention (not a hold) governs.
	for _, r := range h1.Report.ProtectedVersions {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("legal hold remains ON after every hold was released: %s", r.Key)
		}
	}
}

// Case E: two holds, release both, expired: the unheld control becomes
// eligible again and expires normally through the full disposal lifecycle.
func TestCaseEBothReleasedThenControlExpires(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-E", f.p1, f.m1, f.u["alice"])
	h1 := f.placeHold("carol", f.m1, "first")
	h2 := f.placeHold("erin", f.m1, "second")
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("erin"), h2.ID, "r2"); err != nil {
		t.Fatal(err)
	}
	if got := f.sweepAs("carol"); got != 1 {
		t.Fatalf("unheld expired control must be eligible, marked %d", got)
	}
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-E"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	if outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-E")); err != nil || outcome != "disposed" {
		t.Fatalf("finish outcome %s err %v", outcome, err)
	}
	if it := f.item("T-E"); it.State != records.ItemDisposed {
		t.Fatalf("state %s, want disposed", it.State)
	}
	for _, r := range h1.Report.ProtectedVersions {
		if !f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("version %s not physically deleted", r.Key)
		}
	}
}

// Case F: purge begun (tombstoned), hold acknowledged between begin and the
// conditional delete, finish attempted: the hold wins - the tombstone is
// lifted, no byte is deleted, and the finish refuses.
func TestCaseFHoldAcknowledgedDuringInflightPurge(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-F", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-F"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	// The hold commits while the purge is in flight (after begin, before
	// finish). Placement restores the tombstoned item and bumps the epoch.
	f.placeHold("carol", f.m1, "inflight-hold")
	if it := f.item("T-F"); it.State != records.ItemActive {
		t.Fatalf("tombstone must be lifted by the acknowledged hold: %s", it.State)
	}
	outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-F"))
	if err != nil {
		t.Fatal(err)
	}
	if outcome != "not_purging" && outcome != "restored_active" {
		t.Fatalf("finish outcome %s: the conditional delete must refuse", outcome)
	}
	for _, r := range refsOf(f, f.turnID("T-F")) {
		if f.fs.isDeleted(r.Key, r.Version) {
			t.Fatal("a byte was deleted although the hold was acknowledged first")
		}
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("version %s not protected: %q", r.Key, state)
		}
	}
	// The fence itself: while a conditional delete transaction holds the
	// matter epoch row, a concurrent hold placement cannot commit - the
	// linearization point of ADR 0001 section 7. A second turn stands in so
	// the finisher reaches the epoch lock.
	f.seedTurn("T-F2", f.p2, f.m2, f.u["bob"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-F2"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin (fence turn) outcome %s err %v", outcome, err)
	}
	block := make(chan struct{})
	release := make(chan struct{})
	f.rs.Hooks.AtEpochLock = func(stage, tenant, matter string) {
		if stage == "finish_purge" {
			close(block)
			<-release
		}
	}
	finishing := make(chan struct{})
	go func() {
		_, _, _ = f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-F2"))
		close(finishing)
	}()
	<-block
	placed := make(chan error, 1)
	go func() {
		_, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "fenced-hold", "idem-fence")
		placed <- err
	}()
	select {
	case err := <-placed:
		t.Fatalf("hold placement committed while the conditional delete was in flight: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	<-finishing
	if err := <-placed; err != nil {
		t.Fatalf("queued placement after the fence released: %v", err)
	}
}

// Case G: purge begun, an UNRELATED epoch change (a hold scoped to another
// custodian, placed and released), finish attempted: no blind delete; the
// purge restarts under the new epoch.
func TestCaseGUnrelatedEpochChangeRestartsPurge(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-G", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-G"), nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	// An epoch change that does not match the item: a custodian-scoped hold
	// for bob (the item belongs to alice), placed and released.
	h := f.placeHold("carol", f.m1, "unrelated-epoch", f.u["bob"])
	if it := f.item("T-G"); it.State != records.ItemPurging {
		t.Fatalf("unrelated hold must not restore the item: %s", it.State)
	}
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "unrelated-done"); err != nil {
		t.Fatal(err)
	}
	if outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), f.turnID("T-G")); err != nil || outcome != "stale_retry" {
		t.Fatalf("finish outcome %s err %v (want stale_retry: restart under the new epoch)", outcome, err)
	}
	if it := f.item("T-G"); it.State != records.ItemDisposalPending {
		t.Fatalf("state %s, want disposal_pending restart", it.State)
	}
	for _, r := range refsOf(f, f.turnID("T-G")) {
		if f.fs.isDeleted(r.Key, r.Version) {
			t.Fatal("no byte may be deleted on a stale epoch")
		}
	}
}

func refsOf(f *rfx, turn string) []struct{ Key, Version string } {
	refs, err := f.fb.TurnVersionRefs(f.ctx(), f.tenant, turn)
	if err != nil {
		f.t.Fatal(err)
	}
	out := make([]struct{ Key, Version string }, 0, len(refs))
	for _, r := range refs {
		out = append(out, struct{ Key, Version string }{r.Key, r.Version})
	}
	return out
}

func ptrPrincipal(p store.Principal) *store.Principal { return &p }

// The grace period between sweep and purge approval is enforced.
func TestPurgeRequiresGraceElapsed(t *testing.T) {
	f := newRfx(t)
	if err := f.rs.SetPolicy(f.ctx(), f.principal("carol"), 1, 3600); err != nil {
		t.Fatal(err)
	}
	f.seedTurn("T-GR", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-GR"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if outcome != "grace_not_elapsed" {
		t.Fatalf("outcome %s, want grace_not_elapsed", outcome)
	}
}

// Separation of duties: the officer whose sweep requested disposal cannot
// approve its purge.
func TestPurgeApproverMustDifferFromSweepRequester(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-SOD", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol") // carol requested disposal
	_, err := f.rs.BeginPurge(f.ctx(), f.principal("carol"), f.turnID("T-SOD"), nil)
	if !errors.Is(err, store.ErrForbidden) {
		t.Fatalf("same-officer purge must be forbidden, got %v", err)
	}
	outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), f.turnID("T-SOD"), nil)
	if err != nil || outcome != "purging" {
		t.Fatalf("different-officer purge outcome %s err %v", outcome, err)
	}
}

// Only records officers act on the lifecycle; admins, operators, members and
// other tenants are all refused (fail closed).
func TestLifecycleAuthorization(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-AUTH", f.p1, f.m1, f.u["alice"])
	for _, name := range []string{"dave", "frank", "alice", "zed"} {
		p := f.principal(name)
		if _, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1}, "reason", "idem-"+name); !errors.Is(err, store.ErrForbidden) && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s placed a hold: %v", name, err)
		}
		if _, err := f.rs.ReleaseHold(f.ctx(), p, "00000000-0000-0000-0000-000000000000", "r"); !errors.Is(err, store.ErrForbidden) && !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s released a hold: %v", name, err)
		}
	}
	// Records officers of another tenant cannot see or act on this hold.
	h := f.placeHold("carol", f.m1, "authz")
	if _, err := f.rs.GetHold(f.ctx(), f.principal("zed"), h.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("cross-tenant hold inspection must fail closed: %v", err)
	}
}

// Cross-tenant scope substitution fails closed: a matter or custodian that
// only exists in another tenant is indistinguishable from a nonexistent one.
func TestCrossTenantScopeSubstitutionFailsClosed(t *testing.T) {
	f := newRfx(t)
	var otherMatter, otherUser string
	if err := f.pool.QueryRow(f.ctx(), `SELECT p.matter_id::text, u.id::text FROM projects p, users u WHERE p.tenant_id=$1 AND u.tenant_id=$1 LIMIT 1`, f.other).Scan(&otherMatter, &otherUser); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: otherMatter}, "r", "idem-x1"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign matter accepted: %v", err)
	}
	if _, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1, CustodianIDs: []string{otherUser}}, "r", "idem-x2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("foreign custodian accepted: %v", err)
	}
	// A matter change through the scope-change endpoint is a substitution.
	h := f.placeHold("carol", f.m1, "sub")
	if _, err := f.rs.ChangeScope(f.ctx(), f.principal("carol"), h.ID, records.Scope{MatterID: otherMatter}, "change"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("matter substitution accepted: %v", err)
	}
}

// Custodian revocation (disable) never releases a hold scoped to that
// custodian, and the hold's protection survives.
func TestCustodianRevocationDoesNotReleaseHold(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-CR", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "custodian-scoped", f.u["alice"])
	if err := f.st.DisableUser(f.ctx(), f.principal("dave"), f.u["alice"]); err != nil {
		t.Fatal(err)
	}
	after, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != records.HoldEffective {
		t.Fatalf("revocation changed hold state to %s", after.State)
	}
	held, _, err := f.svc.ItemHeld(f.ctx(), f.principal("carol"), f.turnID("T-CR"))
	if err != nil || !held {
		t.Fatal("item must stay held after custodian revocation")
	}
	if f.sweepAs("erin") != 0 {
		t.Fatal("held item became a disposal candidate after revocation")
	}
	// The revoked custodian loses workspace access but the lifecycle record
	// is intact: the report still names the custodian's turns.
	found := false
	for _, it := range h.Report.Items {
		if it.TurnID == f.turnID("T-CR") {
			found = true
		}
	}
	if !found {
		t.Fatal("coverage report lost the custodian's turn")
	}
}

// Placement protection failure: the hold is never acknowledged effective; it
// stays failed with an honest report, the fence remains in force, and a
// retry succeeds (idempotent).
func TestProtectionFailureFailsClosedAndRetries(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-PF", f.p1, f.m1, f.u["alice"])
	f.fs.failSet = errors.New("storage outage")
	p := f.principal("carol")
	_, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1}, "reason", "idem-fail")
	if err == nil {
		t.Fatal("placement must fail closed when protection cannot be established")
	}
	holds, err := f.rs.ListHolds(f.ctx(), p)
	if err != nil {
		t.Fatal(err)
	}
	var failed *records.Hold
	for _, h := range holds {
		if h.IdempotencyKey == "idem-fail" {
			failed = h
		}
	}
	if failed == nil || failed.State != records.HoldFailed {
		t.Fatalf("failed hold not recorded durably: %+v", failed)
	}
	if failed.Report.Error == "" {
		t.Fatal("failure detail missing")
	}
	// The fence still blocks disposal of matching items.
	if f.sweepAs("carol") != 0 {
		t.Fatal("a failed (fenced) hold must still block disposal")
	}
	// Recovery re-establishes protection and marks it effective.
	f.fs.failSet = nil
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	after, err := f.rs.GetHold(f.ctx(), p, failed.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.State != records.HoldEffective {
		t.Fatalf("retry state %s, want effective", after.State)
	}
	for _, r := range after.Report.ProtectedVersions {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("version %s not protected after recovery", r.Key)
		}
	}
}

// Protection readback failure (legal hold set but readback says OFF) is a
// fail-closed condition, never a silent downgrade.
func TestProtectionReadbackMismatchFailsClosed(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-RB", f.p1, f.m1, f.u["alice"])
	// Corrupt the readback: the fake reports OFF after set.
	f.fs.mu.Lock()
	original := f.fs.legalHold
	f.fs.legalHold = map[string]string{}
	f.fs.mu.Unlock()
	f.fs.failRead = nil
	// Make SetLegalHold succeed but every readback report OFF.
	f.fs.legalHoldAfter = "OFF"
	p := f.principal("carol")
	_, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1}, "reason", "idem-rb")
	if err == nil {
		t.Fatal("readback mismatch must fail the placement")
	}
	f.fs.legalHoldAfter = ""
	f.fs.mu.Lock()
	f.fs.legalHold = original
	f.fs.mu.Unlock()
}

// A hold placement with the same idempotency key is exactly-once: retries
// return the durable hold without duplicating protection epochs or audits.
func TestIdempotentPlacement(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-ID", f.p1, f.m1, f.u["alice"])
	p := f.principal("carol")
	h1, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1}, "reason", "idem-same")
	if err != nil {
		t.Fatal(err)
	}
	var epoch1 int64 = h1.Epoch
	h2, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1}, "reason", "idem-same")
	if err != nil {
		t.Fatal(err)
	}
	if h2.ID != h1.ID || h2.Epoch != epoch1 {
		t.Fatalf("retry created or bumped a hold: %+v vs %+v", h1, h2)
	}
	count, err := countAudit(f, "hold.place")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("hold.place audit rows = %d, want 1", count)
	}
}

func countAudit(f *rfx, action string) (int, error) {
	var n int
	err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM audit_log WHERE action=$1`, action).Scan(&n)
	return n, err
}

// Release authorization and storage completion are distinct: a release whose
// cleanup cannot complete removes the claim but keeps protection (never a
// silent downgrade), and reconciliation completes it later.
func TestReleaseCleanupPendingIsConservative(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-RC", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "release-cleanup")
	// Storage goes down after the claim is durably removed.
	f.fs.failSet = errors.New("storage outage during cleanup")
	rel, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "done")
	if err != nil {
		t.Fatalf("release claim removal failed: %v", err)
	}
	if rel.State != records.HoldReleased {
		t.Fatalf("state %s", rel.State)
	}
	// Disposal is now possible in principle (claim removed), but the legal
	// hold cleanup never completed: the bytes remain protected.
	for _, r := range h.Report.ProtectedVersions {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("cleanup failure must leave protection in place (over-protection), got %q", state)
		}
	}
	// The pending cleanup is recorded durably and reconciliation retries it.
	after, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Report.ReleaseCleanupPending) == 0 {
		t.Fatal("pending cleanup not recorded")
	}
	f.fs.failSet = nil
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	final, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(final.Report.ReleaseCleanupPending) != 0 {
		t.Fatalf("cleanup still pending after recovery: %+v", final.Report.ReleaseCleanupPending)
	}
	for _, r := range h.Report.ProtectedVersions {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("legal hold not cleared after recovery: %s", r.Key)
		}
	}
}

// Already-expired records at activation are reported, not silently assumed
// preserved: the hold protects what exists and names what expired.
func TestAlreadyExpiredRecordsAreReported(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-EXP", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "expiry-report")
	found := false
	for _, it := range h.Report.Items {
		if it.TurnID == f.turnID("T-EXP") && it.AlreadyExpired {
			found = true
		}
	}
	if !found {
		t.Fatal("already-expired in-scope record not reported")
	}
}

// Uncovered records (versions missing at establishment) block the effective
// transition and are reported explicitly.
func TestUncoveredRecordsBlockEffective(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-UC", f.p1, f.m1, f.u["alice"])
	f.fb.noRefs[f.turnID("T-UC")] = true // in the inventory, but versions cannot be enumerated
	if _, err := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "uncovered", "idem-uc"); err == nil {
		t.Fatal("incomplete protection must not be acknowledged as a successful activation")
	}
	holds, err := f.rs.ListHolds(f.ctx(), f.principal("carol"))
	if err != nil {
		t.Fatal(err)
	}
	var h *records.Hold
	for _, cand := range holds {
		if cand.IdempotencyKey == "idem-uc" {
			h = cand
		}
	}
	if h == nil || h.State != records.HoldFailed {
		t.Fatalf("state %+v, want failed (uncovered records block effective)", h)
	}
	if len(h.Report.Uncovered) != 1 || h.Report.Uncovered[0] != f.turnID("T-UC") {
		t.Fatalf("uncovered record not reported: %+v", h.Report)
	}
}
