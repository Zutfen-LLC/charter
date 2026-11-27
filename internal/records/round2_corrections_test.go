package records_test

import (
	"context"
	"errors"
	"sort"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/records"
)

// C07 round-2 review corrections: every test here is executable RED
// evidence at the reviewed head 3f3d700 (retained logs in
// charter-c07-correction2/red/) and GREEN at the corrected head.

// TurnNamespaceRefs mirrors the retained backend's namespace fallback
// enumeration: every version listed under the turn's own namespaces (event
// slots, data events) plus the object versions of its still-decodable slot
// commits, WITHOUT chain verification, with completeness classification: a
// listed slot marker whose read fails (namespaceFail) or whose candidate
// cannot be verified (namespaceCorrupt) makes the enumeration INCOMPLETE -
// its references are unknown, never silently absent.
func (b *fakeBackend) TurnNamespaceRefs(ctx context.Context, tenantID, turnID string) (evidence.NamespaceEnumeration, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	commits, ok := b.commits[turnID]
	if !ok {
		return evidence.NamespaceEnumeration{}, evidence.ErrNotFound
	}
	out := []evidence.VersionRef{}
	complete := true
	gone := func(r evidence.VersionRef) bool {
		return b.storage != nil && b.storage.isDeleted(r.Key, r.Version)
	}
	for i, c := range commits {
		if i == 0 {
			continue // the namespace walk has no admission root
		}
		if gone(c.slot) {
			// A hole in the listed slot sequence: the missing slot's
			// references are unknown.
			complete = false
			continue
		}
		out = append(out, c.slot)
		if b.namespaceFail[turnID] || b.namespaceCorrupt[turnID] {
			// Unreadable or unverifiable marker: its references are unknown.
			complete = false
			continue
		}
		if c.event != nil && !gone(*c.event) {
			out = append(out, *c.event)
		}
		for _, o := range c.objects {
			if !gone(o) {
				out = append(out, o)
			}
		}
	}
	if len(out) == 0 {
		return evidence.NamespaceEnumeration{}, evidence.ErrNotFound
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return evidence.NamespaceEnumeration{Refs: out, Complete: complete}, nil
}

// ---------------- Finding 1: hold coverage of partially disposed records ----------------

// A matching record whose admission marker was deleted mid-disposal (the
// purge transaction failed, the durable plan still has outstanding
// versions) must not silently disappear from hold coverage: it needs an
// attributable disposition, its remaining bytes receive protection, and
// direct deletion of those bytes after base retention must be refused.
func TestPartiallyDisposedTurnAppearsInHoldCoverage(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-PDC", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), id, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	// The durable exact-version plan commits before any deletion.
	outcome := ""
	if err := f.rs.FinishPurgePlanTx(f.ctx(), ptrPrincipal(f.principal("erin")), f.tenant, id, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return f.fb.TurnDisposalRefs(ctx, f.tenant, id)
	}, &outcome); err != nil {
		t.Fatal(err)
	}
	// The disposal is interrupted after the admission marker was physically
	// deleted while other required versions remain; the transaction never
	// commits dispositions.
	if err := f.fs.DeleteVersion(f.ctx(), refs[0].Key, refs[0].Version); err != nil {
		t.Fatal(err)
	}
	f.fb.dropTurn(f.tenant, id)
	// A matching hold is placed before any disposal recovery completes.
	h := f.placeHold("carol", f.m1, "coverage of a partially disposed turn")
	inItems := false
	for _, it := range h.Report.Items {
		if it.TurnID == id {
			inItems = true
		}
	}
	inUncovered := false
	for _, u := range h.Report.Uncovered {
		if u == id {
			inUncovered = true
		}
	}
	inGaps := false
	for _, g := range h.Report.DisposedBeforeHold {
		if g == id {
			inGaps = true
		}
	}
	if !inItems && !inUncovered && !inGaps {
		t.Fatalf("FINDING 1: matching record %s is absent from Items, Uncovered and DisposedBeforeHold while the hold is %s", id, h.State)
	}
	// The surviving versions receive the required native protection.
	for _, r := range refs[1:] {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("FINDING 1: surviving version %s unprotected (legal hold %q) under an acknowledged hold", r.Key, state)
		}
		if err := f.fs.DeleteVersion(f.ctx(), r.Key, r.Version); !errors.Is(err, s3transport.ErrObjectProtected) {
			t.Fatalf("FINDING 1: direct deletion of a protected surviving version must be refused, got %v", err)
		}
	}
}

// A matching record restored to active whose live enumeration root is gone
// and which has no durable plan is UNVERIFIABLE: it is reported uncovered
// and prevents the effective acknowledgment (no effective hold may be
// based on silently incomplete inventory).
func TestUnverifiableRestoredTurnBlocksEffective(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-URB", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	// Root deleted without any disposal plan or committed disposition.
	refs := refsOf(f, id)
	if err := f.fs.DeleteVersion(f.ctx(), refs[0].Key, refs[0].Version); err != nil {
		t.Fatal(err)
	}
	f.fb.dropTurn(f.tenant, id)
	h, placeErr := f.svc.Place(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "unverifiable restored record", "idem-r2-urb")
	if placeErr == nil && h != nil && h.State == records.HoldEffective {
		t.Fatal("FINDING 1: hold acknowledged effective while a matching record is unverifiable and absent from every coverage disposition")
	}
	var holdID string
	if err := f.pool.QueryRow(f.ctx(), `SELECT id::text FROM holds WHERE idempotency_key=$1`, "idem-r2-urb").Scan(&holdID); err != nil {
		t.Fatal(err)
	}
	stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), holdID)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range stored.Report.Uncovered {
		if u == id {
			found = true
		}
	}
	if !found {
		t.Fatalf("FINDING 1: unverifiable record %s not reported uncovered (state %s, report %+v)", id, stored.State, stored.Report)
	}
}

// A catalog-loading error is never converted into an empty catalog: the
// coverage determination fails instead of acknowledging on silently
// incomplete inventory.
func TestCatalogLoadErrorFailsEstablishment(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-CLE", f.p1, f.m1, f.u["alice"])
	h := f.placeHold("carol", f.m1, "catalog error establishment")
	// The turn leaves the live inventory and the catalog becomes
	// unreadable before a reestablishment.
	f.fb.dropTurn(f.tenant, id)
	if _, err := f.pool.Exec(f.ctx(), `ALTER TABLE retention_items RENAME TO retention_items_unreadable`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := f.pool.Exec(f.ctx(), `ALTER TABLE retention_items_unreadable RENAME TO retention_items`); err != nil {
			t.Fatal(err)
		}
	}()
	if _, err := f.svc.Reestablish(f.ctx(), h); err == nil {
		t.Fatal("FINDING 1: a lifecycle catalog load failure was treated as an empty catalog; establishment must fail instead")
	}
}

// ---------------- Finding 3: unsafe namespace fallback ----------------

// Two records share an exact content-addressed object version. The second
// record is intact, but its verified enumeration and the fallback
// enumeration of its marker fail transiently. Disposal of the first record
// must be REFUSED: an unreadable reference is never an absent reference.
func TestUnreadableSiblingMarkerBlocksSharedVersionDeletion(t *testing.T) {
	f := newRfx(t)
	tA := f.seedTurn("T-F3A", f.p1, f.m1, f.u["alice"], "f3-shared")
	tB := f.seedTurn("T-F3B", f.p1, f.m1, f.u["alice"], "f3-shared")
	f.sweepAs("carol")
	var shared struct{ Key, Version string }
	for _, r := range refsOf(f, tB) {
		if r.Key == "ns/objects/f3-shared" {
			shared = r
		}
	}
	if shared.Key == "" {
		t.Fatal("no shared version seeded")
	}
	// B's enumeration root and marker reads fail (transient storage error).
	f.fb.failEnum[tB] = &transportErr{}
	f.fb.namespaceFail[tB] = true
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), tA, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), tA); err == nil {
		t.Fatal("FINDING 3: disposal was authorized while a sibling record's reference set was unknown")
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatal("FINDING 3: the shared exact version was deleted while the sibling's reference was unreadable")
	}
	if it := f.itemByID(tA); it.State == records.ItemDisposed {
		t.Fatal("FINDING 3: disposal completed on unknown sibling references")
	}
	// Storage access is restored: the disposal now converges, and the
	// shared version survives it (retained_shared).
	f.fb.failEnum[tB] = nil
	f.fb.namespaceFail[tB] = false
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), tA); err != nil {
		t.Fatalf("disposal must converge once the sibling enumerates: %v", err)
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatal("FINDING 3: the shared version must survive the disposal of the other reference")
	}
	if it := f.itemByID(tA); it.State != records.ItemDisposed {
		t.Fatalf("FINDING 3: disposal did not converge: %s", it.State)
	}
}

// Invalid signed metadata for a sibling's listed marker is an unknown
// reference set, never a reference-free one: the irreversible deletion is
// refused.
func TestCorruptSiblingMetadataBlocksSharedVersionDeletion(t *testing.T) {
	f := newRfx(t)
	tA := f.seedTurn("T-F3C", f.p1, f.m1, f.u["alice"], "f3c-shared")
	tB := f.seedTurn("T-F3D", f.p1, f.m1, f.u["alice"], "f3c-shared")
	f.sweepAs("carol")
	var shared struct{ Key, Version string }
	for _, r := range refsOf(f, tB) {
		if r.Key == "ns/objects/f3c-shared" {
			shared = r
		}
	}
	f.fb.failEnum[tB] = &transportErr{}
	f.fb.namespaceCorrupt[tB] = true
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), tA, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), tA); err == nil {
		t.Fatal("FINDING 3: disposal was authorized while a sibling's signed metadata was unverifiable")
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatal("FINDING 3: the shared exact version was deleted under an unverifiable sibling marker")
	}
}

// Release cleanup must not remove native protection while a REQUIRED
// turn's reference set is unknown: the second record is held by another
// hold whose protection depends on the shared version.
func TestUnreadableRequiredReferenceBlocksProtectionRemoval(t *testing.T) {
	f := newRfx(t)
	tB := f.seedTurn("T-F3F", f.p1, f.m1, f.u["bob"], "f3e-shared")
	h1 := f.placeHold("carol", f.m1, "broad hold over both records")
	h2 := f.placeHold("carol", f.m1, "narrow hold over the second record", f.u["bob"])
	var shared struct{ Key, Version string }
	for _, r := range refsOf(f, tB) {
		if r.Key == "ns/objects/f3e-shared" {
			shared = r
		}
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("shared version must be protected under both holds, got %q", state)
	}
	// B's enumeration becomes unreadable while H1 releases: B is still
	// REQUIRED by H2, and its unknown reference set must block the cleanup.
	f.fb.failEnum[tB] = &transportErr{}
	f.fb.namespaceFail[tB] = true
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "release under an unreadable required reference"); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("FINDING 3: native protection was removed while a required record's references were unreadable (state %q)", state)
	}
	if stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h2.ID); err != nil || stored.State != records.HoldEffective {
		t.Fatalf("FINDING 3: the narrower hold must stay effective: %v %+v", err, stored)
	}
	// Access restored: the idempotent release retry converges the cleanup,
	// and the shared version stays protected for H2.
	f.fb.failEnum[tB] = nil
	f.fb.namespaceFail[tB] = false
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h1.ID, "release retry"); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("FINDING 3: H2 still requires the shared version, got %q", state)
	}
}

// ---------------- Finding 4: disposal-plan destruction after partial deletion ----------------

// A physical delete may have committed at the storage while the disposal
// transaction rolled back. A later hold intervenes and the item is
// restored: the plan (the only remaining exact-version inventory) must not
// be destroyed, the loss must be recorded, the remaining bytes protected,
// and a later release and disposal must remain recoverable.
func TestRestorePreservesPlanAfterPartialDeletion(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-RPP", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), id, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	outcome := ""
	if err := f.rs.FinishPurgePlanTx(f.ctx(), ptrPrincipal(f.principal("erin")), f.tenant, id, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return f.fb.TurnDisposalRefs(ctx, f.tenant, id)
	}, &outcome); err != nil {
		t.Fatal(err)
	}
	// The first delete (the admission marker) commits at the storage; the
	// transaction is lost before recording dispositions.
	if err := f.fs.DeleteVersion(f.ctx(), refs[0].Key, refs[0].Version); err != nil {
		t.Fatal(err)
	}
	f.fb.dropTurn(f.tenant, id)
	// A matching hold intervenes: the placement restores the item and must
	// protect the remaining bytes.
	h := f.placeHold("carol", f.m1, "hold over a partially deleted record")
	for _, r := range refs[1:] {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("FINDING 4: remaining version %s unprotected after the hold (state %q)", r.Key, state)
		}
	}
	// The stale purge completion runs: the restore must not destroy the
	// only remaining exact-version inventory, and the partially deleted
	// state must be represented honestly in the plan.
	if outcome, _, _ := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), id); outcome == "disposed" {
		t.Fatal("FINDING 4: a held, partially deleted record must not complete disposal")
	}
	plan, err := f.rs.PlanOf(f.ctx(), f.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != len(refs) {
		t.Fatalf("FINDING 4: the disposal plan was destroyed after a partial physical deletion (%d of %d versions remain inventoried)", len(plan), len(refs))
	}
	missingDispositioned := false
	for _, row := range plan {
		if row.Key == refs[0].Key && row.Version == refs[0].Version {
			if row.Disposition == records.OutcomeAbsent || row.Disposition == records.OutcomeDeleted {
				missingDispositioned = true
			}
		}
	}
	if !missingDispositioned {
		t.Fatalf("FINDING 4: the physically deleted version is not recorded as gone in the durable plan: %+v", plan)
	}
	if it := f.itemByID(id); it.State != records.ItemActive {
		t.Fatalf("FINDING 4: restored item state %s, want active", it.State)
	}
	// Release the hold: the eventual disposal of the remaining bytes stays
	// recoverable (the plan drives it to a verified completion).
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "release after partial restore"); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // retention (1s) re-expires
	if _, err := f.svc.Sweep(f.ctx(), f.principal("carol")); err != nil {
		t.Fatal(err)
	}
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), id, nil); err != nil || outcome != "purging" {
		t.Fatalf("second begin outcome %s err %v", outcome, err)
	}
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), id); err != nil {
		t.Fatalf("FINDING 4: the eventual disposal of the remaining bytes failed: %v", err)
	}
	if it := f.itemByID(id); it.State != records.ItemDisposed {
		t.Fatalf("FINDING 4: eventual disposal did not complete: %s", it.State)
	}
	for i, r := range refs {
		gone := f.fs.isDeleted(r.Key, r.Version)
		if i == 0 && !gone {
			t.Fatal("FINDING 4: the pre-deleted version must stay recorded as gone")
		}
	}
}

// A successful DeleteVersion response alone is not proof of physical
// absence: the disposal must verify by readback and refuse to complete
// when the bytes are still readable.
func TestDeleteResponseAloneIsNotAbsence(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-DLA", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), id, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	// The storage acknowledges every delete without deleting.
	f.fs.mu.Lock()
	f.fs.lieDelete = true
	f.fs.mu.Unlock()
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), id); err == nil {
		t.Fatal("FINDING 4: a disposal completed on delete acknowledgments alone, without storage readback")
	}
	if it := f.itemByID(id); it.State == records.ItemDisposed {
		t.Fatal("FINDING 4: disposal claimed while the versions are still readable")
	}
	refs := refsOf(f, id)
	surviving := 0
	for _, r := range refs {
		if !f.fs.isDeleted(r.Key, r.Version) {
			surviving++
		}
	}
	if surviving != len(refs) {
		t.Fatalf("FINDING 4: %d of %d versions were actually deleted by a lying acknowledgment", len(refs)-surviving, len(refs))
	}
}

// ---------------- Finding 5: hold placement idempotency and scope binding ----------------

// A reused idempotency key with a CHANGED placement intent fails
// explicitly; an identical retry returns the original durable hold with no
// duplicate hold, epoch bump or audit entry.
func TestIdempotentKeyRejectsChangedPlacementIntent(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-IDR", f.p1, f.m1, f.u["alice"])
	p := f.principal("carol")
	key := "idem-r2-intent"
	windowStart := time.Now().Add(-24 * time.Hour)
	windowEnd := time.Now().Add(24 * time.Hour)
	h1, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: &windowStart, WindowEnd: &windowEnd}, "original authorized intent", key)
	if err != nil {
		t.Fatal(err)
	}
	mustFail := func(name string, scope records.Scope, reason, actor string) {
		t.Helper()
		pr := f.principal(actor)
		h, err := f.svc.Place(f.ctx(), pr, scope, reason, key)
		if err == nil {
			t.Fatalf("FINDING 5: reusing key %q with a changed %s acknowledged the unrelated existing hold %s", key, name, h.ID)
		}
		if !errors.Is(err, records.ErrConflict) {
			t.Fatalf("FINDING 5: changed %s must fail explicitly (409 conflict), got %v", name, err)
		}
	}
	// A different matter under the same key.
	mustFail("matter", records.Scope{MatterID: f.m2, CustodianIDs: []string{f.u["alice"]}, WindowStart: &windowStart, WindowEnd: &windowEnd}, "original authorized intent", "carol")
	// A different custodian selection.
	mustFail("custodian selection", records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["bob"]}, WindowStart: &windowStart, WindowEnd: &windowEnd}, "original authorized intent", "carol")
	// A changed time window.
	otherEnd := windowEnd.Add(time.Hour)
	mustFail("time window", records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: &windowStart, WindowEnd: &otherEnd}, "original authorized intent", "carol")
	// A changed reason (placement intent includes the recorded reason).
	mustFail("reason", records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: &windowStart, WindowEnd: &windowEnd}, "a different reason", "carol")
	// Another authorized records officer reusing the key.
	mustFail("placing officer", records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: &windowStart, WindowEnd: &windowEnd}, "original authorized intent", "erin")
	// The identical retry returns the original durable operation and its
	// current outcome with no duplicate hold, epoch bump or audit row.
	before, err := f.rs.GetHold(f.ctx(), p, h1.ID)
	if err != nil {
		t.Fatal(err)
	}
	audits, err := countAudit(f, "hold.place")
	if err != nil {
		t.Fatal(err)
	}
	h2, err := f.svc.Place(f.ctx(), p, records.Scope{MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: &windowStart, WindowEnd: &windowEnd}, "original authorized intent", key)
	if err != nil {
		t.Fatal(err)
	}
	if h2.ID != h1.ID || h2.Epoch != before.Epoch || h2.State != before.State {
		t.Fatalf("FINDING 5: identical retry returned a different durable outcome: %+v vs %+v", h2, before)
	}
	if n, err := countAudit(f, "hold.place"); err != nil || n != audits {
		t.Fatalf("FINDING 5: identical retry wrote %d additional audit rows", n-audits)
	}
	var count int
	if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM holds WHERE idempotency_key=$1`, key).Scan(&count); err != nil || count != 1 {
		t.Fatalf("FINDING 5: %d holds exist under one key", count)
	}
	if h2.PlacedBy != p.UserID {
		t.Fatalf("FINDING 5: actor attribution not preserved: %s vs %s", h2.PlacedBy, p.UserID)
	}
}

// ---------------- Finding 6: claims ledger consistency ----------------

// Protection completion cannot succeed on a missing claim row: the durable
// claim ledger must own every native protection mutation.
func TestMarkClaimProtectedRequiresClaimRow(t *testing.T) {
	f := newRfx(t)
	tx, err := f.pool.Begin(f.ctx())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(f.ctx()) //nolint:errcheck
	v := records.VersionRef{Key: "ns/objects/never-claimed", Version: "v-never"}
	if err := records.MarkClaimProtected(f.ctx(), tx, "00000000-0000-0000-0000-000000000000", v); err == nil {
		t.Fatal("FINDING 6: MarkClaimProtected succeeded without a durable claim row")
	}
}

// A hold that becomes applicable between EnsureProtected's claim phase and
// its native-mutation phase receives its durable claims in the SAME fence
// transaction, before the native mutation: native protection without a
// durable owner is impossible.
func TestNewApplicableHoldBetweenPhasesGetsDurableClaim(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-NAB", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	// H1 is pending: the recorder-side guard is what protects the turn.
	h1, err := f.rs.PlaceHold(f.ctx(), f.principal("carol"), records.Scope{MatterID: f.m1}, "first applicable hold", "idem-r2-nab1")
	if err != nil {
		t.Fatal(err)
	}
	// A second hold becomes applicable between the two phases (the
	// deterministic interleave point added by the correction).
	var h2 *records.Hold
	var hookErr error
	f.svc.Hooks.BeforeApplicableReload = func() {
		f.svc.Hooks.BeforeApplicableReload = nil
		h2, hookErr = f.rs.PlaceHold(f.ctx(), f.principal("erin"), records.Scope{MatterID: f.m1}, "concurrently applicable hold", "idem-r2-nab2")
	}
	defer func() { f.svc.Hooks.BeforeApplicableReload = nil }()
	if err := f.svc.EnsureProtected(f.ctx(), f.tenant, f.m1, f.u["alice"], id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if h2 == nil {
		t.Fatal("the concurrent hold was not placed")
	}
	// EVERY applicable hold owns a durable claim for every version, and the
	// native protection is actually established.
	for _, hold := range []*records.Hold{h1, h2} {
		claims, err := f.rs.ClaimsOfHold(f.ctx(), hold.ID)
		if err != nil {
			t.Fatal(err)
		}
		claimed := map[string]bool{}
		for _, c := range claims {
			claimed[c.Key+"|"+c.Version] = true
		}
		for _, r := range refs {
			if !claimed[r.Key+"|"+r.Version] {
				t.Fatalf("FINDING 6: hold %s received native protection without a durable claim on %s", hold.ID, r.Key)
			}
		}
	}
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("FINDING 6: version %s not protected (state %q)", r.Key, state)
		}
	}
}

// An effective hold repairs missing protection at recovery: a matching
// record admitted while the guard could not complete its protection (the
// interrupted/denied capture window) receives verified native protection
// without any user retry.
func TestRecoveryRepairsMissingProtectionOfEffectiveHold(t *testing.T) {
	f := newRfx(t)
	// The hold is acknowledged effective before the matching record exists.
	h := f.placeHold("carol", f.m1, "hold awaiting future matching work")
	if h.State != records.HoldEffective {
		t.Fatalf("hold not effective: %s", h.State)
	}
	// A matching record is published whose protection never completed (the
	// recorder gap under reproduction: terminal event committed, protection
	// failed, no client replay).
	id := f.seedTurn("T-EHR", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("setup: version %s unexpectedly protected", r.Key)
		}
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("FINDING 2/6: recovery did not repair the missing native protection of %s (state %q)", r.Key, state)
		}
		if err := f.fs.DeleteVersion(f.ctx(), r.Key, r.Version); !errors.Is(err, s3transport.ErrObjectProtected) {
			t.Fatalf("FINDING 2/6: direct deletion of a recovered-protected version must be refused, got %v", err)
		}
	}
}
