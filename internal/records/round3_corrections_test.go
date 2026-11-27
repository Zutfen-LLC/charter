package records_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/records"
)

// C07 round-3 review corrections: every test here is executable RED
// evidence at the reviewed head 702bb2f (retained logs in
// charter-c07-correction3/red/) and GREEN at the corrected head.

// seedTurn3Commit seeds a three-commit turn (admission, first event slot,
// terminal slot) whose shared input object hangs off the ADMISSION commit -
// the faithful retained shape: the admission marker is the only place a
// turn's input objects are referenced. When shared is non-empty, the object
// key "ns/objects/<shared>" is referenced by the admission ONLY (no later
// event repeats the reference).
func (f *rfx) seedTurn3Commit(label, project, matter, custodian, shared string) string {
	f.t.Helper()
	id := evidence.NewUUID()
	f.labelled[id] = label
	f.byLabel[label] = id
	t := evidence.TurnIdentity{
		TenantID: f.tenant, ProjectID: project, MatterID: matter,
		CustodianID: custodian, TurnID: id, RecordedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	admission := evidence.VersionRef{Key: "ns/" + id + "/admissions/x", Version: "v-" + id + "-0"}
	slot1 := evidence.VersionRef{Key: "ns/" + id + "/events/1", Version: "v-" + id + "-1"}
	slot2 := evidence.VersionRef{Key: "ns/" + id + "/events/2", Version: "v-" + id + "-2"} // terminal
	ev1 := evidence.VersionRef{Key: "ns/" + id + "/data/events/e1", Version: "v-" + id + "-3"}
	ev2 := evidence.VersionRef{Key: "ns/" + id + "/data/events/e2", Version: "v-" + id + "-4"}
	own := evidence.VersionRef{Key: "ns/" + id + "/objects/own", Version: "v-" + id + "-5"}
	admissionCommit := fakeCommit{slot: admission}
	if shared != "" {
		// The SAME exact version id the seedTurn convention mints for a
		// first shared parameter: one key, one version, two referencing
		// turns (content addressing deduplicates).
		admissionCommit.objects = []evidence.VersionRef{{Key: "ns/objects/" + shared, Version: "v-shared-0-" + shared}}
	}
	f.fb.addCommitTurn(t, []fakeCommit{
		admissionCommit,
		{slot: slot1, event: &ev1, objects: []evidence.VersionRef{own}},
		{slot: slot2, event: &ev2},
	})
	f.turns = append(f.turns, id)
	return id
}

// ---------------- Finding 1 (CRITICAL): shared-reference fallback excludes admission objects ----------------

// Two records in DIFFERENT matters share one exact content-addressed object
// version; the surviving record references it through its admission marker
// only. A chain gap on the surviving record forces fallback enumeration
// without a disposal plan. Disposal of the other eligible record must never
// delete the shared object version: the surviving admission evidence and
// every surviving version stay intact (cross-matter shared references).
func TestAdmissionSharedReferenceSurvivesSiblingDisposal(t *testing.T) {
	f := newRfx(t)
	// A carries the shared object on its first event (so A's own disposal
	// set contains it under the reviewed head's enumeration models); B
	// carries it on its admission marker ONLY.
	aID := f.seedTurn("T-R3A", f.p1, f.m1, f.u["alice"], "r3-shared")
	bID := f.seedTurn3Commit("T-R3B", f.p2, f.m2, f.u["bob"], "r3-shared")
	var shared evidence.VersionRef
	for _, r := range refsOf(f, bID) {
		if r.Key == "ns/objects/r3-shared" {
			shared = evidence.VersionRef{Key: r.Key, Version: r.Version}
		}
	}
	if shared.Key == "" {
		t.Fatal("setup: no shared version seeded")
	}
	// Break B's subsequent event chain (a deleted middle slot while the
	// terminal slot survives) so B's reference set resolves through the
	// namespace fallback, with no disposal plan for B.
	if err := f.fs.DeleteVersion(f.ctx(), "ns/"+bID+"/events/1", "v-"+bID+"-1"); err != nil {
		t.Fatal(err)
	}
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), aID, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	if _, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), aID); err != nil {
		t.Fatalf("the unrelated disposal must converge: %v", err)
	}
	// FINDING 1: the shared exact version must physically survive A's
	// disposal, because B's admission references it.
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("FINDING 1: the shared admission-only object version %s was deleted by the sibling's disposal: the surviving record's admission evidence is destroyed", shared.Key)
	}
	// B's admission marker and its own evidence stay intact.
	for _, r := range refsOf(f, bID) {
		if r.Key == "ns/"+bID+"/admissions/x" && f.fs.isDeleted(r.Key, r.Version) {
			t.Fatal("FINDING 1: the surviving record's admission marker was deleted")
		}
	}
	if it := f.itemByID(bID); it.State == records.ItemDisposed {
		t.Fatal("FINDING 1: the surviving record was disposed by the sibling's disposal")
	}
}

// Release cleanup must not remove the native legal hold of a version that a
// REQUIRED (still held) record references through its admission marker only:
// the same reference-resolution defect exercised against native protection
// removal instead of deletion.
func TestAdmissionSharedReferenceBlocksProtectionRemoval(t *testing.T) {
	f := newRfx(t)
	f.seedTurn("T-R3C", f.p1, f.m1, f.u["alice"], "r3e-shared")
	bID := f.seedTurn3Commit("T-R3D", f.p2, f.m2, f.u["bob"], "r3e-shared")
	// H_A over A's matter claims the shared version (via A's refs); H_B
	// over B's matter keeps B required after H_A releases.
	hA := f.placeHold("carol", f.m1, "hold over the first shared reference")
	hB := f.placeHold("erin", f.m2, "hold over the admission-only reference")
	var shared evidence.VersionRef
	for _, r := range refsOf(f, bID) {
		if r.Key == "ns/objects/r3e-shared" {
			shared = evidence.VersionRef{Key: r.Key, Version: r.Version}
		}
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("setup: shared version must be protected under both holds, got %q", state)
	}
	// B's verified enumeration breaks (two versions at one slot key - the
	// protected slots stay readable): B's reference set now resolves
	// through the namespace fallback.
	f.fb.chainConflict[bID] = true
	// H_A releases: the cleanup must NOT clear the shared version's legal
	// hold, because B - still held by the active H_B - references it.
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), hA.ID, "release under an admission-only sibling reference"); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("FINDING 1: native protection was removed from %s while a required record still references it through its admission marker (state %q)", shared.Key, state)
	}
	if stored, err := f.rs.GetHold(f.ctx(), f.principal("erin"), hB.ID); err != nil || stored.State != records.HoldEffective {
		t.Fatalf("FINDING 1: the still-applicable hold must stay effective: %v %+v", err, stored)
	}
}

// ---------------- Finding 2 (HIGH): native mutation precedes durable ownership commit ----------------

// A hold that becomes applicable between EnsureProtected's phases must have
// its ownership claims DURABLY COMMITTED before the native mutation: a
// failure after SetLegalHold but before the phase-2 transaction commits
// (process termination / rollback) leaves native protection ON with no
// committed owner, and a release before repair can never converge it. The
// "initially empty applicable-hold set" variant of the finding.
func TestNewlyApplicableClaimsSurviveNativeMutationCrash(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-R3E", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	// No hold is applicable when EnsureProtected starts (the initially
	// empty set): phase 1 commits nothing.
	var h2 *records.Hold
	var hookErr error
	f.svc.Hooks.BeforeApplicableReload = func() {
		f.svc.Hooks.BeforeApplicableReload = nil
		h2, hookErr = f.rs.PlaceHold(f.ctx(), f.principal("erin"), records.Scope{MatterID: f.m1}, "concurrently applicable hold", "idem-r3-crash")
	}
	defer func() { f.svc.Hooks.BeforeApplicableReload = nil }()
	// Deterministic crash after the native mutation, before the phase-2
	// transaction commits.
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "readback" {
			f.svc.Hooks.StorageFault = nil
			return errors.New("injected crash after the native mutation")
		}
		return nil
	}
	defer func() { f.svc.Hooks.StorageFault = nil }()
	err := f.svc.EnsureProtected(f.ctx(), f.tenant, f.m1, f.u["alice"], id, time.Now())
	if err == nil {
		t.Fatal("setup: the injected crash must fail the protection pass")
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if h2 == nil {
		t.Fatal("setup: the concurrent hold was not placed")
	}
	// H2 is released before effective-hold repair can reconstruct
	// ownership.
	if _, err := f.svc.Release(f.ctx(), f.principal("erin"), h2.ID, "release before repair"); err != nil {
		t.Fatal(err)
	}
	// FINDING 2: no version may keep native protection without a committed
	// owner in the claims ledger.
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 2: native protection left ON for %s with no committed ownership claim (the release could not converge it)", r.Key)
		}
	}
	var claims int
	if err := f.pool.QueryRow(f.ctx(), `SELECT count(*) FROM hold_version_claims WHERE hold_id=$1`, h2.ID).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if claims != 0 {
		t.Fatalf("FINDING 2: %d claims remain after the released hold's convergence", claims)
	}
}

// The claims-commit phase itself never performs the native mutation: a
// crash BEFORE any native mutation converges trivially (nothing was set),
// and the committed claims still fence.
func TestClaimsCommitCrashBeforeNativeMutationConverges(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-R3M", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	var h2 *records.Hold
	var hookErr error
	f.svc.Hooks.BeforeApplicableReload = func() {
		f.svc.Hooks.BeforeApplicableReload = nil
		h2, hookErr = f.rs.PlaceHold(f.ctx(), f.principal("erin"), records.Scope{MatterID: f.m1}, "concurrently applicable hold", "idem-r3-pre")
	}
	defer func() { f.svc.Hooks.BeforeApplicableReload = nil }()
	f.svc.Hooks.StorageFault = func(stage string) error {
		if stage == "protect" {
			f.svc.Hooks.StorageFault = nil
			return errors.New("injected crash before the native mutation")
		}
		return nil
	}
	defer func() { f.svc.Hooks.StorageFault = nil }()
	if err := f.svc.EnsureProtected(f.ctx(), f.tenant, f.m1, f.u["alice"], id, time.Now()); err == nil {
		t.Fatal("setup: the injected crash must fail the protection pass")
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	// Nothing was natively mutated...
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 2: a version was natively protected before the claims were committed... (state %q)", state)
		}
	}
	// ...and the release converges the committed claims.
	if _, err := f.svc.Release(f.ctx(), f.principal("erin"), h2.ID, "release before any mutation"); err != nil {
		t.Fatal(err)
	}
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 2: protection without a durable owner after the pre-mutation crash (state %q)", state)
		}
	}
}

// ---------------- Finding 3 (HIGH): partial disposal cannot resume after terminal-evidence loss ----------------

// disposeAndInterrupt drives one turn through an authorized, interrupted
// disposal: sweep, begin, plan, then a physical deletion at the given
// position while other exact versions survive. The turn's live enumeration
// root (admission) is always removed (the real deletion order deletes it
// first), so later hold coverage comes from the durable plan. deleteKey is
// the optional second version deleted at the interruption position
// ("" = admission-only).
func disposeAndInterrupt(f *rfx, label, deleteKey string) (string, []struct{ Key, Version string }) {
	f.t.Helper()
	id := f.seedTurn3Commit(label, f.p1, f.m1, f.u["alice"], "")
	refs := refsOf(f, id)
	f.sweepAs("carol")
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), id, nil); err != nil || outcome != "purging" {
		f.t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	outcome := ""
	if err := f.rs.FinishPurgePlanTx(f.ctx(), ptrPrincipal(f.principal("erin")), f.tenant, id, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return f.fb.TurnDisposalRefs(ctx, f.tenant, id)
	}, &outcome); err != nil {
		f.t.Fatal(err)
	}
	// Interrupt: the disposal deletes the admission (always) and the
	// targeted second version while the other planned versions survive;
	// the disposition transaction never commits.
	if err := f.fs.DeleteVersion(f.ctx(), refs[0].Key, refs[0].Version); err != nil {
		f.t.Fatal(err)
	}
	if deleteKey != "" {
		if err := f.fs.DeleteVersion(f.ctx(), deleteKey, versionOfKey(f, refs, deleteKey)); err != nil {
			f.t.Fatal(err)
		}
	}
	f.fb.dropTurn(f.tenant, id)
	return id, refs
}

func versionOfKey(f *rfx, refs []struct{ Key, Version string }, key string) string {
	f.t.Helper()
	for _, r := range refs {
		if r.Key == key {
			return r.Version
		}
	}
	f.t.Fatalf("no version for key %s", key)
	return ""
}

// resumeAfterRelease releases the hold, lets retention re-expire and runs
// the ordinary sweep/begin/finish operations, reporting whether the record
// reached a verified disposition.
func resumeAfterRelease(f *rfx, h *records.Hold, id string) (string, error) {
	f.t.Helper()
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "release after interrupted disposal"); err != nil {
		f.t.Fatal(err)
	}
	if err := f.svc.Recover(f.ctx()); err != nil {
		f.t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // retention (1s) re-expires
	if _, err := f.svc.Sweep(f.ctx(), f.principal("carol")); err != nil {
		f.t.Fatal(err)
	}
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), id, nil); err != nil {
		return "", err
	} else if outcome != "purging" {
		return "not_eligible: " + outcome, nil
	}
	outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), id)
	return outcome, err
}

// The terminal event SLOT MARKER was deleted mid-disposal: after release,
// the ordinary sweep must still reach a verified disposition from the
// durable plan - the live terminality probe now sees a non-terminal highest
// slot, which is missing evidence, not counterevidence.
func TestPartialDisposalResumesAfterTerminalSlotLoss(t *testing.T) {
	f := newRfx(t)
	id, refs := disposeAndInterrupt(f, "T-R3F", "")
	if err := f.fs.DeleteVersion(f.ctx(), "ns/"+id+"/events/2", versionOfKey(f, refs, "ns/"+id+"/events/2")); err != nil {
		t.Fatal(err)
	}
	h := f.placeHold("carol", f.m1, "hold over an interrupted disposal")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective over the partially disposed record: %s", h.State)
	}
	// Partial-loss reporting and durable plan preservation.
	var found bool
	for _, it := range h.Report.Items {
		if it.TurnID == id && it.PartiallyDisposed && it.MissingVersions >= 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("FINDING 3: the interrupted disposal's partial loss is not reported (missing terminal slot and admission): %+v", h.Report.Items)
	}
	plan, err := f.rs.PlanOf(f.ctx(), f.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != len(refs) {
		t.Fatalf("FINDING 3: the durable plan was destroyed (%d of %d versions inventoried)", len(plan), len(refs))
	}
	outcome, err := resumeAfterRelease(f, h, id)
	if err != nil || outcome != "disposed" {
		t.Fatalf("FINDING 3: the remaining versions can never reach a verified disposition after the terminal slot was deleted mid-disposal (outcome %q err %v): sweep eligibility must retain trustworthy durable proof of previously verified terminality", outcome, err)
	}
	// Actual absence of every unshared surviving version after the completed
	// disposal.
	for _, r := range refs {
		if !f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("FINDING 3: version %s survived the completed disposal", r.Key)
		}
	}
}

// The terminal event's DATA bytes were deleted mid-disposal (the slot marker
// survives): the live terminality probe fails closed (unreadable terminal
// evidence), and the record must still converge from the durable plan.
func TestPartialDisposalResumesAfterTerminalDataLoss(t *testing.T) {
	f := newRfx(t)
	id, refs := disposeAndInterrupt(f, "T-R3G", "")
	if err := f.fs.DeleteVersion(f.ctx(), "ns/"+id+"/data/events/e2", versionOfKey(f, refs, "ns/"+id+"/data/events/e2")); err != nil {
		t.Fatal(err)
	}
	_ = refs
	h := f.placeHold("carol", f.m1, "hold over an interrupted disposal (terminal data)")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	outcome, err := resumeAfterRelease(f, h, id)
	if err != nil || outcome != "disposed" {
		t.Fatalf("FINDING 3: the remaining versions can never reach a verified disposition after the terminal event data was deleted mid-disposal (outcome %q err %v)", outcome, err)
	}
}

// Control (the round-2 S4 shape): only the admission marker was deleted -
// the terminal evidence survives, so both the reviewed head and the
// correction converge. Interruption at the admission-marker position must
// keep working.
func TestPartialDisposalResumesAfterAdmissionOnlyLoss(t *testing.T) {
	f := newRfx(t)
	id, refs := disposeAndInterrupt(f, "T-R3H", "")
	_ = refs
	h := f.placeHold("carol", f.m1, "hold over an interrupted disposal (admission only)")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	outcome, err := resumeAfterRelease(f, h, id)
	if err != nil || outcome != "disposed" {
		t.Fatalf("FINDING 3 (control): the admission-marker interruption lost convergence (outcome %q err %v)", outcome, err)
	}
}

// An in-flight capture (no disposal plan) is never made disposal-eligible
// by the plan-backed terminality rule.
func TestPlanBackedTerminalityNeverSweepsInFlightCapture(t *testing.T) {
	f := newRfx(t)
	id := f.seedTurn("T-R3I", f.p1, f.m1, f.u["alice"])
	f.fb.nonterminal[id] = true
	f.sweepAs("carol")
	if it := f.itemByID(id); it.State != records.ItemActive {
		t.Fatalf("FINDING 3: an in-flight capture became disposal-eligible (%s)", it.State)
	}
	// An unrelated turn is swept (its plan-backed state is irrelevant to
	// the in-flight turn, which has no plan).
	other := f.seedTurn("T-R3J", f.p1, f.m1, f.u["alice"])
	f.sweepAs("carol")
	if it := f.itemByID(id); it.State != records.ItemActive {
		t.Fatalf("FINDING 3: the in-flight capture was swept while an unrelated disposal was pending (%s)", it.State)
	}
	_ = other
}

// ---------------- Finding 4 (HIGH): effective-hold repair silently ignores uncovered records ----------------

// Recovery of an EFFECTIVE hold whose coverage pass leaves records
// UNCOVERED (nil error, non-empty report) must durably and operationally
// record the condition: pending repair state, attributable audit rows, and
// resolution by a successful subsequent recovery - without erasing the
// historical failure evidence.
func TestRecoveryRecordsEffectiveHoldRepairGaps(t *testing.T) {
	f := newRfx(t)
	h := f.placeHold("carol", f.m1, "effective hold with a repair gap")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	// A matching record whose exact-version inventory is unverifiable
	// (enumeration failure: nil-error uncovered in the coverage pass).
	id := f.seedTurn("T-R3K", f.p1, f.m1, f.u["alice"])
	refs := refsOf(f, id)
	f.fb.failEnum[id] = &transportErr{}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	// FINDING 4: the uncovered condition must be durably visible.
	var reportRaw []byte
	if err := f.pool.QueryRow(f.ctx(), `SELECT report FROM holds WHERE id=$1`, h.ID).Scan(&reportRaw); err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(reportRaw, &stored); err != nil {
		t.Fatal(err)
	}
	if _, ok := stored["repair_pending"]; !ok {
		t.Fatalf("FINDING 4: recovery silently discarded the uncovered condition: the durable hold report carries no repair state (%v)", stored)
	}
	if pending, _ := stored["repair_pending"].([]any); len(pending) == 0 {
		t.Fatalf("FINDING 4: the repair-pending state is empty although a matching record is uncovered (%v)", stored)
	}
	// An attributable audit row exists.
	if n, err := countAudit(f, "hold.protection_repair_pending"); err != nil || n == 0 {
		t.Fatalf("FINDING 4: no attributable repair-failure audit row was written (n=%d err=%v)", n, err)
	}
	// The uncovered record is not claimed as natively protected.
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state == "ON" {
			t.Fatalf("FINDING 4: the uncovered record is claimed natively protected (%s is ON)", r.Key)
		}
	}
	// A successful subsequent recovery resolves the outstanding repair
	// state without erasing the historical failure evidence.
	f.fb.failEnum[id] = nil
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
	if pending, _ := stored["repair_pending"].([]any); len(pending) != 0 {
		t.Fatalf("FINDING 4: the resolved repair state was not cleared (%v)", stored)
	}
	for _, r := range refs {
		if state := f.fs.holdState(r.Key, r.Version); state != "ON" {
			t.Fatalf("FINDING 4: the repaired record's version %s is not protected after recovery (state %q)", r.Key, state)
		}
		if err := f.fs.DeleteVersion(f.ctx(), r.Key, r.Version); !errors.Is(err, s3transport.ErrObjectProtected) {
			t.Fatalf("FINDING 4: direct deletion of a repaired-protected version must be refused, got %v", err)
		}
	}
	if n, err := countAudit(f, "hold.protection_repair_pending"); err != nil || n == 0 {
		t.Fatalf("FINDING 4: the historical failure evidence was erased (n=%d err=%v)", n, err)
	}
}

// Repeated failure, recovery and release interleavings: a repair that fails
// again is retried (the condition stays durably visible), and the release
// path still converges.
func TestRecoveryRepairFailureIsDistinguishableAndRetryable(t *testing.T) {
	f := newRfx(t)
	h := f.placeHold("carol", f.m1, "effective hold with repeated repair failures")
	if h.State != records.HoldEffective {
		t.Fatalf("setup: hold not effective: %s", h.State)
	}
	id := f.seedTurn("T-R3L", f.p1, f.m1, f.u["alice"])
	// The enumeration fails persistently for the matching record.
	f.fb.failEnum[id] = &transportErr{}
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	// A second recovery with the fault still armed: the repair stays
	// pending (failures are retried, never downgraded).
	if err := f.svc.Recover(f.ctx()); err != nil {
		t.Fatal(err)
	}
	var reportRaw []byte
	if err := f.pool.QueryRow(f.ctx(), `SELECT report FROM holds WHERE id=$1`, h.ID).Scan(&reportRaw); err != nil {
		t.Fatal(err)
	}
	var stored map[string]any
	if err := json.Unmarshal(reportRaw, &stored); err != nil {
		t.Fatal(err)
	}
	if pending, _ := stored["repair_pending"].([]any); len(pending) == 0 {
		t.Fatalf("FINDING 4: the repeated repair failure is not recorded as pending (%v)", stored)
	}
	// The hold is released: the release converges the outstanding claims.
	f.fb.failEnum[id] = nil
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), h.ID, "release with a prior repair gap"); err != nil {
		t.Fatal(err)
	}
	if stored, err := f.rs.GetHold(f.ctx(), f.principal("carol"), h.ID); err != nil || stored.State != records.HoldReleased {
		t.Fatalf("FINDING 4: the hold must converge to released: %v %+v", err, stored)
	}
}
