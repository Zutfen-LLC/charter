package records_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/records"
)

// seedTurn4Commit registers a turn whose ADMISSION commit carries its
// event-zero data (the real retained profile's shape) and whose SUBSEQUENT
// terminal event references the shared content-addressed object: the exact
// interruption shape the round-4 review requires (a shared object referenced
// by a subsequent event, never an admission-only one).
func seedTurn4Commit(f *rfx, label, project, matter, custodian, shared string) string {
	f.t.Helper()
	id := evidence.NewUUID()
	f.labelled[id] = label
	f.byLabel[label] = id
	t := evidence.TurnIdentity{
		TenantID: f.tenant, ProjectID: project, MatterID: matter,
		CustodianID: custodian, TurnID: id, RecordedAt: time.Now().UTC().Add(-2 * time.Hour),
	}
	admission := evidence.VersionRef{Key: "ns/" + id + "/admissions/x", Version: "v-" + id + "-0"}
	ev0 := evidence.VersionRef{Key: "ns/" + id + "/data/events/e0", Version: "v-" + id + "-1"}
	slot1 := evidence.VersionRef{Key: "ns/" + id + "/events/1", Version: "v-" + id + "-2"}
	ev1 := evidence.VersionRef{Key: "ns/" + id + "/data/events/e1", Version: "v-" + id + "-3"}
	own := evidence.VersionRef{Key: "ns/" + id + "/objects/own", Version: "v-" + id + "-4"}
	slot2 := evidence.VersionRef{Key: "ns/" + id + "/events/2", Version: "v-" + id + "-5"}
	ev2 := evidence.VersionRef{Key: "ns/" + id + "/data/events/e2", Version: "v-" + id + "-6"}
	sharedRef := evidence.VersionRef{Key: "ns/objects/" + shared, Version: "v-shared-0-" + shared}
	f.fb.addCommitTurn(t, []fakeCommit{
		{slot: admission, event: &ev0},
		{slot: slot1, event: &ev1, objects: []evidence.VersionRef{own}},
		{slot: slot2, event: &ev2, objects: []evidence.VersionRef{sharedRef}},
	})
	f.turns = append(f.turns, id)
	return id
}

func sharedRefOf(f *rfx, shared string) evidence.VersionRef {
	f.t.Helper()
	return evidence.VersionRef{Key: "ns/objects/" + shared, Version: "v-shared-0-" + shared}
}

// protectVersion sets a native legal hold on the exact version (selective
// native protection: the storage refuses its deletion while other versions
// of the same record stay deletable).
func protectVersion(f *rfx, r evidence.VersionRef, on bool) {
	f.t.Helper()
	if err := f.svc.Storage.SetLegalHold(f.ctx(), r.Key, r.Version, on); err != nil {
		f.t.Fatal(err)
	}
}

func refByKey(f *rfx, refs []evidence.VersionRef, key string) evidence.VersionRef {
	f.t.Helper()
	for _, r := range refs {
		if r.Key == key {
			return r
		}
	}
	f.t.Fatalf("no version for key %s", key)
	return evidence.VersionRef{}
}

func refsOf4(f *rfx, turn string) []evidence.VersionRef {
	f.t.Helper()
	refs, err := f.fb.TurnDisposalRefs(f.ctx(), f.tenant, turn)
	if err != nil {
		f.t.Fatal(err)
	}
	return refs
}

// interruptDisposal runs the AUTHORIZED disposal planning phase and then the
// actual FinishPurge with selective native protection on the admission marker
// and event-zero data: the production deletion loop continues after
// ErrObjectProtected, so the subsequent event markers and data are physically
// deleted, the disposition transaction never commits (ErrBlockedStorage), and
// the record stays purging with a surviving admission and a durable plan that
// still lists every version.
func interruptDisposal(f *rfx, id string) ([]evidence.VersionRef, error) {
	f.t.Helper()
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
	refs := refsOf4(f, id)
	admission := refByKey(f, refs, "ns/"+id+"/admissions/x")
	ev0 := refByKey(f, refs, "ns/"+id+"/data/events/e0")
	protectVersion(f, admission, true)
	protectVersion(f, ev0, true)
	_, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), id)
	return refs, err
}

// Round-4 finding 1 (CRITICAL), forward direction: FinishPurge deletes
// versions from the durable disposal plan, but sharedReferences constructs
// its own-version intersection from the live disposalRefs whenever that
// enumeration SUCCEEDS - and a successful enumeration can be TRUNCATED (the
// deleted suffix shrinks the contiguity horizon). The disposal retry must not
// destroy a surviving record's shared object version.
func TestDisposalRetryPreservesSharedVersionOfDeletedSuffix(t *testing.T) {
	f := newRfx(t)
	// Terminal records A and B share an exact content-addressed object
	// referenced by a SUBSEQUENT event of A (its terminal event) and by B's
	// admission, across two matters.
	a := seedTurn4Commit(f, "T-R4A", f.p1, f.m1, f.u["alice"], "r4fwd")
	b := f.seedTurn3Commit("T-R4B", f.p2, f.m2, f.u["bob"], "r4fwd")
	shared := sharedRefOf(f, "r4fwd")
	bRefs := refsOf4(f, b)
	if !contains4(bRefs, shared) {
		t.Fatalf("setup: B does not reference the shared object")
	}
	// Expire A and complete the authorized disposal planning phase, then
	// execute the actual FinishPurge with the admission marker and
	// event-zero data protected.
	aRefs, err := interruptDisposal(f, a)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	// Interrupted state: the admission marker and event-zero data survive
	// while the subsequent event markers, data events and own object are
	// physically deleted.
	for _, key := range []string{"ns/" + a + "/admissions/x", "ns/" + a + "/data/events/e0"} {
		if r := refByKey(f, aRefs, key); f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("setup: protected version %s was deleted", key)
		}
	}
	for _, key := range []string{"ns/" + a + "/events/1", "ns/" + a + "/events/2", "ns/" + a + "/data/events/e1", "ns/" + a + "/data/events/e2", "ns/" + a + "/objects/own"} {
		if r := refByKey(f, aRefs, key); !f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("setup: version %s was not deleted during the interrupted disposal", key)
		}
	}
	// The shared object survived the first run (the then-complete live
	// enumeration fenced it).
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("setup: the shared object did not survive the interrupted disposal")
	}
	// Remove the temporary protection and retry the ordinary disposal.
	protectVersion(f, refByKey(f, aRefs, "ns/"+a+"/admissions/x"), false)
	protectVersion(f, refByKey(f, aRefs, "ns/"+a+"/data/events/e0"), false)
	outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), a)
	if err != nil || outcome != "disposed" {
		t.Fatalf("disposal retry: outcome %q err %v", outcome, err)
	}
	// The live enumeration now succeeds TRUNCATED while the durable plan
	// still contains the surviving versions: B's shared object must survive.
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("FINDING 1: the disposal retry deleted the shared object version referenced by the surviving record %s: the deleter used the durable plan's version set while shared-reference protection was evaluated against a truncated live enumeration", b)
	}
	// The surviving record's evidence is intact.
	for _, r := range bRefs {
		if f.fs.isDeleted(r.Key, r.Version) {
			t.Fatalf("FINDING 1: the surviving record's version %s was deleted by the partner's disposal", r.Key)
		}
	}
	if it := f.itemByID(a); it.State != records.ItemDisposed {
		t.Fatalf("the disposal did not complete: %s", it.State)
	}
}

// Round-4 finding 1 (CRITICAL), inverse direction: a partially disposed
// sibling with a SURVIVING admission marker whose durable plan contains
// references omitted by its truncated live enumeration. Those durable
// references must fence the disposal of another record referencing the same
// exact version.
func TestPartiallyDisposedSiblingPlanFencesDisposal(t *testing.T) {
	f := newRfx(t)
	// B2 is interrupted mid-disposal (admission protected, subsequent events
	// deleted) with the shared object referenced by its deleted terminal
	// event; A2 (live, different matter) references the same exact version
	// through its admission.
	b2 := seedTurn4Commit(f, "T-R4B2", f.p2, f.m2, f.u["bob"], "r4inv")
	a2 := f.seedTurn3Commit("T-R4A2", f.p1, f.m1, f.u["alice"], "r4inv")
	shared := sharedRefOf(f, "r4inv")
	b2Refs, err := interruptDisposal(f, b2)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("setup: the shared object did not survive the interrupted disposal")
	}
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/admissions/x"), false)
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/data/events/e0"), false)
	// Dispose A2: the partially disposed sibling's durable plan must fence
	// the shared version its truncated live enumeration no longer lists.
	if outcome, err := f.rs.BeginPurge(f.ctx(), f.principal("erin"), a2, nil); err != nil || outcome != "purging" {
		f.t.Fatalf("begin outcome %s err %v", outcome, err)
	}
	outcome, _, err := f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), a2)
	if err != nil || outcome != "disposed" {
		t.Fatalf("sibling disposal: outcome %q err %v", outcome, err)
	}
	if f.fs.isDeleted(shared.Key, shared.Version) {
		t.Fatalf("FINDING 1: the disposal of %s deleted the shared object version that the partially disposed sibling %s still lists in its durable plan: the truncated live enumeration overrode known durable references", a2, b2)
	}
	// The sibling's own disposal converges afterward from its durable plan
	// (the shared version has no remaining live referent, so it is deleted
	// by the sibling's own authorized disposal - correct convergence).
	outcome, _, err = f.svc.FinishPurge(f.ctx(), ptrPrincipal(f.principal("erin")), b2)
	if err != nil || outcome != "disposed" {
		t.Fatalf("sibling convergence: outcome %q err %v", outcome, err)
	}
	if it := f.itemByID(b2); it.State != records.ItemDisposed {
		t.Fatalf("the sibling's disposal did not complete: %s", it.State)
	}
}

// Round-4 finding 1 + finding 2 integration: the same reference resolution
// must govern native legal-hold removal. A hold over a partially disposed
// record covers the remaining in-scope versions its durable plan still lists
// (including the shared version referenced only by the deleted suffix), and
// releasing ANOTHER hold over the live referencing record must not clear the
// shared version's protection while the interrupted record is still held.
func TestReleaseKeepsPlanReferencedSharedVersionProtected(t *testing.T) {
	f := newRfx(t)
	b2 := seedTurn4Commit(f, "T-R4B3", f.p2, f.m2, f.u["bob"], "r4rel")
	a2 := f.seedTurn3Commit("T-R4A3", f.p1, f.m1, f.u["alice"], "r4rel")
	shared := sharedRefOf(f, "r4rel")
	if !contains4(refsOf4(f, a2), shared) {
		t.Fatalf("setup: the live referencing record does not reference the shared object")
	}
	b2Refs, err := interruptDisposal(f, b2)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/admissions/x"), false)
	protectVersion(f, refByKey(f, b2Refs, "ns/"+b2+"/data/events/e0"), false)
	// A hold over the interrupted record's matter: plan-backed coverage must
	// protect ALL remaining in-scope versions, the shared version included.
	hb := f.placeHold("carol", f.m2, "round4 hold over the interrupted record")
	if hb.State != records.HoldEffective {
		t.Fatalf("setup: hold over the interrupted record not effective: %s", hb.State)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("FINDING 2: the interrupted record's remaining shared version is not protected by the hold over it (state %q): plan-backed coverage must protect all remaining in-scope versions", state)
	}
	// A second, overlapping hold over the LIVE referencing record.
	ha := f.placeHold("erin", f.m1, "round4 hold over the live referencing record")
	if ha.State != records.HoldEffective {
		t.Fatalf("setup: hold over the live record not effective: %s", ha.State)
	}
	// Release the live record's hold: the shared version's protection must
	// survive, because the interrupted (still held) record's durable plan
	// still references the exact version.
	if _, err := f.svc.Release(f.ctx(), f.principal("erin"), ha.ID, "release the live reference"); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state != "ON" {
		t.Fatalf("FINDING 1: protection was removed from the shared version while a held record still references it through its durable disposal plan (state %q)", state)
	}
	// Releasing the interrupted record's hold too leaves the shared version
	// owned by nothing (correct convergence: the sibling's own disposal may
	// delete it afterward).
	if _, err := f.svc.Release(f.ctx(), f.principal("carol"), hb.ID, "release the interrupted record"); err != nil {
		t.Fatal(err)
	}
	if state := f.fs.holdState(shared.Key, shared.Version); state == "ON" {
		t.Fatalf("the shared version's protection did not converge after both releases (state %q)", state)
	}
}

func contains4(refs []evidence.VersionRef, r evidence.VersionRef) bool {
	for _, x := range refs {
		if x == r {
			return true
		}
	}
	return false
}
