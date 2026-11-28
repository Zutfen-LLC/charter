package records_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
)

// A disposed record's retained_shared survivors must never re-enter content
// authority (C08 correction finding 1): the export snapshot classifies the
// record as a disposed gap, attributes the surviving exact versions as
// retained_shared without declaring them deleted or absent, exports no
// content through the disposed identity, and never requires the retaining
// record's native hold. Uses real PostgreSQL and the C07 exact-version fake;
// native storage readback is the shared-disposition drill's job.
func TestDisposedSharedSurvivorNeverRegainsExportContent(t *testing.T) {
	f := newRfx(t)
	ctx := f.ctx()
	// Terminal records A and B in different projects and matters reference
	// the same exact content-addressed version.
	a := seedTurn4Commit(f, "T-C08S-A", f.p1, f.m1, f.u["alice"], "c08sh")
	b := f.seedTurn3Commit("T-C08S-B", f.p2, f.m2, f.u["bob"], "c08sh")
	for j := range f.fb.turns[f.tenant] {
		f.fb.turns[f.tenant][j].RecordedAt = f.fb.turns[f.tenant][j].RecordedAt.Truncate(time.Millisecond)
	}
	shared := sharedRefOf(f, "c08sh")
	f.svc.Backend = exportSnapshotFake{f.fb}
	f.sweepAs("carol")
	officer := f.principal("erin")
	if got, err := f.rs.BeginPurge(ctx, officer, a, nil); err != nil || got != "purging" {
		t.Fatalf("begin purge: %s %v", got, err)
	}
	if got, _, err := f.svc.FinishPurge(ctx, &officer, a); err != nil || got != "disposed" {
		t.Fatalf("dispose: %s %v", got, err)
	}
	plan, err := f.svc.Store.PlanOf(ctx, f.tenant, a)
	if err != nil {
		t.Fatal(err)
	}
	sharedRows, lost := 0, 0
	for _, row := range plan {
		if row.Key == shared.Key && row.Version == shared.Version {
			if row.Disposition != records.OutcomeRetainedShared {
				t.Fatalf("shared disposition: %+v", row)
			}
			sharedRows++
			continue
		}
		if row.Disposition != records.OutcomeDeleted && row.Disposition != records.OutcomeAbsent {
			t.Fatalf("record-specific disposition: %+v", row)
		}
		lost++
	}
	if sharedRows != 1 || lost == 0 {
		t.Fatalf("plan census: shared=%d lost=%d", sharedRows, lost)
	}
	// The shared version physically survived through B's reference and holds
	// no native protection while B is unheld.
	if err := f.fs.Head(ctx, shared.Key, shared.Version); err != nil {
		t.Fatalf("shared physical presence: %v", err)
	}
	if mode, err := f.fs.LegalHold(ctx, shared.Key, shared.Version); err != nil || mode == "ON" {
		t.Fatalf("shared native hold while peer unheld: %q %v", mode, err)
	}
	// Hold over A's historical scope only; B stays unheld.
	h := f.placeHold("carol", f.m1, "disposed shared attribution", f.u["alice"])
	if h.State != records.HoldEffective {
		t.Fatalf("hold state: %s", h.State)
	}
	intent := records.ExportIntent{ProjectID: f.p1, MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: time.Now().UTC().Add(-4 * time.Hour), WindowEnd: time.Now().UTC(), Reason: "synthetic shared attribution"}
	snap, check := f.svc.ExportSnapshotCallbacks(f.tenant, f.u["carol"])
	requester := f.principal("carol")
	for _, id := range []string{"disposed-shared-unheld", "disposed-shared-held"} {
		e, err := f.rs.RequestExport(ctx, requester, records.NewExportRequest{RequestID: id, Intent: intent}, snap, check)
		if err != nil {
			t.Fatalf("%s: request: %v", id, err)
		}
		var snapshot records.ExportSnapshot
		if err = json.Unmarshal(e.Snapshot, &snapshot); err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Records) != 1 || snapshot.Records[0].TurnID != a {
			t.Fatalf("%s: record census: %+v", id, snapshot.Records)
		}
		got := snapshot.Records[0]
		if got.State != records.ItemDisposed || got.Classification != "disposed" || len(got.Versions) != 0 || len(got.HeldBy) == 0 {
			t.Fatalf("%s: disposed authority: %+v", id, got)
		}
		if len(got.Missing) != lost {
			t.Fatalf("%s: declared loss=%d want=%d", id, len(got.Missing), lost)
		}
		if len(got.RetainedShared) != 1 || got.RetainedShared[0].Key != shared.Key || got.RetainedShared[0].Version != shared.Version || got.RetainedShared[0].Disposition != records.OutcomeRetainedShared || got.RetainedShared[0].PlanEpoch == nil {
			t.Fatalf("%s: shared attribution: %+v", id, got.RetainedShared)
		}
		for _, miss := range got.Missing {
			if miss.Key == shared.Key && miss.Version == shared.Version {
				t.Fatalf("%s: shared survivor declared missing: %+v", id, miss)
			}
		}
		if id == "disposed-shared-unheld" {
			// B acquires a native hold over the shared bytes between the two
			// requests: A's disposed classification must be unchanged and no
			// native protection claim must attach to A through the hold.
			if err := f.fs.SetLegalHold(ctx, shared.Key, shared.Version, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if mode, err := f.fs.LegalHold(ctx, shared.Key, shared.Version); err != nil || mode != "ON" {
		t.Fatalf("peer hold after placement: %q %v", mode, err)
	}
	// B's own export remains functional and carries the shared version as
	// its authorized content, not as a gap attribution.
	f.placeHold("carol", f.m2, "peer scope", f.u["bob"])
	peerSnap, peerCheck := f.svc.ExportSnapshotCallbacks(f.tenant, f.u["carol"])
	peerIntent := records.ExportIntent{ProjectID: f.p2, MatterID: f.m2, CustodianIDs: []string{f.u["bob"]}, WindowStart: time.Now().UTC().Add(-4 * time.Hour), WindowEnd: time.Now().UTC(), Reason: "synthetic peer export"}
	e, err := f.rs.RequestExport(ctx, requester, records.NewExportRequest{RequestID: "peer-shared-content", Intent: peerIntent}, peerSnap, peerCheck)
	if err != nil {
		t.Fatalf("peer request: %v", err)
	}
	var peer records.ExportSnapshot
	if err = json.Unmarshal(e.Snapshot, &peer); err != nil {
		t.Fatal(err)
	}
	if len(peer.Records) != 1 || peer.Records[0].TurnID != b || peer.Records[0].Classification != "complete" || len(peer.Records[0].RetainedShared) != 0 {
		t.Fatalf("peer authority: %+v", peer.Records)
	}
	peerShared := false
	for _, v := range peer.Records[0].Versions {
		if v.Key == shared.Key && v.Version == shared.Version {
			peerShared = true
		}
	}
	if !peerShared {
		t.Fatalf("peer export lost the shared content version: %+v", peer.Records[0].Versions)
	}
}
