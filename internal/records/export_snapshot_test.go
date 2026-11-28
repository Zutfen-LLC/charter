package records

import (
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func TestExportSnapshotSelectionUsesExplicitScopeAndEffectiveMatchedHold(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	inside := start.Add(time.Minute)
	outside := end
	items := []Item{
		{TenantID: "tenant", TurnID: "in", ProjectID: "project", MatterID: "matter", CustodianID: "cust", RecordedAt: inside, State: ItemActive},
		{TenantID: "tenant", TurnID: "boundary", ProjectID: "project", MatterID: "matter", CustodianID: "cust", RecordedAt: outside, State: ItemActive},
		{TenantID: "tenant", TurnID: "foreign", ProjectID: "other", MatterID: "matter", CustodianID: "cust", RecordedAt: inside, State: ItemActive},
	}
	ids := []evidence.TurnIdentity{
		{TenantID: "tenant", TurnID: "in", ProjectID: "project", MatterID: "matter", CustodianID: "cust", RecordedAt: inside},
		{TenantID: "tenant", TurnID: "boundary", ProjectID: "project", MatterID: "matter", CustodianID: "cust", RecordedAt: outside},
		{TenantID: "tenant", TurnID: "foreign", ProjectID: "other", MatterID: "matter", CustodianID: "cust", RecordedAt: inside},
	}
	holds := []*Hold{{ID: "hold", TenantID: "tenant", MatterID: "matter", State: HoldEffective, CustodianIDs: []string{"cust"}, WindowStart: &start, WindowEnd: &end, Epoch: 3}}
	got, err := SelectExportSnapshot(ExportSnapshotRequest{TenantID: "tenant", ProjectID: "project", MatterID: "matter", Custodians: []string{"cust"}, WindowStart: start, WindowEnd: end, CustodyActor: "reviewer", CustodyAt: start, Holds: holds, Items: items, Identities: ids, Epoch: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 || got.Records[0].TurnID != "in" {
		t.Fatalf("records = %#v", got.Records)
	}
	if len(got.Uncovered) != 0 || len(got.HoldIDs) != 1 || got.HoldIDs[0] != "hold" {
		t.Fatalf("coverage/holds = %#v %#v", got.Uncovered, got.HoldIDs)
	}
}

func TestExportSnapshotSelectionRequiresEffectiveMatchedHold(t *testing.T) {
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	item := Item{TenantID: "tenant", TurnID: "t", ProjectID: "p", MatterID: "m", CustodianID: "c", RecordedAt: now, State: ItemActive}
	id := evidence.TurnIdentity{TenantID: "tenant", TurnID: "t", ProjectID: "p", MatterID: "m", CustodianID: "c", RecordedAt: now}
	req := ExportSnapshotRequest{TenantID: "tenant", ProjectID: "p", MatterID: "m", Custodians: []string{"c"}, WindowStart: now.Add(-time.Minute), WindowEnd: now.Add(time.Minute), CustodyActor: "reviewer", CustodyAt: now, Items: []Item{item}, Identities: []evidence.TurnIdentity{id}, Epoch: 4}
	got, err := SelectExportSnapshot(req)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 || len(got.Uncovered) != 1 || got.Uncovered[0] != "t" {
		t.Fatalf("snapshot = %#v", got)
	}
	req.Holds = []*Hold{{ID: "h", TenantID: "tenant", MatterID: "m", State: HoldEffective, Epoch: 3}}
	got, err = SelectExportSnapshot(req)
	if err != nil || len(got.Records[0].HeldBy) != 1 {
		t.Fatalf("effective historical hold should cover its match despite a later matter epoch: %#v, %v", got, err)
	}
	req.Holds[0].State = HoldPending
	got, err = SelectExportSnapshot(req)
	if err != nil || len(got.Records[0].HeldBy) != 0 || len(got.Uncovered) != 1 {
		t.Fatalf("pending protection must not authorize export: %#v, %v", got, err)
	}
}
