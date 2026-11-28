package records_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/records"
)

type exportSnapshotFake struct{ *fakeBackend }

func (exportSnapshotFake) Info() evidence.BackendInfo {
	return evidence.BackendInfo{Kind: evidence.RetentionProfile}
}

func TestExportSnapshotCallbackLocksAndFreezesC07InventoryAndExactRefs(t *testing.T) {
	f := newRfx(t)
	f.svc.Backend = exportSnapshotFake{f.fb}
	heldTurn := f.seedTurn("snapshot-held", f.p1, f.m1, f.u["alice"])
	unheldTurn := f.seedTurn("snapshot-unheld", f.p1, f.m1, f.u["bob"])
	if err := catalogSnapshotTurns(f); err != nil {
		t.Fatal(err)
	}
	if h := f.placeHold("carol", f.m1, "snapshot coverage", f.u["alice"]); h.State != records.HoldEffective {
		t.Fatalf("hold state %s", h.State)
	}
	actor := f.u["carol"]
	snapshot, revalidate := f.svc.ExportSnapshotCallbacks(f.tenant, actor)
	intent := records.ExportIntent{ProjectID: f.p1, MatterID: f.m1, CustodianIDs: []string{f.u["alice"], f.u["bob"]}, WindowStart: time.Now().UTC().Add(-4 * time.Hour), WindowEnd: time.Now().UTC().Add(time.Hour), Reason: "synthetic snapshot test"}
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var tenantLocked bool
	if err = tx.QueryRow(context.Background(), `SELECT true FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, f.tenant).Scan(&tenantLocked); err != nil || !tenantLocked {
		t.Fatalf("test did not acquire tenant serialization lock: %v", err)
	}
	b, err := snapshot(context.Background(), tx, intent)
	if err != nil {
		t.Fatal(err)
	}
	var got records.ExportSnapshot
	if err = json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 2 {
		t.Fatalf("records=%d: %#v", len(got.Records), got.Records)
	}
	byTurn := map[string]records.ExportSnapshotRecord{}
	for _, r := range got.Records {
		byTurn[r.TurnID] = r
	}
	held, ok := byTurn[heldTurn]
	if !ok || len(held.HeldBy) != 1 || held.HeldBy[0] == "" || len(held.Versions) == 0 {
		t.Fatalf("held snapshot record=%#v", held)
	}
	if _, ok := byTurn[unheldTurn]; !ok {
		t.Fatalf("unheld record omitted: %#v", got.Records)
	}
	if len(byTurn[unheldTurn].Versions) != 0 {
		t.Fatalf("uncovered turn leaked version references: %#v", byTurn[unheldTurn].Versions)
	}
	if len(got.Uncovered) != 1 || got.Uncovered[0] != unheldTurn {
		t.Fatalf("uncovered=%v", got.Uncovered)
	}
	if got.TenantID != f.tenant || got.CustodyActor != actor || got.Epoch <= 0 {
		t.Fatalf("snapshot authority binding=%#v", got)
	}
	if err = revalidate(context.Background(), tx, f.p1, intent, b); err != nil {
		t.Fatalf("unchanged snapshot failed revalidation: %v", err)
	}
}

func catalogSnapshotTurns(f *rfx) error {
	for n, identity := range f.fb.turns[f.tenant] {
		// The retained admission envelope records UTC millisecond precision.
		identity.RecordedAt = identity.RecordedAt.UTC().Truncate(time.Millisecond)
		f.fb.turns[f.tenant][n] = identity
		if err := f.rs.CatalogTurn(f.ctx(), f.tenant, identity, records.SweepPolicy{RetentionSeconds: 90 * 24 * 3600, GraceSeconds: 7 * 24 * 3600}); err != nil {
			return err
		}
	}
	return nil
}

func TestExportSnapshotCallbackRevalidationDetectsHoldEpochChange(t *testing.T) {
	f := newRfx(t)
	f.svc.Backend = exportSnapshotFake{f.fb}
	f.seedTurn("snapshot-revalidate", f.p1, f.m1, f.u["alice"])
	if err := catalogSnapshotTurns(f); err != nil {
		t.Fatal(err)
	}
	f.placeHold("carol", f.m1, "initial snapshot hold", f.u["alice"])
	snapshot, revalidate := f.svc.ExportSnapshotCallbacks(f.tenant, f.u["carol"])
	intent := records.ExportIntent{ProjectID: f.p1, MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: time.Now().UTC().Add(-4 * time.Hour), WindowEnd: time.Now().UTC().Add(time.Hour), Reason: "synthetic revalidation"}
	tx, err := f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b, err := snapshot(context.Background(), tx, intent)
	if err != nil {
		tx.Rollback(context.Background())
		t.Fatal(err)
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	f.placeHold("carol", f.m1, "second snapshot hold", f.u["alice"])
	tx, err = f.pool.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	var tenantLocked bool
	if err = tx.QueryRow(context.Background(), `SELECT true FROM tenants WHERE id=$1 FOR NO KEY UPDATE`, f.tenant).Scan(&tenantLocked); err != nil || !tenantLocked {
		t.Fatalf("test did not acquire tenant serialization lock: %v", err)
	}
	if err = revalidate(context.Background(), tx, f.p1, intent, b); err == nil {
		t.Fatal("expected captured snapshot to become stale after hold epoch change")
	}
}
