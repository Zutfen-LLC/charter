package records_test

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/records"
)

var errBeforePlanDelete = errors.New("test interruption before physical deletion")

type planInterruptStorage struct {
	records.RecordsStorage
	attempts int
}

func (s *planInterruptStorage) DeleteVersion(context.Context, string, string) error {
	s.attempts++
	return errBeforePlanDelete
}

func TestPlannedIntactRecordHasIntactHoldCoverage(t *testing.T) {
	f := newRfx(t)
	ctx := f.ctx()
	turn := seedTurn4Commit(f, "intact-plan", f.p1, f.m1, f.u["alice"], "intact-plan-ref")
	refs := refsOf4(f, turn)
	f.sweepAs("carol")
	officer := f.principal("erin")
	if outcome, err := f.rs.BeginPurge(ctx, officer, turn, nil); err != nil || outcome != "purging" {
		t.Fatalf("begin purge: %q %v", outcome, err)
	}
	storage := &planInterruptStorage{RecordsStorage: f.fs}
	f.svc.Storage = storage
	if _, _, err := f.svc.FinishPurge(ctx, &officer, turn); !errors.Is(err, errBeforePlanDelete) || storage.attempts != 1 {
		t.Fatalf("interruption: attempts=%d error=%v", storage.attempts, err)
	}
	f.svc.Storage = f.fs
	plan, err := f.rs.PlanOf(ctx, f.tenant, turn)
	if err != nil || len(plan) != len(refs) || len(plan) == 0 {
		t.Fatalf("committed plan: %v %v", plan, err)
	}
	for _, ref := range plan {
		if err := f.fs.Head(ctx, ref.Key, ref.Version); err != nil {
			t.Fatalf("pre-hold HEAD %v: %v", ref, err)
		}
	}
	h, err := f.svc.Place(ctx, f.principal("carol"), records.Scope{MatterID: f.m1}, "retain intact plan", "intact-plan")
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range plan {
		state, err := f.fs.LegalHold(ctx, ref.Key, ref.Version)
		if err != nil || state != "ON" {
			t.Fatalf("native protection %v: %q %v", ref, state, err)
		}
	}
	stored, err := f.rs.GetHold(ctx, officer, h.ID)
	if err != nil || !reflect.DeepEqual(h.Report, stored.Report) {
		t.Fatalf("durable report mismatch: %v", err)
	}
	if len(h.Report.PartiallyDisposed) != 0 || len(h.Report.Items) != 1 || h.Report.Items[0].TurnID != turn || h.Report.Items[0].PartiallyDisposed || h.Report.Items[0].MissingVersions != 0 || h.Report.Items[0].Versions != len(plan) {
		t.Fatalf("intact plan reported as loss: returned=%+v durable=%+v", h.Report, stored.Report)
	}
}
