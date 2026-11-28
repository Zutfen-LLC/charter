package records_test

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"

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

func TestPlanHoldCoverageClassification(t *testing.T) {
	for _, tc := range []struct {
		name                                                              string
		remove, disposition                                               int
		admission, protectAll, extra, probeError, planError, protectError bool
	}{
		{name: "blocked-delete-all-intact", protectAll: true},
		{name: "surviving-admission", remove: 1},
		{name: "missing-admission", remove: 1, admission: true},
		{name: "previously-dispositioned", remove: 2, disposition: 1},
		{name: "complete-loss", remove: 8, admission: true},
		{name: "presence-unknown", probeError: true},
		{name: "plan-unreadable", planError: true},
		{name: "protection-failure", protectError: true},
		{name: "additional-live-reference", extra: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRfx(t)
			ctx := f.ctx()
			turn := seedTurn4Commit(f, "matrix", f.p1, f.m1, f.u["alice"], "matrix-shared")
			refs := refsOf4(f, turn)
			f.sweepAs("carol")
			officer := f.principal("erin")
			if outcome, err := f.rs.BeginPurge(ctx, officer, turn, nil); err != nil || outcome != "purging" {
				t.Fatalf("begin: %q %v", outcome, err)
			}
			if tc.protectAll {
				for _, r := range refs {
					protectVersion(f, r, true)
				}
				if _, _, err := f.svc.FinishPurge(ctx, &officer, turn); !errors.Is(err, records.ErrBlockedStorage) {
					t.Fatalf("protected delete: %v", err)
				}
				for _, r := range refs {
					protectVersion(f, r, false)
				}
			} else {
				interrupt := &planInterruptStorage{RecordsStorage: f.fs}
				f.svc.Storage = interrupt
				if _, _, err := f.svc.FinishPurge(ctx, &officer, turn); !errors.Is(err, errBeforePlanDelete) {
					t.Fatalf("plan: %v", err)
				}
				f.svc.Storage = f.fs
			}
			if !tc.admission {
				refs[0], refs[1] = refs[1], refs[0]
			}
			for i, r := range refs[:tc.remove] {
				if err := f.fs.DeleteVersion(ctx, r.Key, r.Version); err != nil {
					t.Fatal(err)
				}
				if i < tc.disposition {
					if err := f.rs.MarkPlanAbsent(ctx, f.tenant, turn, records.VersionRef(r)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.extra {
				x := evidence.VersionRef{Key: "ns/" + turn + "/objects/extra", Version: "v-extra"}
				f.fb.mu.Lock()
				f.fb.commits[turn][0].objects = append(f.fb.commits[turn][0].objects, x)
				f.fb.mu.Unlock()
				refs = append(refs, x)
			}
			if tc.probeError {
				f.svc.Storage = planHeadFailure{RecordsStorage: f.fs}
			}
			if tc.planError {
				for _, q := range []string{"ALTER TABLE disposal_plans ALTER COLUMN disposition DROP NOT NULL", "UPDATE disposal_plans SET disposition=NULL"} {
					if _, err := f.pool.Exec(ctx, q); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.protectError {
				f.svc.Hooks.StorageFault = func(string) error { return errors.New("test readback outage") }
			}
			scope := records.Scope{MatterID: f.m1}
			h, err := f.svc.Place(ctx, f.principal("carol"), scope, "classification matrix", tc.name)
			if tc.probeError || tc.planError || tc.protectError {
				if h != nil || !errors.Is(err, records.ErrRetry) {
					t.Fatalf("must fail closed: %v %v", h, err)
				}
				hs, err := f.rs.HoldsInState(ctx, records.HoldFailed)
				if err != nil || len(hs) != 1 || len(hs[0].Report.Items) != 0 || len(hs[0].Report.DisposedBeforeHold) != 0 || len(hs[0].Report.PartiallyDisposed) != 0 {
					t.Fatalf("failed report: %+v %v", hs, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			check := func(r records.Report) {
				t.Helper()
				survivors := len(refs) - tc.remove
				if survivors == 0 {
					if !slices.Equal(r.DisposedBeforeHold, []string{turn}) || len(r.Items) != 0 || len(r.PartiallyDisposed) != 0 {
						t.Fatalf("complete loss: %+v", r)
					}
				} else {
					partial := tc.remove > 0
					if len(r.Items) != 1 || r.Items[0].Versions != survivors || r.Items[0].MissingVersions != tc.remove || r.Items[0].PartiallyDisposed != partial || slices.Contains(r.PartiallyDisposed, turn) != partial || len(r.DisposedBeforeHold) != 0 {
						t.Fatalf("classification: %+v", r)
					}
				}
			}
			check(h.Report)
			for i, r := range refs {
				err := f.fs.Head(ctx, r.Key, r.Version)
				if i < tc.remove {
					if !errors.Is(err, s3transport.ErrObjectAbsent) {
						t.Fatalf("absence %v: %v", r, err)
					}
					continue
				}
				state, holdErr := f.fs.LegalHold(ctx, r.Key, r.Version)
				if err != nil || holdErr != nil || state != "ON" {
					t.Fatalf("surviving exact version %v: HEAD=%v hold=%q %v", r, err, state, holdErr)
				}
			}
			if tc.protectAll {
				scope.CustodianIDs = []string{f.u["alice"]}
				next, err := f.rs.ChangeScope(ctx, officer, h.ID, scope, "scope supersession")
				if err != nil {
					t.Fatal(err)
				}
				report, err := f.svc.Reestablish(ctx, next)
				if err != nil {
					t.Fatal(err)
				}
				check(report)
			}
			for range 2 {
				if err := f.svc.Recover(ctx); err != nil {
					t.Fatal(err)
				}
				got, err := f.rs.GetHold(ctx, officer, h.ID)
				if err != nil {
					t.Fatal(err)
				}
				check(got.Report)
			}
			if tc.protectAll {
				if _, err := f.svc.Release(ctx, officer, h.ID, "released for normal disposal"); err != nil {
					t.Fatal(err)
				}
				f.sweepAs("carol")
				if outcome, err := f.rs.BeginPurge(ctx, officer, turn, nil); err != nil || outcome != "purging" {
					t.Fatalf("begin after release: %q %v", outcome, err)
				}
				if outcome, _, err := f.svc.FinishPurge(ctx, &officer, turn); err != nil || outcome != "disposed" {
					t.Fatalf("finish after release: %q %v", outcome, err)
				}
				for _, r := range refs {
					if err := f.fs.Head(ctx, r.Key, r.Version); !errors.Is(err, s3transport.ErrObjectAbsent) {
						t.Fatalf("post-release physical absence %v: %v", r, err)
					}
				}
			}
		})
	}
}

type planHeadFailure struct{ records.RecordsStorage }

func (s planHeadFailure) Head(context.Context, string, string) error {
	return errors.New("test presence probe outage")
}
