package records_test

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
)

// Uses real PostgreSQL and the C07 exact-version fake. Native readback is a
// separate drill; this test exercises classification, not storage guarantees.
func TestExportSnapshotDistinguishesPlanFromVerifiedLoss(t *testing.T) {
	for _, tc := range []struct {
		name, want       string
		deleteAt         int
		dispose, unknown bool
	}{
		{"planned-intact", "complete", -1, false, false},
		{"partial-with-admission", "partial_loss", 1, false, false},
		{"partial-missing-admission", "partial_loss", 0, false, false},
		{"fully-disposed", "disposed", -1, true, false},
		{"presence-unknown", "", -1, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newRfx(t)
			ctx := f.ctx()
			turn := seedTurn4Commit(f, "export-gap", f.p1, f.m1, f.u["alice"], "export-gap-unique")
			for j := range f.fb.turns[f.tenant] {
				f.fb.turns[f.tenant][j].RecordedAt = f.fb.turns[f.tenant][j].RecordedAt.Truncate(time.Millisecond)
			}
			f.svc.Backend = exportSnapshotFake{f.fb}
			refs := refsOf4(f, turn)
			f.sweepAs("carol")
			officer := f.principal("erin")
			if got, err := f.rs.BeginPurge(ctx, officer, turn, nil); err != nil || got != "purging" {
				t.Fatalf("begin purge: %s %v", got, err)
			}
			losses := 0
			if tc.dispose {
				if got, _, err := f.svc.FinishPurge(ctx, &officer, turn); err != nil || got != "disposed" {
					t.Fatalf("dispose: %s %v", got, err)
				}
				losses = len(refs)
			} else {
				interrupt := &planInterruptStorage{RecordsStorage: f.fs}
				f.svc.Storage = interrupt
				if _, _, err := f.svc.FinishPurge(ctx, &officer, turn); !errors.Is(err, errBeforePlanDelete) {
					t.Fatalf("durable plan attempt: %v", err)
				}
				f.svc.Storage = f.fs
				if tc.deleteAt >= 0 {
					r := refs[tc.deleteAt]
					if err := f.fs.DeleteVersion(ctx, r.Key, r.Version); err != nil {
						t.Fatal(err)
					}
					losses = 1
				}
			}
			h := f.placeHold("carol", f.m1, "export after lifecycle attempt", f.u["alice"])
			if h.State != records.HoldEffective {
				t.Fatalf("hold state: %s", h.State)
			}
			if tc.unknown {
				f.svc.Storage = planHeadFailure{RecordsStorage: f.fs}
			}
			r := records.NewExportRequest{RequestID: "scoped-probe", Intent: records.ExportIntent{ProjectID: f.p1, MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: time.Now().UTC().Add(-4 * time.Hour), WindowEnd: time.Now().UTC(), Reason: "synthetic history"}}
			snap, check := f.svc.ExportSnapshotCallbacks(f.tenant, f.u["carol"])
			e, err := f.rs.RequestExport(ctx, f.principal("carol"), r, snap, check)
			if tc.unknown {
				if err == nil || e.ID != "" {
					t.Fatal("unknown presence created an export")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var snapshot records.ExportSnapshot
			if err = json.Unmarshal(e.Snapshot, &snapshot); err != nil {
				t.Fatal(err)
			}
			if len(snapshot.Records) != 1 {
				t.Fatalf("unexpected recorded census %d", len(snapshot.Records))
			}
			got := snapshot.Records[0]
			if got.Classification != tc.want || len(got.Missing) != losses || len(got.Versions) != len(refs)-losses {
				t.Fatalf("classification=%s missing=%d surviving=%d", got.Classification, len(got.Missing), len(got.Versions))
			}
		})
	}
}
