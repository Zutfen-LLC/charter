package records_test

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
)

// A completed purge retry must be harmless to its durable exact-version
// ledger: C08 historical exports still need that ledger to prove loss.
func TestDurableFinishRetriesPreserveHistoricalDisposalPlan(t *testing.T) {
	f := newRfx(t)
	ctx := context.Background()
	turn := f.seedTurn("retry-owner", f.p1, f.m1, f.u["alice"], "retry-shared")
	_ = f.seedTurn("retry-sibling", f.p1, f.m1, f.u["alice"], "retry-shared")
	f.sweepAs("carol")
	officer := f.principal("erin")
	if got, err := f.rs.BeginPurge(ctx, officer, turn, nil); err != nil || got != "purging" {
		t.Fatalf("begin purge: %q %v", got, err)
	}
	if got, _, err := f.svc.FinishPurge(ctx, &officer, turn); err != nil || got != "disposed" {
		t.Fatalf("initial finish: %q %v", got, err)
	}
	var retained int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2 AND disposition='retained_shared'`, f.tenant, turn).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 1 {
		t.Fatalf("initial finish recorded retained_shared rows=%d, want 1", retained)
	}
	var auditDetail []byte
	if err := f.pool.QueryRow(ctx, `SELECT detail FROM audit_log WHERE tenant_id=$1 AND action='purge.finish' ORDER BY id DESC LIMIT 1`, f.tenant).Scan(&auditDetail); err != nil {
		t.Fatal(err)
	}
	var finishAudit struct {
		Versions        map[string]string `json:"versions"`
		PlannedVersions int               `json:"planned_versions"`
	}
	if err := json.Unmarshal(auditDetail, &finishAudit); err != nil {
		t.Fatal(err)
	}
	var planCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2`, f.tenant, turn).Scan(&planCount); err != nil {
		t.Fatal(err)
	}
	if finishAudit.PlannedVersions != planCount || len(finishAudit.Versions) != planCount || finishAudit.Versions == nil {
		t.Fatalf("committed purge audit is not a complete exact-version receipt: audit=%+v plan_rows=%d", finishAudit, planCount)
	}
	if finishAudit.Versions["ns/objects/retry-shared|v-shared-0-retry-shared"] != records.OutcomeRetainedShared {
		t.Fatalf("purge audit omitted actual retained_shared disposition: %+v", finishAudit.Versions)
	}

	for i := range f.fb.turns[f.tenant] {
		item := f.itemByID(f.fb.turns[f.tenant][i].TurnID)
		f.fb.turns[f.tenant][i].RecordedAt = item.RecordedAt.UTC()
	}
	f.svc.Backend = exportSnapshotFake{f.fb}
	hold := f.placeHold("carol", f.m1, "historical retry export", f.u["alice"])
	if hold.State != records.HoldEffective {
		t.Fatalf("hold state %q", hold.State)
	}
	start, end := time.Now().UTC().Add(-4*time.Hour), time.Now().UTC()
	makeExport := func(requestID string) (records.ExportSummary, error) {
		request := records.NewExportRequest{RequestID: requestID, Intent: records.ExportIntent{
			ProjectID: f.p1, MatterID: f.m1, CustodianIDs: []string{f.u["alice"]},
			WindowStart: start, WindowEnd: end, Reason: "synthetic " + requestID,
		}}
		snapshot, check := f.svc.ExportSnapshotCallbacks(f.tenant, f.u["carol"])
		return f.rs.RequestExport(ctx, f.principal("carol"), request, snapshot, check)
	}
	// A fresh C08 historical export must still be constructible after
	// idempotent lifecycle retries. The prior export-snapshot suite proves
	// the same plan is exportable before this retry sequence.
	// Exercise simultaneous authorized retries as well as the ordinary
	// public finish path. Each call is a real lifecycle transaction.
	const retries = 4
	var wg sync.WaitGroup
	errs := make(chan error, retries)
	for i := 0; i < retries; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			actor := f.principal("erin")
			outcome, _, err := f.svc.FinishPurge(ctx, &actor, turn)
			if err != nil {
				errs <- err
				return
			}
			if outcome != "not_purging" {
				errs <- records.ErrConflict
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("authorized concurrent retry: %v", err)
	}

	var remaining int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2`, f.tenant, turn).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining == 0 {
		t.Errorf("idempotent finish retry erased the durable disposal plan")
	}
	after, err := makeExport("retry-history-after")
	if err != nil {
		t.Fatalf("C08 historical export after retries: %v", err)
	}
	var frozen records.ExportSnapshot
	if err := json.Unmarshal(after.Snapshot, &frozen); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, record := range frozen.Records {
		if record.TurnID == turn {
			found = record.Classification == "partial_loss" && len(record.Missing) > 0 && len(record.Versions) == 1
		}
	}
	if !found {
		t.Fatalf("historical C08 snapshot did not retain exact loss plus shared survivor: %+v", frozen.Records)
	}
}
