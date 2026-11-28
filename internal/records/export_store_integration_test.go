package records_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

func TestScopedExportTransactionalAuthorizationAndPublication(t *testing.T) {
	f := newRfx(t)
	ctx := context.Background()
	if err := f.st.SeedRole(ctx, f.tenant, f.u["erin"], store.RoleExportReviewer); err != nil {
		t.Fatal(err)
	}
	if err := f.st.SeedRole(ctx, f.tenant, f.u["frank"], store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	intent := records.ExportIntent{ProjectID: f.p1, MatterID: f.m1, CustodianIDs: []string{f.u["alice"]}, WindowStart: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), WindowEnd: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), Reason: "review"}
	snapCalls := 0
	snapshot := func(_ context.Context, tx pgx.Tx, _ records.ExportIntent) ([]byte, error) {
		snapCalls++
		var one int
		if err := tx.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil {
			return nil, err
		}
		return []byte(`{"snapshot":1}`), nil
	}
	revalidate := func(_ context.Context, tx pgx.Tx, project string, _ records.ExportIntent, snap []byte) error {
		var locked bool
		if err := tx.QueryRow(ctx, `SELECT true FROM tenants WHERE id=$1`, f.tenant).Scan(&locked); err != nil {
			return err
		}
		if project == "" || string(snap) != `{"snapshot":1}` {
			return errors.New("scope/snapshot changed")
		}
		return nil
	}
	req, err := f.rs.RequestExport(ctx, f.principal("carol"), records.NewExportRequest{RequestID: "matter-export-7", Intent: intent}, snapshot, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if req.State != records.ExportRequested || snapCalls != 1 || req.RequesterRole != "records_officer" {
		t.Fatalf("request=%+v snapshot_calls=%d", req, snapCalls)
	}
	_, err = f.rs.RequestExport(ctx, f.principal("carol"), records.NewExportRequest{RequestID: "matter-export-7", Intent: intent}, snapshot, revalidate)
	if err != nil {
		t.Fatalf("identical retry: %v", err)
	}
	if snapCalls != 1 {
		t.Fatalf("snapshot callback reran on retry: %d", snapCalls)
	}
	changed := intent
	changed.Reason = "changed"
	if _, err = f.rs.RequestExport(ctx, f.principal("carol"), records.NewExportRequest{RequestID: "matter-export-7", Intent: changed}, snapshot, revalidate); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("changed intent error=%v", err)
	}
	if _, err = f.rs.ApproveExport(ctx, f.principal("erin"), f.tenant, req.ID, req.SnapshotDigest, revalidate); err != nil {
		t.Fatalf("independent approval: %v", err)
	}
	if _, err = f.rs.ApproveExport(ctx, f.principal("erin"), f.tenant, req.ID, req.SnapshotDigest, revalidate); err != nil {
		t.Fatalf("same approver replay: %v", err)
	}
	var approvals int
	if err = f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='export.approve'`).Scan(&approvals); err != nil {
		t.Fatal(err)
	}
	if approvals != 1 {
		t.Fatalf("approval audit rows=%d", approvals)
	}
	beforeApproval, err := f.rs.RequestExport(ctx, f.principal("carol"), records.NewExportRequest{RequestID: "cancel-before-approval", Intent: intent}, snapshot, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.rs.CancelExport(ctx, f.principal("carol"), f.tenant, beforeApproval.ID); err != nil {
		t.Fatalf("pending cancellation: %v", err)
	}
	if _, _, err = f.rs.BeginExport(ctx, f.principal("frank"), f.tenant, req.ID, time.Minute, revalidate); !errors.Is(err, records.ErrForbidden) {
		t.Fatalf("unbound officer began generation: %v", err)
	}
	_, rejectedAttempt, err := f.rs.BeginExport(ctx, f.principal("carol"), f.tenant, req.ID, time.Minute, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.rs.RecordExportAttemptFailure(ctx, f.principal("carol"), req.ID, rejectedAttempt, "readback"); err != nil {
		t.Fatalf("retriable generation failure was not persisted: %v", err)
	}
	_, token, err := f.rs.BeginExport(ctx, f.principal("carol"), f.tenant, req.ID, time.Minute, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if token == rejectedAttempt {
		t.Fatal("retry reused previous generation attempt identity")
	}
	if err = f.rs.RecordExportAttemptFailure(ctx, f.principal("carol"), req.ID, rejectedAttempt, "verification"); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("stale attempt rewrote newer generation: %v", err)
	}
	if _, err = f.pool.Exec(ctx, `DELETE FROM tenant_roles WHERE tenant_id=$1 AND user_id=$2 AND role='records_officer'`, f.tenant, f.u["carol"]); err != nil {
		t.Fatal(err)
	}
	manifestDigest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	payload := []byte("verified package")
	verify := func(got []byte, snapshotDigest, manifest string) error {
		if string(got) != string(payload) || snapshotDigest != req.SnapshotDigest || manifest != manifestDigest {
			return errors.New("verification mismatch")
		}
		return nil
	}
	if _, err = f.rs.PublishExport(ctx, f.principal("carol"), f.tenant, req.ID, token, req.SnapshotDigest, manifestDigest, payload, verify, revalidate); !errors.Is(err, records.ErrForbidden) {
		t.Fatalf("revoked requester published: %v", err)
	}
	if err = f.st.SeedRole(ctx, f.tenant, f.u["carol"], store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	if _, err = f.rs.PublishExport(ctx, f.principal("carol"), f.tenant, req.ID, token, req.SnapshotDigest, manifestDigest, payload, verify, revalidate); !errors.Is(err, records.ErrForbidden) {
		t.Fatalf("regrant resurrected stale authority: %v", err)
	}
	req, err = f.rs.RequestExport(ctx, f.principal("carol"), records.NewExportRequest{RequestID: "fresh-after-regrant", Intent: intent}, snapshot, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.rs.ApproveExport(ctx, f.principal("erin"), f.tenant, req.ID, req.SnapshotDigest, revalidate); err != nil {
		t.Fatal(err)
	}
	// Unrelated audit records, even with a colliding export_id in a different
	// tenant, must not enter the immutable request/approval projection.
	if _, err = f.pool.Exec(ctx, `INSERT INTO audit_log(tenant_id,action,detail) VALUES(gen_random_uuid(),'export.request',jsonb_build_object('export_id',$2::text,'debug','unrelated synthetic details')),($1,'export.retrieve',jsonb_build_object('export_id',$2::text,'debug','unrelated synthetic delivery'))`, f.tenant, req.ID); err != nil {
		t.Fatal(err)
	}
	started, token, err := f.rs.BeginExport(ctx, f.principal("carol"), f.tenant, req.ID, time.Minute, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if a := started.CustodyAudit; len(a) != 2 || a[0].Action != "export.request" || a[1].Action != "export.approve" || a[0].ActorID != req.RequesterID || a[1].ActorID != f.u["erin"] || a[0].SnapshotDigest != req.SnapshotDigest || a[1].IntentDigest != req.RequestDigest {
		t.Fatal("generation did not receive exactly its authoritative custody audit projection")
	}
	if _, err = f.pool.Exec(ctx, `CREATE FUNCTION fail_export_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='export.ready' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_export_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_export_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.rs.PublishExport(ctx, f.principal("carol"), f.tenant, req.ID, token, req.SnapshotDigest, manifestDigest, payload, verify, revalidate); err == nil {
		t.Fatal("audit failure must abort package publication")
	}
	if _, err = f.pool.Exec(ctx, `DROP TRIGGER fail_export_audit ON audit_log; DROP FUNCTION fail_export_audit()`); err != nil {
		t.Fatal(err)
	}
	var state string
	var packageNull bool
	if err = f.pool.QueryRow(ctx, `SELECT state,package_bytes IS NULL FROM scoped_exports WHERE tenant_id=$1 AND id=$2`, f.tenant, req.ID).Scan(&state, &packageNull); err != nil {
		t.Fatal(err)
	}
	if state != records.ExportGenerating || !packageNull {
		t.Fatalf("after failed audit state=%s package_null=%v", state, packageNull)
	}
	ready, err := f.rs.PublishExport(ctx, f.principal("carol"), f.tenant, req.ID, token, req.SnapshotDigest, manifestDigest, payload, verify, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if ready.ManifestDigest != manifestDigest || ready.State != records.ExportReady {
		t.Fatalf("ready=%+v", ready)
	}
	got, err := f.rs.GetApprovedExport(ctx, f.principal("erin"), f.tenant, req.ID, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("retrieved=%q", got)
	}
	if got, err = f.rs.GetApprovedExport(ctx, f.principal("frank"), f.tenant, req.ID, revalidate); !errors.Is(err, records.ErrForbidden) || len(got) != 0 {
		t.Fatalf("non-approver retrieval disclosed %d bytes, err=%v", len(got), err)
	}
	if _, err = f.pool.Exec(ctx, `CREATE FUNCTION fail_retrieval_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='export.retrieve' THEN RAISE EXCEPTION 'synthetic delivery audit unavailable'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_retrieval_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_retrieval_audit()`); err != nil {
		t.Fatal(err)
	}
	reviewer := f.principal("erin")
	if got, err = f.rs.GetApprovedExport(ctx, reviewer, f.tenant, req.ID, revalidate); err == nil || len(got) != 0 {
		t.Fatalf("unaudited delivery disclosed %d bytes, err=%v", len(got), err)
	}
	if _, err = f.pool.Exec(ctx, `DROP TRIGGER fail_retrieval_audit ON audit_log; DROP FUNCTION fail_retrieval_audit()`); err != nil {
		t.Fatal(err)
	}
	if _, err = f.pool.Exec(ctx, `DELETE FROM tenant_roles WHERE tenant_id=$1 AND user_id=$2 AND role='export_reviewer'`, f.tenant, reviewer.UserID); err != nil {
		t.Fatal(err)
	}
	if got, err = f.rs.GetApprovedExport(ctx, reviewer, f.tenant, req.ID, revalidate); !errors.Is(err, records.ErrForbidden) || len(got) != 0 {
		t.Fatalf("revoked reviewer received %d bytes, err=%v", len(got), err)
	}
	if err = f.st.SeedRole(ctx, f.tenant, reviewer.UserID, store.RoleExportReviewer); err != nil {
		t.Fatal(err)
	}
	if got, err = f.rs.GetApprovedExport(ctx, reviewer, f.tenant, req.ID, revalidate); !errors.Is(err, records.ErrForbidden) || len(got) != 0 {
		t.Fatalf("reviewer regrant resurrected delivery, bytes=%d err=%v", len(got), err)
	}
	if err = f.rs.CancelExport(ctx, f.principal("carol"), f.tenant, req.ID); err != nil {
		t.Fatal(err)
	}
	got, err = f.rs.GetApprovedExport(ctx, f.principal("erin"), f.tenant, req.ID, revalidate)
	if err == nil || got != nil {
		t.Fatalf("cancelled package returned bytes=%q err=%v", got, err)
	}
	for _, name := range []string{"carol", "frank"} {
		if err := f.st.SeedRole(ctx, f.tenant, f.u[name], store.RoleExportReviewer); err != nil {
			t.Fatal(err)
		}
	}
	competing, err := f.rs.RequestExport(ctx, f.principal("carol"), records.NewExportRequest{RequestID: "competing-reviewers", Intent: intent}, snapshot, revalidate)
	if err != nil {
		t.Fatal(err)
	}
	requester := f.principal("carol")
	requester.UserID = strings.ToUpper(requester.UserID)
	if _, err := f.rs.ApproveExport(ctx, requester, f.tenant, competing.ID, competing.SnapshotDigest, revalidate); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("canonicalized requester was not refused own approval: %v", err)
	}
	gate := make(chan struct{})
	done := make(chan error, 2)
	for _, p := range []store.Principal{reviewer, f.principal("frank")} {
		go func() {
			<-gate
			_, err := f.rs.ApproveExport(ctx, p, f.tenant, competing.ID, competing.SnapshotDigest, revalidate)
			done <- err
		}()
	}
	close(gate)
	a, b := <-done, <-done
	if !((a == nil && errors.Is(b, records.ErrExportConflict)) || (b == nil && errors.Is(a, records.ErrExportConflict))) {
		t.Fatalf("competing approvals did not serialize: %v; %v", a, b)
	}
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='export.approve' AND detail->>'export_id'=$1`, competing.ID).Scan(&approvals); err != nil || approvals != 1 {
		t.Fatalf("competing approval audit count=%d err=%v", approvals, err)
	}
}
