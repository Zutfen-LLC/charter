package records_test

import (
	"context"
	"errors"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
	"testing"
	"time"
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
	_, err = f.rs.ApproveExport(ctx, f.principal("erin"), f.tenant, req.ID, req.SnapshotDigest, revalidate)
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
	_, token, err = f.rs.BeginExport(ctx, f.principal("carol"), f.tenant, req.ID, time.Minute, revalidate)
	if err != nil {
		t.Fatal(err)
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
	if _, err = f.rs.GetApprovedExport(ctx, f.principal("frank"), f.tenant, req.ID, revalidate); !errors.Is(err, records.ErrForbidden) {
		t.Fatalf("non-approver retrieval=%v", err)
	}
	if err = f.rs.CancelExport(ctx, f.principal("carol"), f.tenant, req.ID); err != nil {
		t.Fatal(err)
	}
	got, err = f.rs.GetApprovedExport(ctx, f.principal("erin"), f.tenant, req.ID, revalidate)
	if err == nil || got != nil {
		t.Fatalf("cancelled package returned bytes=%q err=%v", got, err)
	}
}
