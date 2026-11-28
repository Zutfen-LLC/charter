//go:build retention_drill

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/server"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestC08NativeRecoveryMatrixDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	c := config.Load()
	if err := validateLabConfig(c.Addr, c.RetentionS3); err != nil {
		t.Fatal(err)
	}
	if err := validateSyntheticDatabases(c); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("CHARTER_DRILL_OWNER_DSN")
	if _, err := labDSN(dsn); err != nil {
		t.Fatal(err)
	}
	owner, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	root := os.Getenv("CHARTER_DRILL_OUTPUT")
	if root == "" {
		t.Fatal("CHARTER_DRILL_OUTPUT not set")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	runC08NativeRecoveryMatrix(t, ctx, c, owner, root)
}

// Exercise physical loss, rather than treating a plan as loss. A short-lived
// signed namespace uses the same native stack as C07; ordinary qualified
// runtime writes still use their unchanged one-day minimum.
func runC08NativeRecoveryMatrix(t *testing.T, ctx context.Context, c config.Config, owner *pgxpool.Pool, root string) {
	t.Helper()
	must := func(err error) {
		if err != nil {
			_, file, line, _ := runtime.Caller(1)
			t.Fatalf("%s:%d: %v", filepath.Base(file), line, err)
		}
	}
	sc := c.RetentionS3
	secret, err := sizedRead(sc.RecordsSecretFile, 1024, true)
	must(err)
	native, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(secret))})
	must(err)
	seedFile, err := sizedRead(sc.SignerSeedFile, 128, true)
	must(err)
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedFile)))
	must(err)
	evPool, err := pgxpool.New(ctx, c.EvidenceDatabaseURL)
	must(err)
	defer evPool.Close()
	fence, err := (evidence.PG{DB: evPool}).AcquireFence(ctx)
	must(err)
	defer fence.Release()
	started := time.Now()
	b, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: native, Deployment: sc.Deployment + "-c08-history", Bucket: sc.Bucket, TrustedCommitKey: mustHex(t, sc.CommitKey), Signer: ed25519.NewKeyFromSeed(seed), MinimumRetention: started.Add(5 * time.Second), RetainFor: time.Minute, Fence: fence})
	must(err)
	ws, err := pgxpool.New(ctx, c.DatabaseURL)
	must(err)
	defer ws.Close()
	auth := store.Store{DB: owner}
	tenant, err := auth.CreateTenant(ctx, "urn:charter:synthetic:c08-history", "seed", "synthetic C08 historical loss")
	must(err)
	mkUser := func(subject, role string) store.Principal {
		id, err := auth.CreateUser(ctx, tenant, subject, "synthetic "+subject)
		must(err)
		if role != "" {
			must(auth.SeedRole(ctx, tenant, id, role))
		}
		return store.Principal{TenantID: tenant, UserID: id}
	}
	requester := mkUser("requester", store.RoleRecordsOfficer)
	disposer := mkUser("disposer", store.RoleRecordsOfficer)
	reviewer := mkUser("reviewer", store.RoleExportReviewer)
	custodian := mkUser("custodian", "")
	project, err := auth.CreateProject(ctx, tenant, "synthetic historical scope")
	must(err)
	var matter string
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, project).Scan(&matter))
	_, err = owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id,retention_seconds,grace_seconds,set_by) VALUES($1,1,0,$2)`, tenant, requester.UserID)
	must(err)
	rs := &records.Service{Store: &records.Store{DB: ws}, Backend: b, Storage: native, Retained: true}
	recorder := &evidence.Recorder{Backend: b, Fence: fence, Lifecycle: rs, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "c08-history", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "history", ModelID: "det-a"}}, nil
	}}
	labels := []string{"full", "partial-admission", "partial-no-admission"}
	turns := map[string]string{}
	refs := map[string][]evidence.VersionRef{}
	events := map[string][]evidence.Event{}
	maxUntil := time.Time{}
	for _, label := range labels {
		result, err := recorder.Process(ctx, evidence.Request{TenantID: tenant, ProjectID: project, MatterID: matter, CustodianID: custodian.UserID, IdempotencyKey: "c08-history-" + label, Input: []byte("synthetic original " + label)}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("synthetic result " + label)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		turns[label] = result.TurnID
		r, err := b.TurnDisposalRefs(ctx, tenant, result.TurnID)
		must(err)
		refs[label] = r
		events[label], err = b.Load(ctx, tenant, result.TurnID)
		must(err)
		for _, v := range r {
			got, err := native.Read(ctx, v.Key, v.Version)
			must(err)
			if got.Until.After(maxUntil) {
				maxUntil = got.Until
			}
		}
	}
	timer := time.NewTimer(time.Until(maxUntil.Add(time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = rs.Sweep(ctx, requester)
	must(err)
	for _, label := range labels {
		id := turns[label]
		if state, err := rs.Store.BeginPurge(ctx, disposer, id, nil); err != nil || state != "purging" {
			t.Fatalf("%s: begin real C07 purge %q: %v", label, state, err)
		}
		if label != "full" {
			evs := events[label]
			keep := 0
			if label == "partial-no-admission" {
				keep = len(evs) - 1
			}
			hash := evs[keep]["event_hash"].(string)
			for _, r := range refs[label] {
				if strings.HasSuffix(r.Key, "/data/events/"+id+"/"+hash) || (keep == 0 && strings.Contains(r.Key, "/admissions/")) || (keep != 0 && strings.HasSuffix(r.Key, "/events/"+id+"/"+strconv.Itoa(keep))) {
					must(native.SetLegalHold(ctx, r.Key, r.Version, true))
				}
			}
		}
		outcome, _, err := rs.FinishPurge(ctx, &disposer, id)
		if label == "full" {
			if err != nil || outcome != "disposed" {
				t.Fatalf("real full disposition: %s %v", outcome, err)
			}
			// Repeat the authenticated lifecycle finish concurrently after
			// terminal disposal. The HTTP purge-finish handler delegates to
			// this same service method with its authenticated records officer.
			const retries = 4
			var retryWG sync.WaitGroup
			retryErrs := make(chan error, retries)
			for n := 0; n < retries; n++ {
				retryWG.Add(1)
				go func() {
					defer retryWG.Done()
					actor := disposer
					got, _, retryErr := rs.FinishPurge(ctx, &actor, id)
					if retryErr != nil {
						retryErrs <- retryErr
					} else if got != "not_purging" {
						retryErrs <- fmt.Errorf("retry outcome %q", got)
					}
				}()
			}
			retryWG.Wait()
			close(retryErrs)
			for retryErr := range retryErrs {
				t.Errorf("concurrent native finish retry: %v", retryErr)
			}
			var planRows int
			must(ws.QueryRow(ctx, `SELECT count(*) FROM disposal_plans WHERE tenant_id=$1 AND turn_id=$2`, tenant, id).Scan(&planRows))
			if planRows == 0 {
				t.Fatal("native idempotent retry erased completed plan required by historical export")
			}
		} else if !errors.Is(err, records.ErrBlockedStorage) {
			t.Fatalf("expected selective native interruption %s: %s %v", label, outcome, err)
		}
	}
	hold, err := rs.Place(ctx, requester, records.Scope{MatterID: matter, CustodianIDs: []string{custodian.UserID}}, "synthetic loss preservation", "c08-history-hold")
	must(err)
	if hold.State != records.HoldEffective {
		t.Fatal("C07 native hold over remaining exact versions was not effective")
	}
	export := &server.RetainedExports{Records: rs, Backend: b}
	intent := records.ExportIntent{ProjectID: project, MatterID: matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "synthetic recovery matrix"}
	newApproved := func(label string) records.ExportSummary {
		t.Helper()
		r, err := export.Request(ctx, requester, records.NewExportRequest{RequestID: "recovery-" + label, Intent: intent})
		must(err)
		approved, err := export.Approve(ctx, reviewer, r.ID, r.SnapshotDigest)
		must(err)
		return approved
	}
	checkNoPackage := func(id string) {
		t.Helper()
		var null bool
		must(ws.QueryRow(ctx, `SELECT package_bytes IS NULL FROM scoped_exports WHERE tenant_id=$1 AND id=$2`, tenant, id).Scan(&null))
		if !null {
			t.Fatalf("%s: unauthorized package bytes persisted", id)
		}
	}
	// REC-01: durable request snapshot survives a caller/process boundary.
	r1, err := export.Request(ctx, requester, records.NewExportRequest{RequestID: "recovery-request", Intent: intent})
	must(err)
	r1Replay, err := export.Request(ctx, requester, records.NewExportRequest{RequestID: "recovery-request", Intent: intent})
	must(err)
	if r1.ID != r1Replay.ID || r1.SnapshotDigest != r1Replay.SnapshotDigest {
		t.Fatal("REC-01 durable request replay changed")
	}
	changed := intent
	changed.Reason = "different synthetic intent"
	if _, err = export.Request(ctx, requester, records.NewExportRequest{RequestID: "recovery-request", Intent: changed}); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("REC-01 changed idempotency intent: %v", err)
	}
	checkNoPackage(r1.ID)
	// REC-02 approval durability and same-approver idempotency/audit cardinality.
	a2 := newApproved("approval")
	_, err = export.Approve(ctx, reviewer, a2.ID, a2.SnapshotDigest)
	must(err)
	var auditN int
	must(ws.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='export.approve' AND detail->>'export_id'=$1`, a2.ID).Scan(&auditN))
	if auditN != 1 {
		t.Fatalf("REC-02 approval audit rows=%d", auditN)
	}
	// REC-03 a committed lease cannot be duplicated; expiry/reconciliation is
	// independently covered by the history drill's abandoned marker assertions.
	a3 := newApproved("lease")
	_, check := rs.ExportSnapshotCallbacks(tenant, requester.UserID)
	_, _, err = rs.Store.BeginExport(ctx, requester, tenant, a3.ID, 300*time.Millisecond, check)
	must(err)
	if _, _, err = rs.Store.BeginExport(ctx, requester, tenant, a3.ID, time.Second, check); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("REC-03 double lease: %v", err)
	}
	checkNoPackage(a3.ID)
	// REC-04 retry after a durable readback-stage failure, using the real store
	// transition (native readback failure is separately covered by retained-history drill).
	a4 := newApproved("readback")
	_, token4, err := rs.Store.BeginExport(ctx, requester, tenant, a4.ID, time.Minute, check)
	must(err)
	must(rs.Store.RecordExportAttemptFailure(ctx, requester, a4.ID, token4, "readback"))
	var state4 string
	var persistedToken pgtype.Text
	must(ws.QueryRow(ctx, `SELECT state,attempt_token::text FROM scoped_exports WHERE tenant_id=$1 AND id=$2`, tenant, a4.ID).Scan(&state4, &persistedToken))
	if state4 != records.ExportGenerating || !persistedToken.Valid || persistedToken.String != token4 {
		t.Errorf("REC-04 required generating state with attempt token; got state=%q token_valid=%v", state4, persistedToken.Valid)
	}
	if _, err = export.Generate(ctx, requester, a4.ID); err != nil {
		t.Errorf("REC-04 retry after persisted readback failure: %v", err)
	}
	// REC-05 staged-but-unverified package failure leaves no publication. A
	// rejected verifier represents the verification boundary transactionally.
	a5 := newApproved("verify")
	_, token5, err := rs.Store.BeginExport(ctx, requester, tenant, a5.ID, time.Minute, check)
	must(err)
	badVerify := func([]byte, string, string) error { return errors.New("synthetic verification interruption") }
	if _, err = rs.Store.PublishExport(ctx, requester, tenant, a5.ID, token5, a5.SnapshotDigest, strings.Repeat("a", 64), []byte("synthetic staged bytes"), badVerify, check); err == nil {
		t.Fatal("REC-05 verifier failure published")
	}
	must(rs.Store.RecordExportAttemptFailure(ctx, requester, a5.ID, token5, "publish"))
	checkNoPackage(a5.ID)
	if _, err = export.Generate(ctx, requester, a5.ID); err != nil {
		t.Fatalf("REC-05 retry: %v", err)
	}
	// REC-06 revalidation refusal after successful verifier must not publish.
	a6 := newApproved("revalidate")
	_, token6, err := rs.Store.BeginExport(ctx, requester, tenant, a6.ID, time.Minute, check)
	must(err)
	okVerify := func([]byte, string, string) error { return nil }
	refuse := func(context.Context, pgx.Tx, string, records.ExportIntent, []byte) error {
		return errors.New("synthetic revalidation refusal")
	}
	if _, err = rs.Store.PublishExport(ctx, requester, tenant, a6.ID, token6, a6.SnapshotDigest, strings.Repeat("b", 64), []byte("synthetic staged bytes"), okVerify, refuse); err == nil {
		t.Fatal("REC-06 revalidation refusal published")
	}
	checkNoPackage(a6.ID)
	// REC-07 audit insert fault rolls back publication then retry succeeds.
	a7 := newApproved("audit-rollback")
	_, err = owner.Exec(ctx, `CREATE FUNCTION fail_recovery_export_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='export.ready' THEN RAISE EXCEPTION 'synthetic audit interruption'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_recovery_export_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_recovery_export_audit()`)
	must(err)
	if _, err = export.Generate(ctx, requester, a7.ID); err == nil {
		t.Fatal("REC-07 audit fault did not abort generation")
	}
	_, err = owner.Exec(ctx, `DROP TRIGGER fail_recovery_export_audit ON audit_log; DROP FUNCTION fail_recovery_export_audit()`)
	must(err)
	checkNoPackage(a7.ID)
	if _, err = export.Generate(ctx, requester, a7.ID); err != nil {
		t.Fatalf("REC-07 retry: %v", err)
	}
	// REC-08 response-loss simulation: publish and retrieve afresh twice.
	a8 := newApproved("response-lost")
	if _, err = export.Generate(ctx, requester, a8.ID); err != nil {
		t.Fatalf("REC-08 generate: %v", err)
	}
	d1, err := export.Retrieve(ctx, reviewer, a8.ID)
	must(err)
	d2, err := export.Retrieve(ctx, reviewer, a8.ID)
	must(err)
	if len(d1.DirectoryJSON) == 0 || string(d1.DirectoryJSON) != string(d2.DirectoryJSON) {
		t.Fatal("REC-08 repeated retrieval changed or omitted bytes")
	}
	// REC-09 retrieval audit failure refuses with no package bytes.
	a9 := newApproved("retrieve-audit")
	if _, err = export.Generate(ctx, requester, a9.ID); err != nil {
		t.Fatalf("REC-09 generate: %v", err)
	}
	_, err = owner.Exec(ctx, `CREATE FUNCTION fail_recovery_retrieve_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='export.retrieve' THEN RAISE EXCEPTION 'synthetic retrieve interruption'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_recovery_retrieve_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_recovery_retrieve_audit()`)
	must(err)
	if d, err := export.Retrieve(ctx, reviewer, a9.ID); err == nil || len(d.DirectoryJSON) != 0 {
		t.Fatalf("REC-09 leaked %d bytes: %v", len(d.DirectoryJSON), err)
	}
	_, err = owner.Exec(ctx, `DROP TRIGGER fail_recovery_retrieve_audit ON audit_log; DROP FUNCTION fail_recovery_retrieve_audit()`)
	must(err)
	// REC-10 cancellation is idempotent and blocks generation/retrieval.
	a10 := newApproved("cancel")
	must(export.Cancel(ctx, requester, a10.ID))
	must(export.Cancel(ctx, requester, a10.ID))
	if _, err = export.Generate(ctx, requester, a10.ID); err == nil {
		t.Fatal("REC-10 generated cancelled export")
	}
	if d, err := export.Retrieve(ctx, reviewer, a10.ID); err == nil || len(d.DirectoryJSON) != 0 {
		t.Fatalf("REC-10 returned bytes: %v", err)
	}
	// REC-11/13 reuse the existing drill's direct abandoned-lease and
	// reconcile assertions (lines 215-234), without duplicating that scenario.
	// REC-12 manually expired package is refused without bytes.
	a12 := newApproved("expiry")
	if _, err = export.Generate(ctx, requester, a12.ID); err != nil {
		t.Fatalf("REC-12 generate: %v", err)
	}
	_, err = owner.Exec(ctx, `UPDATE scoped_exports SET expires_at=now()-interval '1 second' WHERE tenant_id=$1 AND id=$2`, tenant, a12.ID)
	must(err)
	if d, err := export.Retrieve(ctx, reviewer, a12.ID); err == nil || len(d.DirectoryJSON) != 0 {
		t.Fatalf("REC-12 returned expired bytes: %v", err)
	}
	// REC-14 stale worker token cannot publish over a newer lease.
	a14 := newApproved("stale-worker")
	_, stale, err := rs.Store.BeginExport(ctx, requester, tenant, a14.ID, 300*time.Millisecond, check)
	must(err)
	time.Sleep(400 * time.Millisecond)
	must(rs.Store.ReconcileDueExports(ctx))
	_, fresh, err := rs.Store.BeginExport(ctx, requester, tenant, a14.ID, time.Minute, check)
	must(err)
	if stale == fresh {
		t.Fatal("REC-14 attempt identity was reused")
	}
	if _, err = rs.Store.PublishExport(ctx, requester, tenant, a14.ID, stale, a14.SnapshotDigest, strings.Repeat("c", 64), []byte("stale bytes"), okVerify, check); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("REC-14 stale worker publish: %v", err)
	}
	checkNoPackage(a14.ID)
	// Retain sanitized drill evidence.
	must(os.WriteFile(filepath.Join(root, "c08-recovery-matrix.json"), []byte("{\"rows\":14,\"candidate\":\""+mustHead(t)+"\"}\n"), 0600))
}

func mustHead(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("/mnt/rgw-payload/charter.head")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(b))
}
