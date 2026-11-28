//go:build retention_drill

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/exportbundle"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/server"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestC08NativeHistoryDrill(t *testing.T) {
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
	runC08NativeHistory(t, ctx, c, owner, root)
}

// Exercise physical loss, rather than treating a plan as loss. A short-lived
// signed namespace uses the same native stack as C07; ordinary qualified
// runtime writes still use their unchanged one-day minimum.
func runC08NativeHistory(t *testing.T, ctx context.Context, c config.Config, owner *pgxpool.Pool, root string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
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
	req, err := export.Request(ctx, requester, records.NewExportRequest{RequestID: "history-export", Intent: records.ExportIntent{ProjectID: project, MatterID: matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "synthetic retained loss"}})
	must(err)
	_, err = export.Approve(ctx, reviewer, req.ID, req.SnapshotDigest)
	must(err)
	// Simulate process exit immediately after the durable generation marker:
	// no generator calls readback or attaches package bytes to this attempt.
	_, check := rs.ExportSnapshotCallbacks(tenant, requester.UserID)
	_, abandoned, err := rs.Store.BeginExport(ctx, requester, tenant, req.ID, 650*time.Millisecond, check)
	must(err)
	if p, err := export.Retrieve(ctx, reviewer, req.ID); err == nil || len(p.DirectoryJSON) != 0 {
		t.Fatal("an abandoned generation attempt exposed bytes")
	}
	select {
	case <-time.After(time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	must(rs.Store.ReconcileDueExports(ctx))
	ready, err := export.Generate(ctx, requester, req.ID)
	must(err)
	if err := rs.Store.RecordExportAttemptFailure(ctx, requester, req.ID, abandoned, "readback"); !errors.Is(err, records.ErrExportConflict) {
		t.Fatalf("abandoned generation state could be changed after publication: %v", err)
	}
	p, err := export.Retrieve(ctx, reviewer, req.ID)
	must(err)
	var files map[string][]byte
	must(json.Unmarshal(p.DirectoryJSON, &files))
	result, err := exportbundle.VerifyMembers(files, evidence.RetentionProfile, "sha256:"+ready.ManifestDigest)
	must(err)
	if p.ManifestDigest != "sha256:"+ready.ManifestDigest || result.Status != exportbundle.DeclaredGap || len(result.Gaps) != 3 || result.Turns != 2 {
		t.Fatalf("historical output census %+v", result)
	}
	if files["events/"+turns["full"]+".jsonl"] != nil {
		t.Fatal("full loss manufactured events")
	}
	for _, label := range labels[1:] {
		evs := events[label]
		n := 0
		if label == "partial-no-admission" {
			n = len(evs) - 1
		}
		want, err := evidence.Canonical(evs[n])
		must(err)
		if got := files["events/"+turns[label]+".jsonl"]; string(got) != string(want)+"\n" {
			t.Fatalf("historical survivor %s was rewritten or lost", label)
		}
	}
	must(os.WriteFile(filepath.Join(root, "c08-history-transport.json"), p.DirectoryJSON, 0600))
	receipt, err := json.Marshal(map[string]any{"export_id": req.ID, "trusted_manifest_digest": p.ManifestDigest, "profile": evidence.RetentionProfile, "result": result, "native_physical_loss": true})
	must(err)
	must(os.WriteFile(filepath.Join(root, "c08-history-export.json"), append(receipt, '\n'), 0600))
}
