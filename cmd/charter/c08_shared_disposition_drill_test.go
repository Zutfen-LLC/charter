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

func TestC08NativeSharedDispositionDrill(t *testing.T) {
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
	runC08NativeSharedDisposition(t, ctx, c, owner, root)
}

// The native probe and ordinary C07 paths use actual exact version IDs.
func runC08NativeSharedDisposition(t *testing.T, ctx context.Context, c config.Config, owner *pgxpool.Pool, root string) {
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
	b, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: native, Deployment: sc.Deployment + "-c08-shared", Bucket: sc.Bucket, TrustedCommitKey: mustHex(t, sc.CommitKey), Signer: ed25519.NewKeyFromSeed(seed), MinimumRetention: started.Add(5 * time.Second), RetainFor: time.Minute, Fence: fence})
	must(err)
	ws, err := pgxpool.New(ctx, c.DatabaseURL)
	must(err)
	defer ws.Close()
	auth := store.Store{DB: owner}
	tenant, err := auth.CreateTenant(ctx, "urn:charter:synthetic:c08-shared", "seed", "synthetic C08 historical loss")
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
	_, err = owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id,retention_seconds,grace_seconds,set_by) VALUES($1,1,0,$2)`, tenant, requester.UserID)
	must(err)
	rs := &records.Service{Store: &records.Store{DB: ws}, Backend: b, Storage: native, Retained: true}
	recorder := &evidence.Recorder{Backend: b, Fence: fence, Lifecycle: rs, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "c08-shared", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "history", ModelID: "det-a"}}, nil
	}}

	type fixture struct {
		project, matter, turn string
		refs                  []evidence.VersionRef
	}
	capture := func(label string) fixture {
		var f fixture
		f.project, err = auth.CreateProject(ctx, tenant, "synthetic "+label)
		must(err)
		must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.project).Scan(&f.matter))
		result, err := recorder.Process(ctx, evidence.Request{TenantID: tenant, ProjectID: f.project, MatterID: f.matter, CustodianID: custodian.UserID, IdempotencyKey: label, Input: []byte("synthetic shared input")}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("synthetic output " + label)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		f.turn = result.TurnID
		f.refs, err = b.TurnDisposalRefs(ctx, tenant, f.turn)
		must(err)
		return f
	}
	a, peer := capture("A"), capture("B")
	if a.project == peer.project || a.matter == peer.matter {
		t.Fatal("fixtures must be in different projects and matters")
	}
	input := evidence.SHA256([]byte("synthetic shared input"))
	var shared evidence.VersionRef
	for _, ar := range a.refs {
		for _, br := range peer.refs {
			if ar == br && strings.HasSuffix(ar.Key, strings.TrimPrefix(input, "sha256:")) {
				shared = ar
			}
		}
	}
	if shared.Version == "" {
		t.Fatal("no shared exact content version")
	}
	deadline := time.Time{}
	for _, v := range a.refs {
		got, err := native.Read(ctx, v.Key, v.Version)
		must(err)
		if got.Until.After(deadline) {
			deadline = got.Until
		}
	}
	select {
	case <-time.After(time.Until(deadline.Add(time.Second))):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	_, err = rs.Sweep(ctx, requester)
	must(err)
	if got, err := rs.Store.BeginPurge(ctx, disposer, a.turn, nil); err != nil || got != "purging" {
		t.Fatalf("begin: %q %v", got, err)
	}
	if got, _, err := rs.FinishPurge(ctx, &disposer, a.turn); err != nil || got != "disposed" {
		t.Fatalf("finish: %q %v", got, err)
	}
	plan, err := rs.Store.PlanOf(ctx, tenant, a.turn)
	must(err)
	var sharedRows, eventRows int
	for _, row := range plan {
		if row.Key == shared.Key && row.Version == shared.Version && row.Disposition == records.OutcomeRetainedShared {
			sharedRows++
		}
		if strings.Contains(row.Key, "/"+a.turn+"/") {
			eventRows++
			if row.Disposition != records.OutcomeDeleted && row.Disposition != records.OutcomeAbsent {
				t.Fatalf("record-specific key not disposed: %+v", row)
			}
			if err := native.Head(ctx, row.Key, row.Version); !errors.Is(err, s3transport.ErrObjectAbsent) {
				t.Fatalf("record-specific key still present or unknown: %v", err)
			}
		}
	}
	if sharedRows != 1 || eventRows < 2 {
		t.Fatalf("bad ledger census: shared=%d event=%d", sharedRows, eventRows)
	}
	place := func(f fixture, id string) {
		h, err := rs.Place(ctx, requester, records.Scope{MatterID: f.matter, CustodianIDs: []string{custodian.UserID}}, "synthetic scoped preservation", id)
		must(err)
		if h.State != records.HoldEffective {
			t.Fatalf("hold not effective: %s", h.State)
		}
	}
	place(a, "hold-a")
	ex := &server.RetainedExports{Records: rs, Backend: b}
	makeExport := func(t *testing.T, f fixture, id string) (records.ExportSnapshot, map[string][]byte, exportbundle.Result) {
		t.Helper()
		req, err := ex.Request(ctx, requester, records.NewExportRequest{RequestID: id, Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "synthetic shared attribution"}})
		if err != nil {
			t.Fatalf("request scoped export: %v", err)
		}
		var snap records.ExportSnapshot
		if err := json.Unmarshal(req.Snapshot, &snap); err != nil {
			t.Fatal(err)
		}
		if _, err := ex.Approve(ctx, reviewer, req.ID, req.SnapshotDigest); err != nil {
			t.Fatal(err)
		}
		if _, err := ex.Generate(ctx, requester, req.ID); err != nil {
			t.Fatalf("generate, snapshot record: %+v; %v", snap.Records, err)
		}
		p, err := ex.Retrieve(ctx, reviewer, req.ID)
		if err != nil {
			t.Fatal(err)
		}
		var files map[string][]byte
		if err := json.Unmarshal(p.DirectoryJSON, &files); err != nil {
			t.Fatal(err)
		}
		verified, err := exportbundle.VerifyMembers(files, evidence.RetentionProfile, p.ManifestDigest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "c08-shared-"+id+".json"), p.DirectoryJSON, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "c08-shared-"+id+"-anchor.json"), []byte(`{"trusted_manifest_digest":"`+p.ManifestDigest+`"}`), 0600); err != nil {
			t.Fatal(err)
		}
		return snap, files, verified
	}
	for _, held := range []bool{false, true} {
		label, want := "unheld", "OFF"
		if held {
			label, want = "held", "ON"
			place(peer, "hold-b")
		}
		t.Run(label, func(t *testing.T) {
			if err := native.Head(ctx, shared.Key, shared.Version); err != nil {
				t.Fatal(err)
			}
			if got, err := native.LegalHold(ctx, shared.Key, shared.Version); err != nil || got != want {
				t.Fatalf("physical protection=%q wanted=%q err=%v", got, want, err)
			}
			t.Logf("shared exact version present, native hold %s; A has %d disposed record-specific versions", want, eventRows)
			snap, files, verified := makeExport(t, a, "a-"+label)
			if len(snap.Records) != 1 || snap.Records[0].TurnID != a.turn || snap.Records[0].State != records.ItemDisposed || snap.Records[0].Classification != "disposed" || len(snap.Records[0].Versions) != 0 {
				t.Fatalf("disposed manifest authority: %+v", snap.Records)
			}
			if verified.Status != exportbundle.DeclaredGap || verified.Turns != 0 || len(verified.Gaps) != 1 || verified.Gaps[0] != a.turn+":disposed" {
				t.Fatalf("offline result: %+v", verified)
			}
			for name, body := range files {
				if strings.HasPrefix(name, "events/") || strings.HasPrefix(name, "objects/") || strings.Contains(string(body), peer.turn) || strings.Contains(string(body), peer.project) || strings.Contains(string(body), peer.matter) {
					t.Fatalf("content or peer metadata exported at %q", name)
				}
			}
		})
	}
	t.Run("authorized-peer", func(t *testing.T) {
		snap, files, verified := makeExport(t, peer, "b-held")
		if len(snap.Records) != 1 || snap.Records[0].TurnID != peer.turn || verified.Turns != 1 || len(verified.Gaps) != 0 || len(files["events/"+peer.turn+".jsonl"]) == 0 {
			t.Fatalf("peer export not independent: %+v", verified)
		}
	})
}
