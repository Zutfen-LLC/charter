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
	"sync"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
	capture := func(label, input string) fixture {
		var f fixture
		f.project, err = auth.CreateProject(ctx, tenant, "synthetic "+label)
		must(err)
		must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.project).Scan(&f.matter))
		result, err := recorder.Process(ctx, evidence.Request{TenantID: tenant, ProjectID: f.project, MatterID: f.matter, CustodianID: custodian.UserID, IdempotencyKey: label, Input: []byte(input)}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("synthetic output " + label)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		f.turn = result.TurnID
		f.refs, err = b.TurnDisposalRefs(ctx, tenant, f.turn)
		must(err)
		return f
	}
	sharedOf := func(x, y fixture, digest string) evidence.VersionRef {
		var shared evidence.VersionRef
		for _, xr := range x.refs {
			for _, yr := range y.refs {
				if xr == yr && strings.HasSuffix(xr.Key, strings.TrimPrefix(digest, "sha256:")) {
					shared = xr
				}
			}
		}
		return shared
	}
	input := evidence.SHA256([]byte("synthetic shared input"))
	partialInput := evidence.SHA256([]byte("synthetic partial shared input"))
	a, peer := capture("A", "synthetic shared input"), capture("B", "synthetic shared input")
	ap, bp := capture("A2", "synthetic partial shared input"), capture("B2", "synthetic partial shared input")
	for _, pair := range [][2]fixture{{a, peer}, {ap, bp}} {
		if pair[0].project == pair[1].project || pair[0].matter == pair[1].matter {
			t.Fatal("fixtures must be in different projects and matters")
		}
	}
	shared := sharedOf(a, peer, input)
	sharedPartial := sharedOf(ap, bp, partialInput)
	if shared.Version == "" || sharedPartial.Version == "" {
		t.Fatal("no shared exact content version")
	}
	// Independent readback of the shared version's physical presence and
	// native protection state. Presence is proven by Head; the legal-hold
	// probe may answer ON, OFF, or (for a version that never carried lock
	// metadata on this backend) a not-found that is not physical absence.
	holdState := func(r evidence.VersionRef) string {
		if err := native.Head(ctx, r.Key, r.Version); err != nil {
			t.Fatalf("shared presence probe %s: %v", r.Key, err)
		}
		mode, err := native.LegalHold(ctx, r.Key, r.Version)
		switch {
		case err == nil && mode == "ON":
			return "ON"
		case err == nil:
			return "OFF"
		case errors.Is(err, s3transport.ErrObjectAbsent):
			return "OFF"
		default:
			t.Fatalf("shared protection probe %s: %v", r.Key, err)
			return ""
		}
	}
	deadline := time.Time{}
	for _, f := range []fixture{a, peer, ap, bp} {
		for _, v := range f.refs {
			got, err := native.Read(ctx, v.Key, v.Version)
			must(err)
			if got.Until.After(deadline) {
				deadline = got.Until
			}
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
	// Repeated and concurrent finish-purge retries against the completed
	// disposal must be idempotent and must never erase the exact-version
	// ledger that historical exports attribute (correction finding 2).
	retry := func() (string, error) {
		outcome, _, err := rs.FinishPurge(ctx, &disposer, a.turn)
		return outcome, err
	}
	for i := 0; i < 3; i++ {
		if outcome, err := retry(); err != nil || outcome != "not_purging" {
			t.Fatalf("repeated retry %d: %q %v", i, outcome, err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := retry()
			if err != nil || outcome != "not_purging" {
				results <- "concurrent retry: " + outcome + ": " + err.Error()
				return
			}
			results <- ""
		}()
	}
	wg.Wait()
	close(results)
	for problem := range results {
		if problem != "" {
			t.Fatal(problem)
		}
	}
	plan, err = rs.Store.PlanOf(ctx, tenant, a.turn)
	must(err)
	sharedRows = 0
	for _, row := range plan {
		if row.Key == shared.Key && row.Version == shared.Version && row.Disposition == records.OutcomeRetainedShared {
			sharedRows++
		}
	}
	if sharedRows != 1 {
		t.Fatalf("retries erased the shared attribution: shared=%d", sharedRows)
	}
	place := func(f fixture, id string) *records.Hold {
		h, err := rs.Place(ctx, requester, records.Scope{MatterID: f.matter, CustodianIDs: []string{custodian.UserID}}, "synthetic scoped preservation", id)
		must(err)
		if h.State != records.HoldEffective {
			t.Fatalf("hold not effective: %s", h.State)
		}
		return h
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
	peerIdentity := func(s string) bool {
		return s == peer.turn || s == peer.project || s == peer.matter || s == bp.turn || s == bp.project || s == bp.matter
	}
	// A disposed record's bundle carries no content at all, and no peer
	// identity may appear anywhere in it.
	assertNoContent := func(t *testing.T, files map[string][]byte) {
		t.Helper()
		for name, body := range files {
			if strings.HasPrefix(name, "events/") || strings.HasPrefix(name, "objects/") {
				t.Fatalf("content exported at %q", name)
			}
			if peerIdentity(name) || strings.Contains(string(body), peer.turn) || strings.Contains(string(body), peer.project) || strings.Contains(string(body), peer.matter) || strings.Contains(string(body), bp.turn) || strings.Contains(string(body), bp.project) || strings.Contains(string(body), bp.matter) {
				t.Fatalf("peer metadata exported at %q", name)
			}
		}
	}
	// A partially disposed record legitimately carries its OWN content; only
	// peer identities are forbidden.
	assertNoPeerIdentity := func(t *testing.T, files map[string][]byte) {
		t.Helper()
		for name, body := range files {
			if peerIdentity(name) || strings.Contains(string(body), peer.turn) || strings.Contains(string(body), peer.project) || strings.Contains(string(body), peer.matter) || strings.Contains(string(body), bp.turn) || strings.Contains(string(body), bp.project) || strings.Contains(string(body), bp.matter) {
				t.Fatalf("peer metadata exported at %q", name)
			}
		}
	}
	assertDisposedA := func(t *testing.T, snap records.ExportSnapshot, verified exportbundle.Result, sharedRef evidence.VersionRef) {
		t.Helper()
		if len(snap.Records) != 1 || snap.Records[0].TurnID != a.turn || snap.Records[0].State != records.ItemDisposed || snap.Records[0].Classification != "disposed" || len(snap.Records[0].Versions) != 0 {
			t.Fatalf("disposed manifest authority: %+v", snap.Records)
		}
		rec := snap.Records[0]
		found := false
		for _, sv := range rec.RetainedShared {
			if sv.Key == sharedRef.Key && sv.Version == sharedRef.Version {
				if sv.Disposition != records.OutcomeRetainedShared || sv.PlanEpoch == nil {
					t.Fatalf("malformed shared attribution: %+v", sv)
				}
				found = true
			}
		}
		if !found {
			t.Fatalf("disposed record lost retained_shared attribution: %+v", rec.RetainedShared)
		}
		for _, miss := range rec.Missing {
			if miss.Key == sharedRef.Key && miss.Version == sharedRef.Version {
				t.Fatalf("shared survivor fabricated as missing: %+v", miss)
			}
		}
		if verified.Status != exportbundle.DeclaredGap || verified.Turns != 0 || len(verified.Gaps) != 1 || verified.Gaps[0] != a.turn+":disposed" {
			t.Fatalf("offline result: %+v", verified)
		}
	}
	var holdB *records.Hold
	for _, held := range []bool{false, true} {
		label := "unheld"
		if held {
			label = "held"
			holdB = place(peer, "hold-b")
		}
		t.Run(label, func(t *testing.T) {
			want := "OFF"
			if held {
				want = "ON"
			}
			if state := holdState(shared); state != want {
				t.Fatalf("physical protection=%q wanted=%q", state, want)
			}
			t.Logf("shared exact version present, native hold %s; A has %d disposed record-specific versions", want, eventRows)
			snap, files, verified := makeExport(t, a, "a-"+label)
			assertDisposedA(t, snap, verified, shared)
			assertNoContent(t, files)
		})
	}
	t.Run("authorized-peer", func(t *testing.T) {
		snap, files, verified := makeExport(t, peer, "b-held")
		if len(snap.Records) != 1 || snap.Records[0].TurnID != peer.turn || verified.Turns != 1 || len(verified.Gaps) != 0 || len(files["events/"+peer.turn+".jsonl"]) == 0 {
			t.Fatalf("peer export not independent: %+v", verified)
		}
	})
	// Partially disposed A: the disposal was interrupted with the shared
	// version retained and a record-specific version protected, so the record
	// is NOT disposed and the shared bytes remain its authorized content.
	var blockRef evidence.VersionRef
	for _, r := range ap.refs {
		if blockRef.Version == "" && strings.Contains(r.Key, "/"+ap.turn+"/") {
			blockRef = r
		}
	}
	if blockRef.Version == "" {
		t.Fatal("no record-specific version to protect")
	}
	if got, err := rs.Store.BeginPurge(ctx, disposer, ap.turn, nil); err != nil || got != "purging" {
		t.Fatalf("partial begin: %q %v", got, err)
	}
	must(native.SetLegalHold(ctx, blockRef.Key, blockRef.Version, true))
	if outcome, _, err := rs.FinishPurge(ctx, &disposer, ap.turn); !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("expected interrupted partial disposal: %q %v", outcome, err)
	}
	place(ap, "hold-a2")
	assertPartialA := func(t *testing.T, snap records.ExportSnapshot, verified exportbundle.Result, files map[string][]byte) {
		t.Helper()
		if len(snap.Records) != 1 || snap.Records[0].TurnID != ap.turn || snap.Records[0].State == records.ItemDisposed || snap.Records[0].Classification != "partial_loss" {
			t.Fatalf("partial manifest authority: %+v", snap.Records)
		}
		rec := snap.Records[0]
		if len(rec.Missing) == 0 || len(rec.Versions) == 0 || len(rec.RetainedShared) != 0 {
			t.Fatalf("partial record shape: missing=%d versions=%d shared=%d", len(rec.Missing), len(rec.Versions), len(rec.RetainedShared))
		}
		sharedContent := false
		for _, v := range rec.Versions {
			if v.Key == sharedPartial.Key && v.Version == sharedPartial.Version {
				sharedContent = true
			}
		}
		if !sharedContent {
			t.Fatalf("partial record lost its shared content version: %+v", rec.Versions)
		}
		if verified.Status != exportbundle.DeclaredGap || verified.Turns != 1 || len(verified.Gaps) != 1 || verified.Gaps[0] != ap.turn+":partial_loss" {
			t.Fatalf("partial offline result: %+v", verified)
		}
		object := "objects/" + strings.TrimPrefix(partialInput, "sha256:")
		if len(files[object]) == 0 {
			t.Fatalf("authorized shared content bytes not exported at %q", object)
		}
	}
	t.Run("partial-unheld-peer", func(t *testing.T) {
		// A2's own hold claims the shared version: its protection is this
		// record's responsibility, not the peer's.
		if state := holdState(sharedPartial); state != "ON" {
			t.Fatalf("partial shared protection=%q wanted=ON", state)
		}
		snap, files, verified := makeExport(t, ap, "a2-partial-unheld")
		assertPartialA(t, snap, verified, files)
		assertNoPeerIdentity(t, files)
	})
	place(bp, "hold-b2")
	t.Run("partial-held-peer", func(t *testing.T) {
		if state := holdState(sharedPartial); state != "ON" {
			t.Fatalf("partial shared protection=%q wanted=ON", state)
		}
		snap, files, verified := makeExport(t, ap, "a2-partial-held")
		assertPartialA(t, snap, verified, files)
		assertNoPeerIdentity(t, files)
	})
	t.Run("partial-peer-export", func(t *testing.T) {
		snap, files, verified := makeExport(t, bp, "b2-held")
		if len(snap.Records) != 1 || snap.Records[0].TurnID != bp.turn || verified.Turns != 1 || len(verified.Gaps) != 0 || len(files["events/"+bp.turn+".jsonl"]) == 0 {
			t.Fatalf("partial peer export not independent: %+v", verified)
		}
	})
	// Shared-version survival through release and disposal: once the peer's
	// hold is released and the peer record is disposed, the shared bytes are
	// physically gone, and A's historical attribution stays retained_shared -
	// never a fabricated missing-version disposition.
	if _, err := rs.Release(ctx, requester, holdB.ID, "synthetic release before peer disposal"); err != nil {
		t.Fatalf("release peer hold: %v", err)
	}
	_, err = rs.Sweep(ctx, requester)
	must(err)
	if got, err := rs.Store.BeginPurge(ctx, disposer, peer.turn, nil); err != nil || got != "purging" {
		t.Fatalf("peer begin: %q %v", got, err)
	}
	if got, _, err := rs.FinishPurge(ctx, &disposer, peer.turn); err != nil || got != "disposed" {
		t.Fatalf("peer finish: %q %v", got, err)
	}
	if err := native.Head(ctx, shared.Key, shared.Version); !errors.Is(err, s3transport.ErrObjectAbsent) {
		t.Fatalf("shared version survived its last reference's disposal: %v", err)
	}
	t.Run("disposed-after-shared-loss", func(t *testing.T) {
		snap, files, verified := makeExport(t, a, "a-after-release")
		assertDisposedA(t, snap, verified, shared)
		assertNoContent(t, files)
	})
}
