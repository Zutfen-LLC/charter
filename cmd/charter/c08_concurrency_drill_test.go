//go:build retention_drill

package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestC08NativeConcurrencyDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 11*time.Minute)
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
	runC08NativeConcurrency(t, ctx, c, owner, root)
}

type c08ConcFixture struct {
	project, matter, turn string
	refs                  []evidence.VersionRef
	input                 string
}

type c08ConcHarness struct {
	ctx                                      context.Context
	owner                                    *pgxpool.Pool
	auth                                     store.Store
	rs                                       *records.Service
	ex                                       *server.RetainedExports
	requester, disposer, reviewer, custodian store.Principal
	started                                  time.Time
	capture                                  func(string, string, ...string) c08ConcFixture
	place                                    func(c08ConcFixture, string) *records.Hold
}

func runC08NativeConcurrency(t *testing.T, ctx context.Context, c config.Config, owner *pgxpool.Pool, root string) {
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
	b, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: native, Deployment: sc.Deployment + "-c08-conc", Bucket: sc.Bucket, TrustedCommitKey: mustHex(t, sc.CommitKey), Signer: ed25519.NewKeyFromSeed(seed), MinimumRetention: started.Add(5 * time.Second), RetainFor: time.Minute, Fence: fence})
	must(err)
	ws, err := pgxpool.New(ctx, c.DatabaseURL)
	must(err)
	defer ws.Close()
	auth := store.Store{DB: owner}
	tenant, err := auth.CreateTenant(ctx, "urn:charter:synthetic:c08-conc", "seed", "synthetic C08 concurrency qualification")
	must(err)
	mkUser := func(subject, role string) store.Principal {
		id, e := auth.CreateUser(ctx, tenant, subject, "synthetic "+subject)
		must(e)
		if role != "" {
			must(auth.SeedRole(ctx, tenant, id, role))
		}
		return store.Principal{TenantID: tenant, UserID: id}
	}
	requester, disposer := mkUser("requester", store.RoleRecordsOfficer), mkUser("disposer", store.RoleRecordsOfficer)
	reviewer, custodian := mkUser("reviewer", store.RoleExportReviewer), mkUser("custodian", "")
	_, err = owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id,retention_seconds,grace_seconds,set_by) VALUES($1,1,0,$2)`, tenant, requester.UserID)
	must(err)
	rs := &records.Service{Store: &records.Store{DB: ws}, Backend: b, Storage: native, Retained: true}
	recorder := &evidence.Recorder{Backend: b, Fence: fence, Lifecycle: rs, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "c08-conc", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "concurrency", ModelID: "det-a"}}, nil
	}}
	h := &c08ConcHarness{ctx: ctx, owner: owner, auth: auth, rs: rs, ex: &server.RetainedExports{Records: rs, Backend: b}, requester: requester, disposer: disposer, reviewer: reviewer, custodian: custodian, started: started}
	h.capture = func(label, input string, scope ...string) c08ConcFixture {
		var f c08ConcFixture
		f.input = input
		if len(scope) == 2 {
			f.project, f.matter = scope[0], scope[1]
		} else {
			f.project, err = auth.CreateProject(ctx, tenant, "synthetic concurrency "+label)
			must(err)
			must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.project).Scan(&f.matter))
		}
		out, e := recorder.Process(ctx, evidence.Request{TenantID: tenant, ProjectID: f.project, MatterID: f.matter, CustodianID: custodian.UserID, IdempotencyKey: "c08-conc-" + label, Input: []byte(input)}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("synthetic result " + label)}, nil
		}, func(context.Context) error { return nil })
		must(e)
		f.turn = out.TurnID
		f.refs, e = b.TurnDisposalRefs(ctx, tenant, f.turn)
		must(e)
		return f
	}
	h.place = func(f c08ConcFixture, key string) *records.Hold {
		hold, e := rs.Place(ctx, requester, records.Scope{MatterID: f.matter, CustodianIDs: []string{custodian.UserID}}, "synthetic concurrency hold", key)
		must(e)
		if hold.State != records.HoldEffective {
			t.Fatalf("hold state %s", hold.State)
		}
		return hold
	}
	fresh := func(label string) c08ConcFixture { return h.capture(label, "content "+label) }
	request := func(f c08ConcFixture, key string) records.ExportSummary {
		r, e := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: key, Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "synthetic concurrency qualification"}})
		must(e)
		return r
	}
	approved := func(r records.ExportSummary) { _, e := h.ex.Approve(ctx, reviewer, r.ID, r.SnapshotDigest); must(e) }
	cancelExport := func(id string) { _ = rs.Store.CancelExport(ctx, requester, requester.TenantID, id) }
	assertNoPackage := func(t *testing.T, id string) {
		p, e := h.ex.Retrieve(ctx, reviewer, id)
		if e == nil || len(p.DirectoryJSON) != 0 {
			t.Fatalf("unauthorized package delivered after refusal (%d bytes, err=%v)", len(p.DirectoryJSON), e)
		}
		// The refusal must extend to durable state: no delivery audit may
		// exist, and package bytes must be absent or empty unless the
		// export was legitimately published (state 'ready') before the
		// racing mutation — a published-then-released package is sealed
		// and undeliverable, and only its delivery is forbidden. Callers
		// pass the request key when the request itself was refused (no
		// row exists at all) or the export's UUID afterwards.
		var exportID, state string
		var packageBytes *string
		if err := ws.QueryRow(ctx, `SELECT id::text, state, package_bytes::text FROM scoped_exports WHERE tenant_id=$1 AND (id::text=$2 OR request_key=$2)`, requester.TenantID, id).Scan(&exportID, &state, &packageBytes); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				t.Fatalf("export row readback: %v", err)
			}
			exportID, state, packageBytes = id, "absent", nil
		}
		if state != records.ExportReady && packageBytes != nil && *packageBytes != "" {
			t.Fatalf("refusal left durable package bytes (state=%s)", state)
		}
		var deliveries int
		if err := ws.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='export.retrieve' AND detail->>'export_id'=$2`, requester.TenantID, exportID).Scan(&deliveries); err != nil {
			t.Fatalf("delivery audit readback: %v", err)
		}
		if deliveries != 0 {
			t.Fatalf("refusal left %d delivery audit rows", deliveries)
		}
		cancelExport(id)
	}
	place := h.place
	// waitBlockedOnEpochRow fails the subtest unless a backend running an
	// epoch-row statement is observed waiting on a database lock: this
	// proves the racing hold mutation (release or scope change, whose
	// epoch bump UPDATE targets matter_hold_epochs) reached and blocked
	// on the epoch row held by the still-open export transaction. The
	// interleaving is therefore observed, not merely consistent with
	// the outcome; a mutation that never blocks fails the drill.
	waitBlockedOnEpochRow := func(t *testing.T) {
		deadline := time.Now().Add(15 * time.Second)
		for {
			var blocked int
			if err := ws.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query ILIKE '%matter_hold_epochs%' AND pid <> pg_backend_pid()`).Scan(&blocked); err != nil {
				t.Fatalf("epoch-row block observation: %v", err)
			}
			if blocked > 0 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("racing mutation never blocked on the epoch row held by the open export transaction")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}

	t.Run("CONC-01-placement-vs-snapshot", func(t *testing.T) {
		f := fresh("01")
		entered, release := make(chan struct{}), make(chan struct{})
		rs.Store.Hooks.AtEpochLock = func(stage, _, matter string) {
			if stage == "place" && matter == f.matter {
				close(entered)
				<-release
			}
		}
		defer func() { rs.Store.Hooks.AtEpochLock = nil }()
		placed := make(chan error, 1)
		go func() {
			_, e := rs.Place(ctx, requester, records.Scope{MatterID: f.matter, CustodianIDs: []string{custodian.UserID}}, "synthetic barrier", "conc-01-hold")
			placed <- e
		}()
		<-entered
		reqDone := make(chan records.ExportSummary, 1)
		reqErr := make(chan error, 1)
		go func() {
			r, e := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: "conc-01-export", Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "placement boundary"}})
			reqDone <- r
			reqErr <- e
		}()
		close(release)
		if e := <-placed; e != nil {
			t.Fatal(e)
		}
		r := <-reqDone
		e := <-reqErr
		if e == nil {
			var snap records.ExportSnapshot
			if json.Unmarshal(r.Snapshot, &snap) != nil {
				t.Fatal("invalid snapshot")
			}
			if len(snap.HoldIDs) == 0 {
				t.Fatal("snapshot mixed committed placement without hold attribution")
			}
			cancelExport("conc-01-export")
		} else {
			assertNoPackage(t, "conc-01-export")
		}
	})
	t.Run("CONC-02-release-vs-snapshot", func(t *testing.T) {
		f := fresh("02")
		hold := place(f, "conc-02-hold")
		if _, e := h.rs.Release(ctx, requester, hold.ID, "synthetic release"); e != nil {
			t.Fatal(e)
		}
		r, e := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: "conc-02-export", Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "release versus snapshot"}})
		if e == nil {
			t.Fatalf("snapshot unexpectedly succeeded after release: %+v", r)
		}
		assertNoPackage(t, "conc-02-export")
	})
	t.Run("CONC-03-release-vs-generation", func(t *testing.T) {
		f := fresh("03")
		hold := place(f, "conc-03-hold")
		r := request(f, "conc-03-export")
		approved(r)
		if _, e := h.rs.Release(ctx, requester, hold.ID, "synthetic release before generation"); e != nil {
			t.Fatal(e)
		}
		if _, e := h.ex.Generate(ctx, requester, r.ID); e == nil {
			t.Fatal("generation succeeded after release")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-04-release-vs-publication", func(t *testing.T) {
		f := fresh("04")
		hold := place(f, "conc-04-hold")
		r := request(f, "conc-04-export")
		approved(r)
		_, check := rs.ExportSnapshotCallbacks(requester.TenantID, requester.UserID)
		s, token, e := rs.Store.BeginExport(ctx, requester, requester.TenantID, r.ID, time.Minute, check)
		if e != nil {
			t.Fatal(e)
		}
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		go func() {
			_, e := rs.Store.PublishExport(ctx, requester, requester.TenantID, r.ID, token, s.SnapshotDigest, strings.Repeat("a", 64), []byte("synthetic package bytes"), func([]byte, string, string) error { close(entered); <-release; return nil }, check)
			done <- e
		}()
		<-entered
		if _, e := h.rs.Release(ctx, requester, hold.ID, "synthetic release during verify"); e != nil {
			close(release)
			t.Fatal(e)
		}
		close(release)
		if e := <-done; e == nil {
			t.Fatal("publication accepted stale hold snapshot")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-05-release-vs-retrieval", func(t *testing.T) {
		f := fresh("05")
		hold := place(f, "conc-05-hold")
		r := request(f, "conc-05-export")
		approved(r)
		if _, e := h.ex.Generate(ctx, requester, r.ID); e != nil {
			t.Fatal(e)
		}
		if _, e := h.rs.Release(ctx, requester, hold.ID, "synthetic release before retrieval"); e != nil {
			t.Fatal(e)
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-06-scope-change-vs-approval", func(t *testing.T) {
		f := fresh("06")
		hold := place(f, "conc-06-hold")
		r := request(f, "conc-06-export")
		if _, e := rs.Store.ChangeScope(ctx, requester, hold.ID, records.Scope{MatterID: f.matter, CustodianIDs: []string{}}, "synthetic scope revision"); e != nil {
			t.Fatal(e)
		}
		if _, e := h.ex.Approve(ctx, reviewer, r.ID, r.SnapshotDigest); e == nil {
			t.Fatal("approval accepted stale scope epoch")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-07-scope-change-vs-generation", func(t *testing.T) {
		f := fresh("07")
		hold := place(f, "conc-07-hold")
		r := request(f, "conc-07-export")
		approved(r)
		if _, e := rs.Store.ChangeScope(ctx, requester, hold.ID, records.Scope{MatterID: f.matter, CustodianIDs: []string{}}, "synthetic scope revision"); e != nil {
			t.Fatal(e)
		}
		if _, e := h.ex.Generate(ctx, requester, r.ID); e == nil {
			t.Fatal("generation accepted stale scope epoch")
		}
		assertNoPackage(t, r.ID)
	})
	// Concurrent boundary series: the sequential subtests above prove the
	// stale-state side of each boundary (the mutation committed first).
	// Each subtest below races the mutation against the generation's or the
	// export transaction's durable window deterministically: the
	// barrier-based subtests pause the OPEN export transaction at the
	// Hooks.AtEpochLock seam (which fires inside the snapshot or
	// revalidation transaction while it holds the protection fence, the
	// scoped item rows and the matter epoch row) and only release it after
	// pg_stat_activity shows the racing mutation blocked on the epoch row,
	// so the interleaving is observed, not merely consistent with the
	// outcome; the phase-gap subtests commit the mutation between the two
	// durable generation phases (lease acquired, publication not yet
	// attempted) - the exact window a concurrent mutation can win. The
	// linearization winner is forced, never observed by chance.
	t.Run("CONC-02-release-vs-snapshot-concurrent", func(t *testing.T) {
		f := fresh("02c")
		hold := place(f, "conc-02c-hold")
		entered, proceed := make(chan struct{}), make(chan struct{})
		var once sync.Once
		rs.Store.Hooks.AtEpochLock = func(stage, _, matter string) {
			if stage == "export_snapshot" && matter == f.matter {
				once.Do(func() { close(entered) })
				<-proceed
			}
		}
		defer func() { rs.Store.Hooks.AtEpochLock = nil }()
		reqDone, reqErrC := make(chan records.ExportSummary, 1), make(chan error, 1)
		go func() {
			r, e := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: "conc-02c-export", Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "release concurrent with snapshot"}})
			reqDone <- r
			reqErrC <- e
		}()
		<-entered
		relDone := make(chan error, 1)
		go func() {
			_, e := h.rs.Release(ctx, requester, hold.ID, "synthetic concurrent release")
			relDone <- e
		}()
		waitBlockedOnEpochRow(t)
		close(proceed)
		r := <-reqDone
		if e := <-reqErrC; e != nil {
			t.Fatalf("capture linearizing before the release must succeed: %v", e)
		}
		if e := <-relDone; e != nil {
			t.Fatalf("release after the capture committed: %v", e)
		}
		var snap records.ExportSnapshot
		if json.Unmarshal(r.Snapshot, &snap) != nil || len(snap.HoldIDs) != 1 || snap.HoldIDs[0] != hold.ID {
			t.Fatalf("pre-release snapshot must freeze the effective hold: %+v", snap.HoldIDs)
		}
		if _, e := h.ex.Approve(ctx, reviewer, r.ID, r.SnapshotDigest); e == nil {
			t.Fatal("approval accepted a hold released after the snapshot")
		}
		assertNoPackage(t, "conc-02c-export")
	})
	t.Run("CONC-03-release-vs-generation-concurrent", func(t *testing.T) {
		f := fresh("03c")
		hold := place(f, "conc-03c-hold")
		r := request(f, "conc-03c-export")
		approved(r)
		// The release commits in the exact mid-generation window: after the
		// durable generation lease is acquired, before publication is
		// attempted (the window in which a real concurrent release can
		// commit, because no locks are held during readback). The
		// publication revalidation must then refuse: no bytes, ever.
		_, check := h.rs.ExportSnapshotCallbacks(requester.TenantID, requester.UserID)
		_, token, e := h.rs.Store.BeginExport(ctx, requester, requester.TenantID, r.ID, time.Minute, check)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := h.rs.Release(ctx, requester, hold.ID, "synthetic release between generation phases"); e != nil {
			t.Fatal(e)
		}
		accept := func([]byte, string, string) error { return nil }
		if _, e := h.rs.Store.PublishExport(ctx, requester, requester.TenantID, r.ID, token, r.SnapshotDigest, strings.Repeat("a", 64), []byte("synthetic staged package"), accept, check); e == nil {
			t.Fatal("generation published content whose hold was released mid-generation")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-05-release-vs-retrieval-concurrent", func(t *testing.T) {
		f := fresh("05c")
		hold := place(f, "conc-05c-hold")
		r := request(f, "conc-05c-export")
		approved(r)
		if _, e := h.ex.Generate(ctx, requester, r.ID); e != nil {
			t.Fatal(e)
		}
		entered, proceed := make(chan struct{}), make(chan struct{})
		var once sync.Once
		rs.Store.Hooks.AtEpochLock = func(stage, _, matter string) {
			if stage == "export_revalidate" && matter == f.matter {
				once.Do(func() { close(entered) })
				<-proceed
			}
		}
		defer func() { rs.Store.Hooks.AtEpochLock = nil }()
		got := make(chan []byte, 1)
		getErr := make(chan error, 1)
		go func() {
			p, e := h.ex.Retrieve(ctx, reviewer, r.ID)
			got <- p.DirectoryJSON
			getErr <- e
		}()
		<-entered
		relDone := make(chan error, 1)
		go func() {
			_, e := h.rs.Release(ctx, requester, hold.ID, "synthetic release concurrent with retrieval")
			relDone <- e
		}()
		waitBlockedOnEpochRow(t)
		close(proceed)
		if e := <-getErr; e != nil {
			t.Fatalf("retrieval linearizing before the release must deliver: %v", e)
		}
		if len(<-got) == 0 {
			t.Fatal("retrieval linearizing before the release delivered no bytes")
		}
		if e := <-relDone; e != nil {
			t.Fatalf("release after the retrieval committed: %v", e)
		}
		if p, e := h.ex.Retrieve(ctx, reviewer, r.ID); e == nil || len(p.DirectoryJSON) != 0 {
			t.Fatal("post-release retrieval delivered bytes")
		}
	})
	t.Run("CONC-06-scope-change-vs-approval-concurrent", func(t *testing.T) {
		f := fresh("06c")
		hold := place(f, "conc-06c-hold")
		r := request(f, "conc-06c-export")
		entered, proceed := make(chan struct{}), make(chan struct{})
		var once sync.Once
		rs.Store.Hooks.AtEpochLock = func(stage, _, matter string) {
			if stage == "export_revalidate" && matter == f.matter {
				once.Do(func() { close(entered) })
				<-proceed
			}
		}
		defer func() { rs.Store.Hooks.AtEpochLock = nil }()
		approveDone := make(chan error, 1)
		go func() {
			_, e := h.ex.Approve(ctx, reviewer, r.ID, r.SnapshotDigest)
			approveDone <- e
		}()
		<-entered
		scopeDone := make(chan error, 1)
		go func() {
			_, e := rs.Store.ChangeScope(ctx, requester, hold.ID, records.Scope{MatterID: f.matter, CustodianIDs: []string{}}, "synthetic concurrent scope revision")
			scopeDone <- e
		}()
		waitBlockedOnEpochRow(t)
		close(proceed)
		if e := <-approveDone; e != nil {
			t.Fatalf("approval linearizing before the scope change must succeed: %v", e)
		}
		if e := <-scopeDone; e != nil {
			t.Fatalf("scope change after the approval committed: %v", e)
		}
		if _, e := h.ex.Generate(ctx, requester, r.ID); e == nil {
			t.Fatal("generation accepted a scope revised after approval")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-07-scope-change-vs-generation-concurrent", func(t *testing.T) {
		f := fresh("07c")
		hold := place(f, "conc-07c-hold")
		r := request(f, "conc-07c-export")
		approved(r)
		// The scope revision commits in the exact mid-generation window
		// (durable lease acquired, publication not attempted): the
		// publication revalidation must then refuse on the moved epoch.
		_, check := h.rs.ExportSnapshotCallbacks(requester.TenantID, requester.UserID)
		_, token, e := h.rs.Store.BeginExport(ctx, requester, requester.TenantID, r.ID, time.Minute, check)
		if e != nil {
			t.Fatal(e)
		}
		if _, e := rs.Store.ChangeScope(ctx, requester, hold.ID, records.Scope{MatterID: f.matter, CustodianIDs: []string{}}, "synthetic scope revision between generation phases"); e != nil {
			t.Fatal(e)
		}
		accept := func([]byte, string, string) error { return nil }
		if _, e := h.rs.Store.PublishExport(ctx, requester, requester.TenantID, r.ID, token, r.SnapshotDigest, strings.Repeat("b", 64), []byte("synthetic staged package"), accept, check); e == nil {
			t.Fatal("generation published content whose scope was revised mid-generation")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-08-capture-vs-snapshot", func(t *testing.T) {
		f := fresh("08")
		place(f, "conc-08-hold")
		admitted, finish := make(chan struct{}), make(chan struct{})
		captureResult := make(chan error, 1)
		go func() {
			_, e := recorder.Process(ctx, evidence.Request{TenantID: requester.TenantID, ProjectID: f.project, MatterID: f.matter, CustodianID: custodian.UserID, IdempotencyKey: "conc-08-late", Input: []byte("late synthetic admission")}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
				close(admitted)
				<-finish
				return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("late synthetic output")}, nil
			}, func(context.Context) error { return nil })
			captureResult <- e
		}()
		<-admitted
		_, requestErr := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: "conc-08-export", Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "concurrent capture boundary"}})
		close(finish)
		if captureErr := <-captureResult; captureErr != nil {
			t.Fatal(captureErr)
		}
		if requestErr == nil {
			t.Fatal("snapshot accepted concurrent unfinished admission")
		}
		assertNoPackage(t, "conc-08-export")
	})
	t.Run("CONC-09-disposal-vs-snapshot", func(t *testing.T) {
		f := fresh("09")
		hold := place(f, "conc-09-hold")
		var until time.Time
		for _, ref := range f.refs {
			got, e := native.Read(ctx, ref.Key, ref.Version)
			if e != nil {
				t.Fatal(e)
			}
			if got.Until.After(until) {
				until = got.Until
			}
		}
		if d := time.Until(until.Add(100 * time.Millisecond)); d > 0 {
			time.Sleep(d)
		}
		start := make(chan struct{})
		requestDone := make(chan struct {
			r records.ExportSummary
			e error
		}, 1)
		disposeDone := make(chan error, 1)
		go func() {
			<-start
			r, e := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: "conc-09-export", Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "disposal versus snapshot"}})
			requestDone <- struct {
				r records.ExportSummary
				e error
			}{r, e}
		}()
		go func() {
			<-start
			if _, e := h.rs.Release(ctx, requester, hold.ID, "concurrent disposal"); e != nil {
				disposeDone <- e
				return
			}
			if _, e := rs.Sweep(ctx, requester); e != nil {
				disposeDone <- e
				return
			}
			state, e := rs.Store.BeginPurge(ctx, disposer, f.turn, nil)
			if e != nil || state != "purging" {
				disposeDone <- fmt.Errorf("begin purge %s: %v", state, e)
				return
			}
			out, _, e := rs.FinishPurge(ctx, &disposer, f.turn)
			if e != nil || out != "disposed" {
				disposeDone <- fmt.Errorf("finish purge %s: %v", out, e)
				return
			}
			disposeDone <- nil
		}()
		close(start)
		result := <-requestDone
		if e := <-disposeDone; e != nil {
			t.Fatal(e)
		}
		if result.e == nil {
			var snap records.ExportSnapshot
			if e := json.Unmarshal(result.r.Snapshot, &snap); e != nil {
				t.Fatal(e)
			}
			if len(snap.Records) != 1 || snap.Records[0].TurnID != f.turn || snap.Records[0].State != records.ItemActive || snap.Records[0].Classification != "complete" {
				t.Fatalf("snapshot mixed disposal boundary: %+v", snap.Records)
			}
			if _, e := h.ex.Approve(ctx, reviewer, result.r.ID, result.r.SnapshotDigest); e == nil {
				t.Fatal("approval accepted post-snapshot disposal epoch")
			}
		} else {
			t.Logf("request failed closed against concurrent disposal: %v", result.e)
		}
		assertNoPackage(t, "conc-09-export")
	})
	t.Run("CONC-10-disposal-vs-generation", func(t *testing.T) {
		f := fresh("10")
		hold := place(f, "conc-10-hold")
		r := request(f, "conc-10-export")
		approved(r)
		if _, e := h.rs.Release(ctx, requester, hold.ID, "allow disposal race"); e != nil {
			t.Fatal(e)
		}
		var until time.Time
		for _, ref := range f.refs {
			got, e := native.Read(ctx, ref.Key, ref.Version)
			if e != nil {
				t.Fatal(e)
			}
			if got.Until.After(until) {
				until = got.Until
			}
		}
		if d := time.Until(until.Add(100 * time.Millisecond)); d > 0 {
			time.Sleep(d)
		}
		if _, e := rs.Sweep(ctx, requester); e != nil {
			t.Fatal(e)
		}
		if state, e := rs.Store.BeginPurge(ctx, disposer, f.turn, nil); e != nil || state != "purging" {
			t.Fatalf("begin purge: %s %v", state, e)
		}
		_, check := rs.ExportSnapshotCallbacks(requester.TenantID, requester.UserID)
		_, _, e := rs.Store.BeginExport(ctx, requester, requester.TenantID, r.ID, time.Minute, check)
		if e == nil {
			t.Fatal("begin-export unexpectedly accepted a disposed lifecycle snapshot")
		}
		if _, e := h.ex.Generate(ctx, requester, r.ID); e == nil {
			t.Fatal("generation accepted disposal state change")
		}
		assertNoPackage(t, r.ID)
	})
	t.Run("CONC-11-overlapping-holds", func(t *testing.T) {
		f := fresh("11")
		a := place(f, "conc-11-hold-a")
		place(f, "conc-11-hold-b")
		r := request(f, "conc-11-export")
		var snap records.ExportSnapshot
		if e := json.Unmarshal(r.Snapshot, &snap); e != nil {
			t.Fatal(e)
		}
		if len(snap.HoldIDs) != 2 {
			t.Fatalf("snapshot hold IDs=%v", snap.HoldIDs)
		}
		approved(r)
		if _, e := h.rs.Release(ctx, requester, a.ID, "release one overlap"); e != nil {
			t.Fatal(e)
		}
		still, _, e := rs.ItemHeld(ctx, requester, f.turn)
		if e != nil || !still {
			t.Fatalf("second hold not authoritative: held=%v err=%v", still, e)
		}
		if _, e := h.ex.Generate(ctx, requester, r.ID); e == nil {
			t.Fatal("stale overlapping-hold snapshot generated after epoch change")
		}
		assertNoPackage(t, r.ID)
		r = request(f, "conc-11-export-after-release")
		approved(r)
		if _, e := h.ex.Generate(ctx, requester, r.ID); e != nil {
			t.Fatalf("remaining hold could not authorize a fresh export: %v", e)
		}
		cancelExport(r.ID)
	})
	t.Run("CONC-12-cross-matter-shared-version-disposal", func(t *testing.T) {
		a := fresh("12a")
		bfix := h.capture("12b", "content 12a")
		if a.matter == bfix.matter {
			t.Fatal("fixtures share matter")
		}
		shared := evidence.VersionRef{}
		for _, x := range a.refs {
			for _, y := range bfix.refs {
				if x == y && strings.Contains(x.Key, "/objects/") {
					shared = x
				}
			}
		}
		if shared.Version == "" {
			t.Fatalf("fixtures lack shared exact object version; A=%+v B=%+v", a.refs, bfix.refs)
		}
		var until time.Time
		for _, f := range []c08ConcFixture{a, bfix} {
			for _, ref := range f.refs {
				got, e := native.Read(ctx, ref.Key, ref.Version)
				if e != nil {
					t.Fatal(e)
				}
				if got.Until.After(until) {
					until = got.Until
				}
			}
		}
		if d := time.Until(until.Add(100 * time.Millisecond)); d > 0 {
			time.Sleep(d)
		}
		if _, e := rs.Sweep(ctx, requester); e != nil {
			t.Fatal(e)
		}
		for _, id := range []string{a.turn, bfix.turn} {
			if state, e := rs.Store.BeginPurge(ctx, disposer, id, nil); e != nil || state != "purging" {
				t.Fatalf("begin %s: %s %v", id, state, e)
			}
		}
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		for _, id := range []string{a.turn, bfix.turn} {
			wg.Add(1)
			go func(turn string) {
				defer wg.Done()
				out, _, e := rs.FinishPurge(ctx, &disposer, turn)
				if e != nil || out != "disposed" {
					errs <- fmt.Errorf("finish %s: %s: %v", turn, out, e)
				}
			}(id)
		}
		wg.Wait()
		close(errs)
		for e := range errs {
			t.Fatal(e)
		}
		plans := map[string]map[evidence.VersionRef]string{}
		for _, turn := range []string{a.turn, bfix.turn} {
			rows, e := rs.Store.PlanOf(ctx, requester.TenantID, turn)
			if e != nil {
				t.Fatal(e)
			}
			plans[turn] = map[evidence.VersionRef]string{}
			for _, row := range rows {
				plans[turn][evidence.VersionRef{Key: row.Key, Version: row.Version}] = row.Disposition
			}
		}
		if !((plans[a.turn][shared] == records.OutcomeRetainedShared && plans[bfix.turn][shared] == records.OutcomeDeleted) || (plans[bfix.turn][shared] == records.OutcomeRetainedShared && plans[a.turn][shared] == records.OutcomeDeleted)) {
			t.Fatalf("concurrent disposal did not serialize shared disposition: A=%q B=%q", plans[a.turn][shared], plans[bfix.turn][shared])
		}
		if e := native.Head(ctx, shared.Key, shared.Version); !errors.Is(e, s3transport.ErrObjectAbsent) {
			t.Fatalf("shared physical version not deleted: %v", e)
		}
		for _, f := range []c08ConcFixture{a, bfix} {
			t.Logf("post-disposal export candidate turn=%s matter=%s shared-disposition=%s", f.turn, f.matter, plans[f.turn][shared])
			hold, he := rs.Place(ctx, requester, records.Scope{MatterID: f.matter, CustodianIDs: []string{custodian.UserID}}, "synthetic historical gap hold", "conc-12-hold-"+f.turn)
			if he != nil || hold.State != records.HoldEffective {
				t.Fatalf("post-disposal hold for %s: hold=%+v err=%v", f.turn, hold, he)
			}
			r, re := h.ex.Request(ctx, requester, records.NewExportRequest{RequestID: "conc-12-export-" + f.turn, Intent: records.ExportIntent{ProjectID: f.project, MatterID: f.matter, CustodianIDs: []string{custodian.UserID}, WindowStart: started.UTC().Add(-time.Second), WindowEnd: time.Now().UTC(), Reason: "synthetic historical gap"}})
			if re != nil {
				t.Fatalf("post-disposal export request for %s: %v", f.turn, re)
			}
			var snap records.ExportSnapshot
			if e := json.Unmarshal(r.Snapshot, &snap); e != nil {
				t.Fatal(e)
			}
			if len(snap.Records) != 1 || snap.Records[0].TurnID != f.turn || snap.Records[0].State != records.ItemDisposed {
				t.Fatalf("bad post-disposal snapshot: %+v", snap.Records)
			}
			found := false
			for _, sv := range snap.Records[0].RetainedShared {
				if sv.Key == shared.Key && sv.Version == shared.Version && sv.Disposition == records.OutcomeRetainedShared {
					found = true
				}
			}
			if f.turn == a.turn && plans[a.turn][shared] == records.OutcomeRetainedShared && !found {
				t.Fatal("retained_shared attribution missing")
			}
			if f.turn == bfix.turn && plans[bfix.turn][shared] == records.OutcomeRetainedShared && !found {
				t.Fatal("retained_shared attribution missing")
			}
			if plans[f.turn][shared] == records.OutcomeDeleted {
				missing := false
				for _, mv := range snap.Records[0].Missing {
					if mv.Key == shared.Key && mv.Version == shared.Version && mv.Disposition == records.OutcomeDeleted {
						missing = true
					}
				}
				if !missing {
					t.Fatalf("deleted shared version not represented as missing in %s: %+v", f.turn, snap.Records[0].Missing)
				}
			}
			approved(r)
			if _, e := h.ex.Generate(ctx, requester, r.ID); e != nil {
				t.Fatalf("historical gap generation: %v", e)
			}
			delivery, e := h.ex.Retrieve(ctx, reviewer, r.ID)
			if e != nil {
				t.Fatalf("historical gap retrieval: %v", e)
			}
			var files map[string][]byte
			if e := json.Unmarshal(delivery.DirectoryJSON, &files); e != nil {
				t.Fatal(e)
			}
			verified, e := exportbundle.VerifyMembers(files, evidence.RetentionProfile, delivery.ManifestDigest)
			if e != nil {
				t.Fatal(e)
			}
			if verified.Status != exportbundle.DeclaredGap || verified.Turns != 0 || len(verified.Gaps) != 1 || verified.Gaps[0] != f.turn+":disposed" {
				t.Fatalf("incorrect disposed gap package: %+v", verified)
			}
			if len(files["events/"+f.turn+".jsonl"]) != 0 {
				t.Fatal("disposed record exported event bytes")
			}
			manifest := string(files["manifest.json"])
			if plans[f.turn][shared] == records.OutcomeRetainedShared && (!strings.Contains(manifest, "retained_shared_versions") || !strings.Contains(manifest, shared.Key) || !strings.Contains(manifest, shared.Version)) {
				t.Fatal("retained_shared attribution missing from package manifest")
			}
			if plans[f.turn][shared] == records.OutcomeDeleted && (!strings.Contains(manifest, "missing_versions") || !strings.Contains(manifest, shared.Key) || !strings.Contains(manifest, shared.Version)) {
				t.Fatal("deleted version missing from package manifest")
			}
			cancelExport(r.ID)
		}
	})
}
