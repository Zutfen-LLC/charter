//go:build retention_drill

package main

// TestC07ReviewCorrectionDrill runs the C07 independent-review correction
// interleavings against REAL PostgreSQL and the pinned SeaweedFS Object Lock
// profile: every preservation-critical race is reproduced with deterministic
// barriers on the real storage's native legal holds and versioned deletes,
// and asserted against the ACTUAL storage state (never logical flags).
//
// Interleavings (review findings 1-6):
//   R1 release-cleanup vs a newer hold's established native protection
//      (same matter; the stale cleanup cannot clear it),
//   R2 a real record with missing required versions blocks every effective
//      transition (placement, reestablishment, recovery),
//   R3 future matching work (admitted after activation) is cleared when the
//      final applicable hold is released and recovery converges,
//   R4 an interrupted conditional delete resumes from the durable disposal
//      plan without already-deleted enumeration metadata,
//   R5 an admitted, actively executing turn is never swept by ordinary
//      expiry (verified terminal capture state required),
//   R6 a concurrent capture cannot acquire a reference to an exact
//      content-addressed version between a disposal's shared-reference
//      snapshot and its deletion (the tenant protection fence).

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// slotSeqOf returns the numeric event-slot sequence of an
// <prefix>/events/<turn>/<seq> key, or "" when the key is not an event slot.
func slotSeqOf(key string) string {
	i := strings.LastIndex(key, "/")
	if i < 0 || i == len(key)-1 {
		return ""
	}
	tail := key[i+1:]
	if tail == "" || !isNumeric(tail) {
		return ""
	}
	return tail
}

func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func TestC07ReviewCorrectionDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	absent := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s not set", name)
		}
		return v
	}
	c := config.Load()
	if c.EvidenceBackend != config.EvidenceBackendRetentionS3 || c.RetentionS3.RecordsAccessKey == "" || c.RetentionS3.RecordsSecretFile == "" {
		t.Fatal("review drill requires the retained profile with the records-scoped storage credential")
	}
	must(validateLabConfig(c.Addr, c.RetentionS3))
	must(validateSyntheticDatabases(c))
	ds := absent("CHARTER_DRILL_OWNER_DSN")
	_, err := labDSN(ds)
	must(err)
	owner, err := pgxpool.New(ctx, ds)
	must(err)
	defer owner.Close()
	must(owner.Ping(ctx))
	root := absent("CHARTER_DRILL_OUTPUT")
	must(os.MkdirAll(root, 0700))
	dump := func(name string, x any) {
		t.Helper()
		b, e := json.MarshalIndent(x, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(root, name), append(b, '\n'), 0600))
	}
	sc := c.RetentionS3
	seedKey, err := hex.DecodeString(sc.CommitKey)
	must(err)
	recordsSecret, err := sizedRead(sc.RecordsSecretFile, 1024, true)
	must(err)
	recordsClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(recordsSecret))})
	must(err)
	seedBytes, err := sizedRead(sc.SignerSeedFile, 128, true)
	must(err)
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedBytes)))
	must(err)
	signer := ed25519.NewKeyFromSeed(seed)

	idp := syntheticidp.New("charter-retention-drill", "synthetic-rv")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-rv", "c07-review-drill")
	must(err)
	alice, err := st.CreateUser(ctx, tenant, "alice", "review custodian alice")
	must(err)
	bob, err := st.CreateUser(ctx, tenant, "bob", "review custodian bob")
	must(err)
	r1, err := st.CreateUser(ctx, tenant, "records-one", "review records officer one")
	must(err)
	r2, err := st.CreateUser(ctx, tenant, "records-two", "review records officer two")
	must(err)
	p1, err := st.CreateProject(ctx, tenant, "review matter project")
	must(err)
	p2, err := st.CreateProject(ctx, tenant, "review in-flight project")
	must(err)
	p3, err := st.CreateProject(ctx, tenant, "review future-work project")
	must(err)
	var matter1, matter2, matter3 string
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p1).Scan(&matter1))
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p2).Scan(&matter2))
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p3).Scan(&matter3))
	must(st.SeedMember(ctx, tenant, p1, alice))
	must(st.SeedMember(ctx, tenant, p2, bob))
	must(st.SeedMember(ctx, tenant, p3, alice))
	must(st.SeedRole(ctx, tenant, r1, store.RoleRecordsOfficer))
	must(st.SeedRole(ctx, tenant, r2, store.RoleRecordsOfficer))
	officer1 := store.Principal{TenantID: tenant, UserID: r1, Roles: map[string]bool{store.RoleRecordsOfficer: true}}
	officer2 := store.Principal{TenantID: tenant, UserID: r2, Roles: map[string]bool{store.RoleRecordsOfficer: true}}

	// Drill-owned deployment namespace with the shortest writable retention
	// horizon so disposal is permitted by real storage enforcement within a
	// bounded drill (same boundary the integrated C07 drill documents).
	deployment := sc.Deployment + "-c07r"
	evPool, err := pgxpool.New(ctx, os.Getenv("CHARTER_EVIDENCE_DATABASE_URL"))
	must(err)
	defer evPool.Close()
	seedFence, err := (evidence.PG{DB: evPool}).AcquireFence(ctx)
	must(err)
	writeClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(recordsSecret))})
	must(err)
	seedStarted := time.Now()
	writeBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: writeClient, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	svc := recordsServiceFor(owner, writeBackend, recordsClient)
	// The recorder carries the lifecycle guard: admissions, appends and
	// object staging acquire the tenant protection fence (finding 6B).
	recorder := &evidence.Recorder{Backend: writeBackend, Fence: seedFence, Lifecycle: svc, Logf: func(f string, a ...any) {
		t.Logf("recorder: "+f, a...)
	},
		Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
			return evidence.Decision{Allow: true, PolicyVersion: "c07-review-drill", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "seed", ModelID: "det-a"}}, nil
		}}
	seedTurn := func(custodian, project, matter, input string) string {
		t.Helper()
		res, err := recorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: project, MatterID: matter, CustodianID: custodian,
			IdempotencyKey: "c07r-" + input, Input: []byte(input),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("review output " + input)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		return res.TurnID
	}
	// Fast lifecycle policy: retention 1s, no grace.
	if _, err := owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id, retention_seconds, grace_seconds, set_by) VALUES ($1, 1, 0, $2) ON CONFLICT (tenant_id) DO UPDATE SET retention_seconds=1, grace_seconds=0`, tenant, r1); err != nil {
		t.Fatal(err)
	}
	itemState := func(turn string) string {
		t.Helper()
		items, err := svc.Store.Items(ctx, officer1)
		must(err)
		for _, it := range items {
			if it.TurnID == turn {
				return it.State
			}
		}
		return ""
	}
	waitLockOrState := func(idem string, wantState string) {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			var state *string
			if err := owner.QueryRow(ctx, `SELECT state FROM holds WHERE idempotency_key=$1`, idem).Scan(&state); err == nil && state != nil && *state == wantState {
				return
			}
			var waiters int
			if err := owner.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND datname = current_database()`).Scan(&waiters); err == nil && waiters > 0 {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("placement %s neither reached %s nor blocked on the protection fence", idem, wantState)
	}

	// ---- Seed turns (all before the retention wait) ----
	r1Turn := seedTurn(alice, p1, matter1, "r1-shared-turn")
	r2Turn := seedTurn(alice, p1, matter1, "r2-uncovered-turn")
	r4Turn := seedTurn(alice, p1, matter1, "r4-partial-disposal")
	r6Turn := seedTurn(alice, p1, matter1, "r6-shared-input")
	refs1, err := writeBackend.TurnDisposalRefs(ctx, tenant, r1Turn)
	must(err)
	refs2, err := writeBackend.TurnDisposalRefs(ctx, tenant, r2Turn)
	must(err)
	refs4, err := writeBackend.TurnDisposalRefs(ctx, tenant, r4Turn)
	must(err)
	refs6, err := writeBackend.TurnDisposalRefs(ctx, tenant, r6Turn)
	must(err)
	dump("c07r-seed-turns.json", map[string]string{"r1": r1Turn, "r2": r2Turn, "r4": r4Turn, "r6": r6Turn})

	// ---- R6 (before the retention wait): concurrent capture vs disposal of
	// a shared exact version while its base retention is still active ----
	// On the real storage two guards overlap: content-addressed reuse
	// requires UNEXPIRED retention, and unexpired retention refuses the
	// delete (the storage-native invariant), while the tenant protection
	// fence serializes the capture's reference acquisition with the
	// disposal's delete phase. Both turns must keep verifiable evidence.
	time.Sleep(2 * time.Second) // lifecycle retention (1s) elapses
	if marked, err := svc.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	} else if marked == 0 {
		t.Fatal("R6: no disposal-eligible turn")
	}
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, r6Turn, func(context.Context, pgx.Tx, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("R6 begin: %s %v", outcome, err)
	}
	objPaused := make(chan struct{})
	objResume := make(chan struct{})
	var objOnce sync.Once
	svc.Hooks.BeforeStorageDelete = func(key, version string) {
		if strings.Contains(key, "/data/objects/") {
			objOnce.Do(func() {
				close(objPaused)
				<-objResume
			})
		}
	}
	disposalDone := make(chan error, 1)
	go func() {
		_, _, err := svc.FinishPurge(ctx, &officer2, r6Turn)
		disposalDone <- err
	}()
	<-objPaused
	// T2: a concurrent capture of the SAME content (the same
	// content-addressed object version) through the real recorder. Its
	// admission is fenced out until the disposal's delete phase completes.
	t2model := make(chan struct{})
	t2proceed := make(chan struct{})
	t2done := make(chan error, 1)
	var t2Turn atomic.Value
	go func() {
		res, err := recorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: p1, MatterID: matter1, CustodianID: alice,
			IdempotencyKey: "c07r-r6-t2", Input: []byte("r6-shared-input"),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			close(t2model)
			<-t2proceed
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("review output r6-shared-input")}, nil
		}, func(context.Context) error { return nil })
		if err == nil {
			t2Turn.Store(res.TurnID)
		}
		t2done <- err
	}()
	admittedOrFenced := make(chan struct{})
	go func() {
		select {
		case <-t2model:
			// T2's admission completed during the frozen disposal.
		case <-time.After(3 * time.Second):
			// bounded fallback: T2 is blocked on the protection fence.
		}
		close(admittedOrFenced)
	}()
	<-admittedOrFenced
	close(objResume)
	disposalErr := <-disposalDone
	if !errors.Is(disposalErr, records.ErrBlockedStorage) {
		t.Fatalf("R6: disposal within active base retention must be honestly blocked, got %v", disposalErr)
	}
	close(t2proceed)
	must(<-t2done)
	t2 := t2Turn.Load().(string)
	svc.Hooks.BeforeStorageDelete = nil
	// THE invariant: BOTH turns keep verifiable evidence chains - nothing
	// was deleted (the storage refused while retention is active) and the
	// capture's references are intact.
	for _, turn := range []string{r6Turn, t2} {
		events, err := writeBackend.Load(ctx, tenant, turn)
		must(err)
		if _, err := writeBackend.LoadRetainedObjects(ctx, tenant, turn, events); err != nil {
			t.Fatalf("R6 FINDING 6B: %s evidence broken: %v", turn, err)
		}
	}
	for _, r := range refs6 {
		state, lerr := recordsClient.LegalHold(ctx, r.Key, r.Version)
		// A version whose legal hold was never set is reported by the
		// storage as an object-lock 404; the versions' presence was just
		// verified by the Load readback above.
		if lerr != nil && !errors.Is(lerr, s3transport.ErrObjectAbsent) {
			must(lerr)
		}
		if state == "ON" {
			t.Fatalf("R6: no hold was placed; legal hold must not be set: %s", r.Key)
		}
	}
	dump("c07r-r6-shared-reference.json", map[string]any{"disposal_turn": r6Turn, "captured_turn": t2, "disposal_outcome": "blocked_by_storage"})

	// ---- The storage retention horizon passes for the seed versions ----
	if wait := 75*time.Second - time.Since(seedStarted); wait > 0 {
		time.Sleep(wait)
	}

	// ---- R1: release cleanup cannot clear a newer hold's protection ----
	h1, err := svc.Place(ctx, officer1, records.Scope{MatterID: matter1}, "R1 first hold", "c07r-h1")
	must(err)
	if h1.State != records.HoldEffective {
		t.Fatalf("R1: H1 not effective: %v", h1)
	}
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	svc.Hooks.StorageFault = func(stage string) error {
		if stage == "cleanup" {
			once.Do(func() {
				close(paused)
				<-resume
			})
		}
		return nil
	}
	releaseErr := make(chan error, 1)
	go func() {
		_, err := svc.Release(ctx, officer1, h1.ID, "R1 release")
		releaseErr <- err
	}()
	<-paused
	// The newer hold places while the stale cleanup is paused: at the
	// corrected head its establishment serializes on the protection fence.
	h2err := make(chan error, 1)
	var h2 atomic.Value
	go func() {
		hh, err := svc.Place(ctx, officer2, records.Scope{MatterID: matter1, CustodianIDs: []string{alice}}, "R1 second hold", "c07r-h2")
		if hh != nil {
			h2.Store(hh)
		}
		h2err <- err
	}()
	waitLockOrState("c07r-h2", records.HoldEffective)
	close(resume)
	must(<-releaseErr)
	must(<-h2err)
	h2v, _ := h2.Load().(*records.Hold)
	if h2v == nil || h2v.State != records.HoldEffective {
		t.Fatalf("R1: H2 state %v", h2v)
	}
	svc.Hooks.StorageFault = nil
	// THE invariant: an effective hold never loses required native
	// protection - verified against the ACTUAL storage state.
	for _, r := range refs1 {
		state, err := recordsClient.LegalHold(ctx, r.Key, r.Version)
		must(err)
		if state != "ON" {
			t.Fatalf("R1 FINDING 1: effective hold %s lost native protection on %s (storage reports %q)", h2v.ID, r.Key, state)
		}
	}
	dump("c07r-r1-release-race.json", map[string]any{"turn": r1Turn, "hold2": h2v.ID, "versions_verified_on": len(refs1)})
	if _, err := svc.Release(ctx, officer2, h2v.ID, "R1 final release"); err != nil {
		t.Fatal(err)
	}

	// ---- R2: missing required versions block every effective transition ----
	// Delete a mid-chain event slot: the turn stays enumerable from its
	// admission, but its exact version set is no longer verifiable (an
	// incomplete chain fails closed instead of truncating silently).
	// The event-slot keys are <prefix>/events/<turn>/<seq> (a bare numeric
	// sequence); the data events live under /data/events/ and do not break
	// the walk when deleted.
	slot2 := ""
	for _, r := range refs2 {
		if !strings.Contains(r.Key, "/events/"+r2Turn+"/") || strings.Contains(r.Key, "/data/") {
			continue
		}
		if tail := slotSeqOf(r.Key); tail != "" {
			slot2 = r.Key + "|" + r.Version
			break
		}
	}
	if slot2 == "" {
		t.Fatal("R2: no event-slot version found")
	}
	slotKey, slotVersion, _ := strings.Cut(slot2, "|")
	must(recordsClient.DeleteVersion(ctx, slotKey, slotVersion))
	h, err := svc.Store.PlaceHold(ctx, officer1, records.Scope{MatterID: matter1}, "R2 hold", "c07r-h2u")
	must(err)
	// A pending hold recovered with an uncovered record must NOT become
	// effective (the transition refuses it; the fence stands).
	if err := svc.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	after, err := svc.Store.GetHold(ctx, officer1, h.ID)
	must(err)
	if after.State == records.HoldEffective {
		t.Fatalf("R2 FINDING 2: recovery acknowledged a hold as effective while uncovered records exist (%d)", len(after.Report.Uncovered))
	}
	if len(after.Report.Uncovered) == 0 {
		t.Fatal("R2: the uncovered record must be reported")
	}
	// Scope-change reestablishment refuses it too.
	changed, err := svc.Store.ChangeScope(ctx, officer1, h.ID, records.Scope{MatterID: matter1, CustodianIDs: []string{alice}}, "R2 narrow")
	must(err)
	if _, err := svc.Reestablish(ctx, changed); err == nil {
		t.Fatal("R2: reestablishment of a hold with uncovered records must refuse the effective transition")
	}
	after2, err := svc.Store.GetHold(ctx, officer1, h.ID)
	must(err)
	if after2.State == records.HoldEffective {
		t.Fatal("R2 FINDING 2: reestablishment acknowledged effectiveness with uncovered records")
	}
	dump("c07r-r2-uncovered.json", map[string]any{"turn": r2Turn, "state": after2.State, "uncovered": after2.Report.Uncovered})
	if _, err := svc.Release(ctx, officer1, h.ID, "R2 release"); err != nil {
		t.Fatal(err)
	}

	// ---- R0: new captures coexist with retention-expired evidence ----
	// The seed turns' storage retention has expired by now; the namespace
	// still admits and appends new turns (the serving read and append
	// verify their OWN chains' durability, never unrelated expired
	// admissions).
	if _, err := writeBackend.PutObject(ctx, tenant, []byte("r0-unique-content")); err != nil {
		t.Fatalf("R0 object stage: %v", err)
	}
	if _, err := recorder.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: p2, MatterID: matter2, CustodianID: bob,
		IdempotencyKey: "c07r-r0-coexist", Input: []byte("r0 coexistence input"),
	}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("r0 output")}, nil
	}, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("R0 FINDING (coexistence): capture after other turns' retention expired: %v", err)
	}

	// ---- R3: future matching work is cleared when the final hold releases ----
	// (Its own matter: R2 deliberately left an uncovered turn in matter1,
	// and a hold over that matter correctly refuses to become effective.)
	h3, err := svc.Place(ctx, officer1, records.Scope{MatterID: matter3}, "R3 hold", "c07r-h3")
	must(err)
	if h3.State != records.HoldEffective {
		t.Fatalf("R3: H3 not effective: %v", h3)
	}
	// New matching work captured through the real recorder after activation
	// (the guard protects it and claims it durably).
	r3Turn := seedTurn(alice, p3, matter3, "r3-future-work")
	refs3, err := writeBackend.TurnDisposalRefs(ctx, tenant, r3Turn)
	must(err)
	for _, r := range refs3 {
		state, err := recordsClient.LegalHold(ctx, r.Key, r.Version)
		must(err)
		if state != "ON" {
			t.Fatalf("R3: future work not protected while held: %s is %q", r.Key, state)
		}
	}
	if _, err := svc.Release(ctx, officer1, h3.ID, "R3 release"); err != nil {
		t.Fatal(err)
	}
	must(svc.Recover(ctx))
	for _, r := range refs3 {
		state, err := recordsClient.LegalHold(ctx, r.Key, r.Version)
		must(err)
		if state == "ON" {
			t.Fatalf("R3 FINDING 3A: post-activation version %s leaked permanent protection after the final applicable release", r.Key)
		}
	}
	dump("c07r-r3-future-work.json", map[string]any{"turn": r3Turn, "versions_cleared": len(refs3)})

	// ---- R4: interrupted delete resumes from the durable plan ----
	if marked, err := svc.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	} else if marked == 0 {
		// The R4 turn may already be disposal_pending from the R6 sweep.
		if s := itemState(r4Turn); s != records.ItemDisposalPending {
			t.Fatalf("R4: turn not eligible: %q", s)
		}
	}
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, r4Turn, func(context.Context, pgx.Tx, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("R4 begin: %s %v", outcome, err)
	}
	// Phase A only (the plan commits, no delete runs), then the FIRST
	// version's delete commits at the storage while the delete transaction
	// is "lost" - the interrupted-acknowledgment crash window.
	outcome := ""
	must(svc.Store.FinishPurgePlanTx(ctx, &officer2, tenant, r4Turn, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return writeBackend.TurnDisposalRefs(ctx, tenant, r4Turn)
	}, &outcome))
	must(recordsClient.DeleteVersion(ctx, refs4[0].Key, refs4[0].Version))
	// Recovery completes the disposal from the plan WITHOUT the deleted
	// enumeration root, and every exact version receives a disposition.
	must(svc.Recover(ctx))
	if s := itemState(r4Turn); s != records.ItemDisposed {
		o, _, ferr := svc.FinishPurge(ctx, &officer2, r4Turn)
		t.Fatalf("R4 FINDING 5: interrupted disposal did not converge from the plan: state %q; direct finish: %s err=%v", s, o, ferr)
	}
	plan, err := svc.Store.PlanOf(ctx, tenant, r4Turn)
	must(err)
	if len(plan) != len(refs4) {
		t.Fatalf("R4: plan covers %d of %d exact versions", len(plan), len(refs4))
	}
	for _, row := range plan {
		if row.Disposition != "deleted" && row.Disposition != "absent" {
			t.Fatalf("R4: version %s lacks a verified disposition: %q", row.Key, row.Disposition)
		}
	}
	dump("c07r-r4-partial-disposal.json", map[string]any{"turn": r4Turn, "plan": plan})

	// ---- R5: an in-flight capture is never swept ----
	admitted := make(chan struct{})
	proceed := make(chan struct{})
	r5err := make(chan error, 1)
	var r5Turn atomic.Value
	go func() {
		res, err := recorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: p2, MatterID: matter2, CustodianID: bob,
			IdempotencyKey: "c07r-r5-inflight", Input: []byte("r5 in-flight input"),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			close(admitted)
			<-proceed
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("r5 output")}, nil
		}, func(context.Context) error { return nil })
		if err == nil {
			r5Turn.Store(res.TurnID)
		}
		r5err <- err
	}()
	<-admitted
	time.Sleep(1500 * time.Millisecond) // lifecycle retention (1s) elapses while in flight
	if marked, err := svc.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	} else if marked != 0 {
		t.Fatalf("R5 FINDING 6A: an admitted, actively executing turn was swept (%d items marked)", marked)
	}
	r5pending := fmt.Sprint(r5Turn.Load())
	if s := itemState(r5pending); s != "" && s != "active" {
		t.Fatalf("R5: in-flight turn item state %q", s)
	}
	close(proceed)
	must(<-r5err)
	r5 := r5Turn.Load().(string)
	if terminal, err := writeBackend.TurnTerminal(ctx, tenant, r5); err != nil || !terminal {
		t.Fatalf("R5: completed turn must verify terminal: %v %v", terminal, err)
	}
	time.Sleep(1100 * time.Millisecond)
	if marked, err := svc.Sweep(ctx, officer1); err != nil || marked == 0 {
		t.Fatalf("R5: terminal expired turn must be eligible: %d %v", marked, err)
	}
	if s := itemState(r5); s != records.ItemDisposalPending {
		t.Fatalf("R5: terminal expired turn must be marked: %q", s)
	}
	dump("c07r-r5-terminal.json", map[string]any{"turn": r5, "state_after_terminal_sweep": itemState(r5)})

	// ---- End-to-end re-verification: the R6 concurrent capture's evidence
	// survives the whole drill, including the recovery that completed the
	// blocked disposal of its sharing partner (shared references are never
	// deleted while a non-disposed record requires them). The SERVING read
	// correctly fails closed once T2's retention horizon has passed (the
	// bytes are legitimately deletable then), so survival is asserted with
	// the disposal-tolerant enumeration: the full signed chain still
	// verifies and every exact version is still readable. ----
	refs2, rerr := writeBackend.TurnDisposalRefs(ctx, tenant, t2)
	if rerr != nil {
		t.Fatalf("R6 END-TO-END: concurrent capture's evidence chain broken after the full drill: %v", err)
	}
	if len(refs2) == 0 {
		t.Fatal("R6 END-TO-END: concurrent capture has no enumerable versions")
	}
	for _, r := range refs2 {
		if _, err := recordsClient.Read(ctx, r.Key, r.Version); err != nil {
			t.Fatalf("R6 END-TO-END: concurrent capture's version %s did not survive the full drill: %v", r.Key, err)
		}
	}
	dump("c07r-final-verification.json", map[string]any{"captured_turn": t2, "verified_versions": len(refs2)})

	seedFence.Release()
}
