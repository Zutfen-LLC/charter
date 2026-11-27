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
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

// TestC07Round2ReviewDrill is the real-storage qualification of the C07
// round-2 review corrections (the remaining preservation-critical findings
// of the independent re-review at 3f3d700). It runs against the pinned
// SeaweedFS 4.55 + PostgreSQL 16.16 composition inside the isolated
// no-network runner, with the records-scoped storage credential:
//
//	S1  hold coverage of a partially disposed record (finding 1): a
//	    matching record whose admission marker was deleted mid-disposal is
//	    covered from the durable disposal plan, the remaining bytes are
//	    natively protected, and their direct deletion after base retention
//	    is refused.
//	S2  capture protection for denied, provider-failed, release-vetoed,
//	    recovered and protection-failed turns under an effective hold
//	    (finding 2, cases A/C/D/E/F/G): every terminal path protects the
//	    complete published version set, and recovery repairs missing
//	    protection without a client replay.
//	S3  an unreadable sibling marker blocks the shared-version deletion
//	    (finding 3): the disposal is refused while a sibling's reference
//	    set is unknown, and converges once the read succeeds.
//	S4  verified plan restoration after partial deletion (finding 4): the
//	    exact-version inventory survives the restore, the loss is recorded,
//	    and a later release and disposal complete.
//	S5  hold placement idempotency is bound to the authorized placement
//	    intent (finding 5).
//	S6  a hold that becomes applicable between the claim and native phases
//	    of capture protection receives durable claims first (finding 6).
func TestC07Round2ReviewDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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
		t.Fatal("round-2 drill requires the retained profile with the records-scoped storage credential")
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

	idp := syntheticidp.New("charter-retention-drill", "synthetic-r2")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-r2", "c07-round2-drill")
	must(err)
	alice, err := st.CreateUser(ctx, tenant, "alice", "round2 custodian alice")
	must(err)
	bob, err := st.CreateUser(ctx, tenant, "bob", "round2 custodian bob")
	must(err)
	r1, err := st.CreateUser(ctx, tenant, "records-one", "round2 records officer one")
	must(err)
	r2, err := st.CreateUser(ctx, tenant, "records-two", "round2 records officer two")
	must(err)
	mkProject := func(label string) (string, string) {
		t.Helper()
		p, err := st.CreateProject(ctx, tenant, label)
		must(err)
		var matter string
		must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p).Scan(&matter))
		return p, matter
	}
	pS1, mS1 := mkProject("round2 S1 partial coverage")
	pS2, mS2 := mkProject("round2 S2 terminal protection")
	pS3, mS3 := mkProject("round2 S3 shared fallback")
	pS4, mS4 := mkProject("round2 S4 plan restoration")
	pS6, mS6 := mkProject("round2 S6 claims interleave")
	must(st.SeedMember(ctx, tenant, pS1, alice))
	must(st.SeedMember(ctx, tenant, pS2, bob))
	must(st.SeedMember(ctx, tenant, pS3, alice))
	must(st.SeedMember(ctx, tenant, pS4, alice))
	must(st.SeedMember(ctx, tenant, pS6, bob))
	must(st.SeedRole(ctx, tenant, r1, store.RoleRecordsOfficer))
	must(st.SeedRole(ctx, tenant, r2, store.RoleRecordsOfficer))
	officer1 := store.Principal{TenantID: tenant, UserID: r1, Roles: map[string]bool{store.RoleRecordsOfficer: true}}
	officer2 := store.Principal{TenantID: tenant, UserID: r2, Roles: map[string]bool{store.RoleRecordsOfficer: true}}

	evPool, err := pgxpool.New(ctx, os.Getenv("CHARTER_EVIDENCE_DATABASE_URL"))
	must(err)
	defer evPool.Close()
	seedFence, err := (evidence.PG{DB: evPool}).AcquireFence(ctx)
	must(err)
	writeClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(recordsSecret))})
	must(err)
	seedStarted := time.Now()
	deployment := sc.Deployment + "-c07r2"
	writeBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: writeClient, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	// The lifecycle service enumerates through a fault-injecting transport
	// so scenario S3 can make one sibling marker transiently unreadable.
	svcTransport := &faultInjectingTransport{inner: writeClient}
	svcBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: svcTransport, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	svc := recordsServiceFor(owner, svcBackend, recordsClient)

	deny := map[string]bool{}
	var denyMu sync.Mutex
	newRecorder := func(be evidence.Backend) *evidence.Recorder {
		return &evidence.Recorder{Backend: be, Fence: seedFence, Lifecycle: svc, Logf: func(f string, a ...any) {
			t.Logf("recorder: "+f, a...)
		}, Policy: func(_ context.Context, r evidence.Request) (evidence.Decision, error) {
			denyMu.Lock()
			d := deny[r.IdempotencyKey]
			denyMu.Unlock()
			if d {
				return evidence.Decision{Allow: false, Reason: "round2 policy denial", PolicyVersion: "round2"}, nil
			}
			return evidence.Decision{Allow: true, PolicyVersion: "round2", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "seed", ModelID: "det-a"}}, nil
		}}
	}
	recorder := newRecorder(writeBackend)
	seedTurn := func(project, matter, custodian, input string) string {
		t.Helper()
		res, err := recorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: project, MatterID: matter, CustodianID: custodian,
			IdempotencyKey: "c07r2-" + input, Input: []byte(input),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("round2 output " + input)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		return res.TurnID
	}
	// Fast lifecycle policy: retention 1s, no grace.
	_, err = owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id, retention_seconds, grace_seconds, set_by) VALUES ($1, 1, 0, $2) ON CONFLICT (tenant_id) DO UPDATE SET retention_seconds=1, grace_seconds=0`, tenant, r1)
	must(err)
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
	refsOf := func(turn string) []evidence.VersionRef {
		t.Helper()
		refs, err := writeBackend.TurnDisposalRefs(ctx, tenant, turn)
		must(err)
		return refs
	}
	allProtected := func(turn, tag string) {
		t.Helper()
		refs := refsOf(turn)
		if len(refs) == 0 {
			t.Fatalf("%s: turn %s has no enumerable versions", tag, turn)
		}
		for _, r := range refs {
			state, lerr := recordsClient.LegalHold(ctx, r.Key, r.Version)
			must(lerr)
			if state != "ON" {
				t.Fatalf("%s FINDING: version %s of turn %s is %q, want native legal hold ON", tag, r.Key, turn, state)
			}
		}
	}
	// matterTurns lists the tenant's live turns of one matter (the
	// authoritative inventory); scenario turns are resolved by diffing.
	matterTurns := func(matter string) []string {
		t.Helper()
		inv, ierr := svcBackend.InventoryTurns(ctx, tenant)
		must(ierr)
		var out []string
		for _, id := range inv {
			if id.MatterID == matter {
				out = append(out, id.TurnID)
			}
		}
		sort.Strings(out)
		return out
	}
	newTurn := func(before []string, after []string) string {
		t.Helper()
		seen := map[string]bool{}
		for _, id := range before {
			seen[id] = true
		}
		var delta []string
		for _, id := range after {
			if !seen[id] {
				delta = append(delta, id)
			}
		}
		if len(delta) != 1 {
			t.Fatalf("expected exactly one new turn, got %v (before %v after %v)", delta, before, after)
		}
		return delta[0]
	}

	// ---- Seed the scenario turns (before the retention wait) ----
	s1Turn := seedTurn(pS1, mS1, alice, "r2s1-partial-coverage")
	s3A := seedTurn(pS3, mS3, alice, "r2s3-shared-input")
	s3B := seedTurn(pS3, mS3, alice, "r2s3-shared-input") // same input bytes: one shared exact version
	s4Turn := seedTurn(pS4, mS4, alice, "r2s4-plan-restore")
	s6Turn := seedTurn(pS6, mS6, bob, "r2s6-claims-interleave")
	dump("c07r2-seed-turns.json", map[string]string{"s1": s1Turn, "s3a": s3A, "s3b": s3B, "s4": s4Turn, "s6": s6Turn})
	s1Refs := refsOf(s1Turn)
	s4Refs := refsOf(s4Turn)

	// ---- The storage retention horizon passes for the seed versions ----
	if wait := 75*time.Second - time.Since(seedStarted); wait > 0 {
		time.Sleep(wait)
	}

	// ---- S1: a partially disposed record is covered, not silent ----
	if marked, err := svc.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	} else if marked == 0 {
		t.Fatal("S1: no disposal-eligible turn")
	}
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, s1Turn, func(context.Context, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("S1 begin: %s %v", outcome, err)
	}
	outcome := ""
	must(svc.Store.FinishPurgePlanTx(ctx, &officer2, tenant, s1Turn, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return svcBackend.TurnDisposalRefs(ctx, tenant, s1Turn)
	}, &outcome))
	// The disposal is interrupted after the admission marker was physically
	// deleted while other required versions remain; the transaction never
	// commits dispositions, and the enumeration root is gone.
	must(recordsClient.DeleteVersion(ctx, s1Refs[0].Key, s1Refs[0].Version))
	// A matching hold is placed before any disposal recovery completes.
	s1Hold, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS1}, "S1 hold over a partially disposed record", "c07r2-s1")
	must(err)
	if s1Hold.State != records.HoldEffective {
		t.Fatalf("S1 FINDING 1: hold not effective over partially disposed coverage: %+v", s1Hold)
	}
	found, partial := false, false
	for _, it := range s1Hold.Report.Items {
		if it.TurnID == s1Turn {
			found = true
			partial = it.PartiallyDisposed
		}
	}
	if !found || !partial {
		t.Fatalf("S1 FINDING 1: the partially disposed record %s is not reported as such (found=%t partial=%t)", s1Turn, found, partial)
	}
	if len(s1Hold.Report.PartiallyDisposed) == 0 {
		t.Fatal("S1 FINDING 1: the partially disposed loss is not explicitly reported")
	}
	// The surviving versions are natively protected, and direct deletion
	// after base retention expiry is refused by the legal hold alone.
	for _, r := range s1Refs[1:] {
		state, lerr := recordsClient.LegalHold(ctx, r.Key, r.Version)
		if lerr != nil {
			// Dump the turn's current enumerable version set for diagnosis.
			if cur, cerr := writeBackend.TurnDisposalRefs(ctx, tenant, s1Turn); cerr == nil {
				var curRefs []string
				for _, c := range cur {
					curRefs = append(curRefs, c.Key+"@"+c.Version)
				}
				t.Logf("S1 diagnostic: current refs of %s: %v", s1Turn, curRefs)
			}
			var planRefs []string
			if rows, perr := svc.Store.PlanOf(ctx, tenant, s1Turn); perr == nil {
				for _, row := range rows {
					planRefs = append(planRefs, row.Key+"@"+row.Version+" disp="+row.Disposition)
				}
				t.Logf("S1 diagnostic: plan rows: %v", planRefs)
			}
			t.Fatalf("S1 FINDING 1: legal-hold probe failed for %s@%s: %v", r.Key, r.Version, lerr)
		}
		if state != "ON" {
			t.Fatalf("S1 FINDING 1: surviving version %s is %q, want ON", r.Key, state)
		}
		if derr := recordsClient.DeleteVersion(ctx, r.Key, r.Version); !errors.Is(derr, s3transport.ErrObjectProtected) {
			t.Fatalf("S1 FINDING 1: direct deletion of a protected surviving version must be refused, got %v", derr)
		}
	}
	dump("c07r2-s1-partial-coverage.json", map[string]any{"turn": s1Turn, "hold": s1Hold.ID, "report": s1Hold.Report})

	// ---- S3: an unreadable sibling marker blocks the shared deletion ----
	// B's slot marker becomes transiently unreadable for the lifecycle
	// service's enumerations.
	s3BSlot := ""
	for _, r := range refsOf(s3B) {
		if strings.Contains(r.Key, "/events/"+s3B+"/") && slotSeqOf(r.Key) != "" {
			s3BSlot = r.Key
			break
		}
	}
	if s3BSlot == "" {
		t.Fatal("S3: no sibling slot marker found")
	}
	svcTransport.mu.Lock()
	svcTransport.failReadKey = s3BSlot
	svcTransport.armed = true
	svcTransport.mu.Unlock()
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, s3A, func(context.Context, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("S3 begin: %s %v", outcome, err)
	}
	if _, _, err := svc.FinishPurge(ctx, &officer2, s3A); err == nil {
		t.Fatal("S3 FINDING 3: disposal was authorized while a sibling record's reference set was unknown")
	}
	if it := itemState(s3A); it == records.ItemDisposed {
		t.Fatal("S3 FINDING 3: disposal completed on unknown sibling references")
	}
	// Storage access is restored: the disposal converges and the shared
	// exact version survives it.
	svcTransport.mu.Lock()
	svcTransport.armed = false
	svcTransport.mu.Unlock()
	if _, _, err := svc.FinishPurge(ctx, &officer2, s3A); err != nil {
		t.Fatalf("S3: disposal must converge once the sibling enumerates: %v", err)
	}
	if it := itemState(s3A); it != records.ItemDisposed {
		t.Fatalf("S3: disposal did not converge: %s", it)
	}
	// B's full signed chain and every exact version survive.
	s3BRefs := refsOf(s3B)
	if len(s3BRefs) == 0 {
		t.Fatal("S3 FINDING 3: the intact sibling's evidence chain was broken")
	}
	for _, r := range s3BRefs {
		if _, rerr := recordsClient.Read(ctx, r.Key, r.Version); rerr != nil {
			t.Fatalf("S3 FINDING 3: the sibling's version %s did not survive the partner's disposal: %v", r.Key, rerr)
		}
	}
	dump("c07r2-s3-unknown-sibling.json", map[string]any{"disposal_turn": s3A, "sibling": s3B, "blocked_marker": s3BSlot})

	// ---- S4: verified plan restoration after partial deletion ----
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, s4Turn, func(context.Context, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("S4 begin: %s %v", outcome, err)
	}
	must(svc.Store.FinishPurgePlanTx(ctx, &officer2, tenant, s4Turn, func(ctx context.Context) ([]evidence.VersionRef, error) {
		return svcBackend.TurnDisposalRefs(ctx, tenant, s4Turn)
	}, &outcome))
	// The admission marker's delete commits at the storage; the disposition
	// transaction is lost.
	must(recordsClient.DeleteVersion(ctx, s4Refs[0].Key, s4Refs[0].Version))
	// A matching hold intervenes.
	s4Hold, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS4}, "S4 hold over a partially deleted record", "c07r2-s4")
	must(err)
	if s4Hold.State != records.HoldEffective {
		t.Fatalf("S4 FINDING 4: hold not effective: %+v", s4Hold)
	}
	// The stale purge completion must not destroy the exact-version
	// inventory, and the loss stays recorded in the plan.
	if o, _, ferr := svc.FinishPurge(ctx, &officer2, s4Turn); ferr == nil && o == "disposed" {
		t.Fatal("S4 FINDING 4: a held, partially deleted record completed disposal")
	}
	plan, err := svc.Store.PlanOf(ctx, tenant, s4Turn)
	must(err)
	if len(plan) != len(s4Refs) {
		t.Fatalf("S4 FINDING 4: the disposal plan was destroyed after a partial physical deletion (%d of %d versions inventoried)", len(plan), len(s4Refs))
	}
	missingDispositioned := false
	for _, row := range plan {
		if row.Key == s4Refs[0].Key && row.Version == s4Refs[0].Version && (row.Disposition == records.OutcomeAbsent || row.Disposition == records.OutcomeDeleted) {
			missingDispositioned = true
		}
	}
	if !missingDispositioned {
		t.Fatalf("S4 FINDING 4: the physically deleted version is not recorded as gone: %+v", plan)
	}
	if it := itemState(s4Turn); it != records.ItemActive {
		t.Fatalf("S4: restored item state %s, want active", it)
	}
	// Remaining bytes protected under the hold.
	allProtected(s4Turn, "S4")
	// Release the hold: the eventual disposal of the remaining bytes
	// completes from the plan.
	if _, err := svc.Release(ctx, officer1, s4Hold.ID, "S4 release"); err != nil {
		t.Fatal(err)
	}
	must(svc.Recover(ctx))
	time.Sleep(1100 * time.Millisecond)
	if _, err := svc.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	}
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, s4Turn, func(context.Context, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("S4 second begin: %s %v", outcome, err)
	}
	if o, _, ferr := svc.FinishPurge(ctx, &officer2, s4Turn); ferr != nil || o != "disposed" {
		t.Fatalf("S4 FINDING 4: the eventual disposal of the remaining bytes failed: %s %v", o, ferr)
	}
	plan, err = svc.Store.PlanOf(ctx, tenant, s4Turn)
	must(err)
	for _, row := range plan {
		if row.Disposition != records.OutcomeDeleted && row.Disposition != records.OutcomeAbsent && row.Disposition != records.OutcomeRetainedShared {
			t.Fatalf("S4 FINDING 4: version %s lacks a verified disposition: %q", row.Key, row.Disposition)
		}
	}
	dump("c07r2-s4-plan-restore.json", map[string]any{"turn": s4Turn, "plan": plan})

	// ---- S5: idempotency is bound to the authorized placement intent ----
	wStart := time.Now().Add(-24 * time.Hour)
	wEnd := time.Now().Add(24 * time.Hour)
	s5Key := "c07r2-s5"
	s5h, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS4, CustodianIDs: []string{alice}, WindowStart: &wStart, WindowEnd: &wEnd}, "S5 original authorized intent", s5Key)
	must(err)
	wEnd2 := wEnd.Add(time.Hour)
	for _, tc := range []struct {
		name   string
		scope  records.Scope
		reason string
		actor  store.Principal
	}{
		{"matter", records.Scope{MatterID: mS1, CustodianIDs: []string{alice}, WindowStart: &wStart, WindowEnd: &wEnd}, "S5 original authorized intent", officer1},
		{"custodian selection", records.Scope{MatterID: mS4, CustodianIDs: []string{bob}, WindowStart: &wStart, WindowEnd: &wEnd}, "S5 original authorized intent", officer1},
		{"time window", records.Scope{MatterID: mS4, CustodianIDs: []string{alice}, WindowStart: &wStart, WindowEnd: &wEnd2}, "S5 original authorized intent", officer1},
		{"reason", records.Scope{MatterID: mS4, CustodianIDs: []string{alice}, WindowStart: &wStart, WindowEnd: &wEnd}, "S5 a different reason", officer1},
		{"placing officer", records.Scope{MatterID: mS4, CustodianIDs: []string{alice}, WindowStart: &wStart, WindowEnd: &wEnd}, "S5 original authorized intent", officer2},
	} {
		if _, err := svc.Place(ctx, tc.actor, tc.scope, tc.reason, s5Key); err == nil {
			t.Fatalf("S5 FINDING 5: reusing the key with a changed %s acknowledged the unrelated existing hold", tc.name)
		} else if !errors.Is(err, records.ErrConflict) {
			t.Fatalf("S5 FINDING 5: changed %s must fail explicitly, got %v", tc.name, err)
		}
	}
	// The identical retry returns the original durable outcome.
	s5retry, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS4, CustodianIDs: []string{alice}, WindowStart: &wStart, WindowEnd: &wEnd}, "S5 original authorized intent", s5Key)
	must(err)
	if s5retry.ID != s5h.ID || s5retry.Epoch != s5h.Epoch || s5retry.PlacedBy != s5h.PlacedBy {
		t.Fatalf("S5 FINDING 5: identical retry returned a different durable outcome: %+v vs %+v", s5retry, s5h)
	}
	if _, err := svc.Release(ctx, officer1, s5h.ID, "S5 release"); err != nil {
		t.Fatal(err)
	}
	dump("c07r2-s5-idempotency.json", map[string]any{"hold": s5h.ID, "retries_rejected": 5})

	// ---- S6: a hold becoming applicable between the phases gets claims ----
	s6H1, err := svc.Store.PlaceHold(ctx, officer1, records.Scope{MatterID: mS6}, "S6 first applicable hold", "c07r2-s6-h1")
	must(err)
	var s6H2 *records.Hold
	var hookErr error
	svc.Hooks.BeforeApplicableReload = func() {
		svc.Hooks.BeforeApplicableReload = nil
		s6H2, hookErr = svc.Store.PlaceHold(ctx, officer2, records.Scope{MatterID: mS6}, "S6 concurrently applicable hold", "c07r2-s6-h2")
	}
	must(svc.EnsureProtected(ctx, tenant, mS6, bob, s6Turn, time.Now()))
	svc.Hooks.BeforeApplicableReload = nil
	must(hookErr)
	for _, hold := range []*records.Hold{s6H1, s6H2} {
		claims, cerr := svc.Store.ClaimsOfHold(ctx, hold.ID)
		must(cerr)
		claimed := map[string]bool{}
		for _, cl := range claims {
			claimed[cl.Key+"|"+cl.Version] = true
		}
		for _, r := range refsOf(s6Turn) {
			if !claimed[r.Key+"|"+r.Version] {
				t.Fatalf("S6 FINDING 6: hold %s received native protection without a durable claim on %s", hold.ID, r.Key)
			}
		}
	}
	allProtected(s6Turn, "S6")
	if _, err := svc.Release(ctx, officer1, s6H1.ID, "S6 release 1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Release(ctx, officer2, s6H2.ID, "S6 release 2"); err != nil {
		t.Fatal(err)
	}
	dump("c07r2-s6-claims.json", map[string]any{"turn": s6Turn, "hold1": s6H1.ID, "hold2": s6H2.ID})

	// ---- S2: every terminal path protects matching evidence ----
	s2Hold, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS2}, "S2 hold for terminal-path protection", "c07r2-s2")
	must(err)
	if s2Hold.State != records.HoldEffective {
		t.Fatalf("S2: hold not effective: %+v", s2Hold)
	}
	model := func(out string) func(context.Context, []byte) (evidence.ModelOutcome, error) {
		return func(context.Context, []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte(out)}, nil
		}
	}
	cases := map[string]string{}

	// A: policy-denied turn (terminal without any release path).
	before := matterTurns(mS2)
	denyMu.Lock()
	deny["c07r2-s2a"] = true
	denyMu.Unlock()
	if _, err := recorder.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: pS2, MatterID: mS2, CustodianID: bob,
		IdempotencyKey: "c07r2-s2a", Input: []byte("round2 denied input"),
	}, model("never"), func(context.Context) error { return nil }); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("S2A: want ErrDenied, got %v", err)
	}
	s2a := newTurn(before, matterTurns(mS2))
	allProtected(s2a, "S2A denied")
	cases["denied"] = s2a

	// C: provider failure with partial output and incurred usage.
	before = matterTurns(mS2)
	if _, err := recorder.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: pS2, MatterID: mS2, CustodianID: bob,
		IdempotencyKey: "c07r2-s2c", Input: []byte("round2 provider failure input"),
	}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: false, Output: []byte("round2 partial output")}, errors.New("provider stream error")
	}, func(context.Context) error { return nil }); err == nil || !evidence.IsProviderError(err) {
		t.Fatalf("S2C: want provider error, got %v", err)
	}
	s2c := newTurn(before, matterTurns(mS2))
	allProtected(s2c, "S2C provider failure")
	cases["provider_failure_partial_output"] = s2c

	// D: interruption before response release (release veto).
	before = matterTurns(mS2)
	if _, err := recorder.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: pS2, MatterID: mS2, CustodianID: bob,
		IdempotencyKey: "c07r2-s2d", Input: []byte("round2 release veto input"),
	}, model("round2 vetoed output"), func(context.Context) error { return errors.New("release denied") }); err == nil {
		t.Fatal("S2D: the vetoed release must fail")
	}
	s2d := newTurn(before, matterTurns(mS2))
	allProtected(s2d, "S2D release veto")
	cases["release_veto"] = s2d

	// E: recovery of an admitted open turn (the terminal append fails: the
	// crash-before-terminal window). Recovery resolves it, protects it and
	// never redispatches.
	before = matterTurns(mS2)
	faulty := &faultingRetentionBackend{b: writeBackend}
	faulty.setFault("turn_interrupted", true)
	faultyRec := newRecorder(faulty)
	dispatches := 0
	if _, err := faultyRec.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: pS2, MatterID: mS2, CustodianID: bob,
		IdempotencyKey: "c07r2-s2e", Input: []byte("round2 open turn input"),
	}, func(context.Context, []byte) (evidence.ModelOutcome, error) {
		dispatches++
		return evidence.ModelOutcome{Accepted: true, Complete: false, Output: []byte("round2 open partial")}, errors.New("provider failure")
	}, func(context.Context) error { return nil }); err == nil || !evidence.IsProviderError(err) {
		t.Fatalf("S2E: want provider error, got %v", err)
	}
	s2e := newTurn(before, matterTurns(mS2))
	if terminal, terr := writeBackend.TurnTerminal(ctx, tenant, s2e); terr != nil || terminal {
		t.Fatalf("S2E: the turn must still be open (terminal=%t err=%v)", terminal, terr)
	}
	faulty.setFault("", false)
	// Restart: the (clean) recorder and lifecycle service recover.
	if _, err := recorder.Recover(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	must(svc.Recover(ctx))
	if terminal, terr := writeBackend.TurnTerminal(ctx, tenant, s2e); terr != nil || !terminal {
		t.Fatalf("S2E: recovery did not terminalize the open turn (terminal=%t err=%v)", terminal, terr)
	}
	if dispatches != 1 {
		t.Fatalf("S2E FINDING 2: recovery redispatched the model (%d dispatches)", dispatches)
	}
	allProtected(s2e, "S2E recovered open turn")
	cases["recovered_open_turn"] = s2e

	// F: recovery completing a previously authorized but unfinalized
	// release (the terminal append fails after response_released).
	before = matterTurns(mS2)
	faulty.setFault("turn_completed", true)
	if _, err := faultyRec.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: pS2, MatterID: mS2, CustodianID: bob,
		IdempotencyKey: "c07r2-s2f", Input: []byte("round2 unfinalized release input"),
	}, model("round2 unfinalized output"), func(context.Context) error { return nil }); err == nil {
		t.Fatal("S2F: finalization must fail (recovery will complete it)")
	}
	s2f := newTurn(before, matterTurns(mS2))
	if terminal, terr := writeBackend.TurnTerminal(ctx, tenant, s2f); terr != nil || terminal {
		t.Fatalf("S2F: the turn must still be open after the failed finalization (terminal=%t err=%v)", terminal, terr)
	}
	faulty.setFault("", false)
	if _, err := recorder.Recover(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	must(svc.Recover(ctx))
	if terminal, terr := writeBackend.TurnTerminal(ctx, tenant, s2f); terr != nil || !terminal {
		t.Fatalf("S2F: recovery did not complete the authorized release (terminal=%t err=%v)", terminal, terr)
	}
	allProtected(s2f, "S2F recovered release")
	cases["recovered_unfinalized_release"] = s2f

	// G: protection failure after a terminal event, followed by restart
	// without client replay. The fault is armed from the release gate (the
	// last gate call before the terminal event), so the delivery-time
	// protection pass fails and the terminal versions stay unprotected.
	before = matterTurns(mS2)
	s2gStarted := time.Now()
	if _, err := recorder.Process(ctx, evidence.Request{
		TenantID: tenant, ProjectID: pS2, MatterID: mS2, CustodianID: bob,
		IdempotencyKey: "c07r2-s2g", Input: []byte("round2 protection failure input"),
	}, model("round2 withheld output"), func(context.Context) error {
		// Between the release-gate protection and response_released: the
		// NEXT protection pass (delivery, after the terminal event) fails.
		svc.Hooks.StorageFault = func(stage string) error {
			if stage == "protect" {
				svc.Hooks.StorageFault = nil
				return errors.New("injected delivery protection failure")
			}
			return nil
		}
		return nil
	}); err == nil {
		t.Fatal("S2G: the delivery-time protection failure must fail the turn closed")
	}
	svc.Hooks.StorageFault = nil
	s2g := newTurn(before, matterTurns(mS2))
	if terminal, terr := writeBackend.TurnTerminal(ctx, tenant, s2g); terr != nil || !terminal {
		t.Fatalf("S2G: the turn must be terminal (terminal=%t err=%v)", terminal, terr)
	}
	// Restart WITHOUT a client replay: the recorder has nothing open; the
	// lifecycle recovery repairs the effective hold's missing protection.
	if n, err := recorder.Recover(ctx, time.Time{}); err != nil || n != 0 {
		t.Fatalf("S2G: recovery must not touch terminal turns (n=%d err=%v)", n, err)
	}
	must(svc.Recover(ctx))
	allProtected(s2g, "S2G repaired after restart")
	cases["protection_failure_repaired_without_replay"] = s2g
	// Direct deletion of every version after ITS base retention expires is
	// refused by the legal hold alone.
	if wait := 75*time.Second - time.Since(s2gStarted); wait > 0 {
		time.Sleep(wait)
	}
	for _, r := range refsOf(s2g) {
		if derr := recordsClient.DeleteVersion(ctx, r.Key, r.Version); !errors.Is(derr, s3transport.ErrObjectProtected) {
			t.Fatalf("S2G FINDING 2: direct deletion after base retention expired must be refused by the hold, got %v", derr)
		}
	}
	dump("c07r2-s2-terminal-paths.json", map[string]any{"hold": s2Hold.ID, "cases": cases})

	if _, err := svc.Release(ctx, officer1, s2Hold.ID, "S2 release"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Release(ctx, officer1, s1Hold.ID, "S1 release"); err != nil {
		t.Fatal(err)
	}
	seedFence.Release()
}

// faultInjectingTransport wraps the storage transport with a transient
// single-key read failure for the lifecycle service's enumerations.
type faultInjectingTransport struct {
	inner interface {
		Bucket() string
		Create(context.Context, string, []byte, time.Time) (string, error)
		Read(ctx context.Context, key, version string) (s3transport.Version, error)
		Versions(context.Context, string) ([]s3transport.Ref, error)
	}
	mu          sync.Mutex
	failReadKey string
	armed       bool
}

func (t *faultInjectingTransport) Bucket() string { return t.inner.Bucket() }
func (t *faultInjectingTransport) Create(ctx context.Context, key string, data []byte, until time.Time) (string, error) {
	return t.inner.Create(ctx, key, data, until)
}
func (t *faultInjectingTransport) Versions(ctx context.Context, prefix string) ([]s3transport.Ref, error) {
	return t.inner.Versions(ctx, prefix)
}
func (t *faultInjectingTransport) Read(ctx context.Context, key, version string) (s3transport.Version, error) {
	t.mu.Lock()
	armed, fail := t.armed, t.failReadKey
	t.mu.Unlock()
	if armed && fail != "" && key == fail {
		return s3transport.Version{}, fmt.Errorf("injected transient read failure for %s", key)
	}
	return t.inner.Read(ctx, key, version)
}

// faultingRetentionBackend drops every append of one event type while
// armed, so a turn stays open (the crash-before-terminal window); the next
// recovery resolves it.
type faultingRetentionBackend struct {
	b     *evidence.RetentionBackend
	setMu sync.Mutex
	// failType and armed are read on the recorder's serialized append
	// path; setFault synchronizes them for the drill.
	failType string
	armed    bool
}

func (f *faultingRetentionBackend) setFault(typ string, arm bool) {
	f.setMu.Lock()
	f.failType, f.armed = typ, arm
	f.setMu.Unlock()
}

// Info/Admit/Append/... delegate to the retained backend; only Append
// injects.
func (f *faultingRetentionBackend) Info() evidence.BackendInfo { return f.b.Info() }
func (f *faultingRetentionBackend) Admit(ctx context.Context, a evidence.Admission, e evidence.Event, objs [][]byte) (evidence.AdmitResult, error) {
	return f.b.Admit(ctx, a, e, objs)
}
func (f *faultingRetentionBackend) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	typ, _ := e["type"].(string)
	f.setMu.Lock()
	fire := f.armed && typ == f.failType
	f.setMu.Unlock()
	if fire {
		return evidence.Receipt{}, errors.New("injected terminal append fault")
	}
	return f.b.Append(ctx, e)
}
func (f *faultingRetentionBackend) PutObject(ctx context.Context, tenant string, data []byte) (evidence.Receipt, error) {
	return f.b.PutObject(ctx, tenant, data)
}
func (f *faultingRetentionBackend) Load(ctx context.Context, tenant, turn string) ([]evidence.Event, error) {
	return f.b.Load(ctx, tenant, turn)
}
func (f *faultingRetentionBackend) Object(ctx context.Context, tenant, sha string) ([]byte, error) {
	return f.b.Object(ctx, tenant, sha)
}
func (f *faultingRetentionBackend) OpenTurns(ctx context.Context, before time.Time) ([]evidence.TurnRef, error) {
	return f.b.OpenTurns(ctx, before)
}
