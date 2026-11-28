//go:build retention_drill

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// TestC07Round3ReviewDrill is the real-storage qualification of the C07
// round-3 review corrections (the four findings of the independent
// re-review at 702bb2f). It runs against the pinned SeaweedFS 4.55 +
// PostgreSQL 16.16 composition inside the isolated no-network runner, with
// the records-scoped storage credential:
//
//	S1  two turns in different matters share one exact content-addressed
//	    input version referenced through their ADMISSION markers only; a
//	    chain gap (a deleted middle slot) on the surviving turn forces
//	    fallback enumeration without a disposal plan, and the disposal of
//	    the other turn must not delete the shared object version (finding
//	    1, cross-matter; the surviving admission evidence stays intact).
//	S1b the same reference-resolution defect exercised against native
//	    legal-hold removal: a REQUIRED (still held) record whose verified
//	    enumeration breaks (a duplicate version at one slot key) keeps the
//	    shared version's protection when the other hold releases (finding
//	    1), and both releases converge.
//	S2  a hold that becomes applicable between EnsureProtected's phases
//	    has its ownership claims DURABLY COMMITTED before the native
//	    mutation: a crash after SetLegalHold but before the phase-2 commit
//	    never leaves native protection ON with no committed owner (finding
//	    2), and the release converges.
//	S3  an interrupted disposal whose TERMINAL EVENT SLOT (S3a), TERMINAL
//	    EVENT DATA (S3b) or ADMISSION MARKER (S3c control) was deleted
//	    while other exact versions survive: the matching hold covers the
//	    survivors from the durable plan with the loss reported, and after
//	    release the ordinary sweep/begin/finish operations reach a
//	    verified disposition for every unshared surviving version (finding
//	    3); held and shared versions survive.
//	S4  recovery of an effective hold whose matching record's exact-version
//	    inventory is transiently unverifiable records the repair gap
//	    durably (repair_pending + an attributable audit row), never
//	    silently discarding it, and a subsequent recovery resolves it
//	    without erasing the historical evidence (finding 4).
func TestC07Round3ReviewDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
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
		t.Fatal("round-3 drill requires the retained profile with the records-scoped storage credential")
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

	idp := syntheticidp.New("charter-retention-drill", "synthetic-r3")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-r3", "c07-round3-drill")
	must(err)
	alice, err := st.CreateUser(ctx, tenant, "r3-alice", "round3 custodian alice")
	must(err)
	bob, err := st.CreateUser(ctx, tenant, "r3-bob", "round3 custodian bob")
	must(err)
	r1, err := st.CreateUser(ctx, tenant, "r3-records-one", "round3 records officer one")
	must(err)
	r2, err := st.CreateUser(ctx, tenant, "r3-records-two", "round3 records officer two")
	must(err)
	mkProject := func(label string) (string, string) {
		t.Helper()
		p, err := st.CreateProject(ctx, tenant, label)
		must(err)
		var matter string
		must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p).Scan(&matter))
		return p, matter
	}
	pS1, mS1 := mkProject("round3 S1 shared fallback")
	pS1bA, mS1bA := mkProject("round3 S1b release fence A")
	pS1bB, mS1bB := mkProject("round3 S1b release fence B")
	pS2, mS2 := mkProject("round3 S2 durable claims")
	pS3, mS3 := mkProject("round3 S3 terminality")
	pS3Shared, mS3Shared := mkProject("round3 S3 shared control")
	pS4, mS4 := mkProject("round3 S4 repair gap")
	must(st.SeedMember(ctx, tenant, pS1, alice))
	must(st.SeedMember(ctx, tenant, pS1bA, alice))
	must(st.SeedMember(ctx, tenant, pS1bB, bob))
	must(st.SeedMember(ctx, tenant, pS2, alice))
	must(st.SeedMember(ctx, tenant, pS3, alice))
	must(st.SeedMember(ctx, tenant, pS3Shared, alice))
	must(st.SeedMember(ctx, tenant, pS4, bob))
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
	deployment := sc.Deployment + "-c07r3"
	writeBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: writeClient, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	// The lifecycle service enumerates through a fault-injecting transport
	// so scenario S4 can make one turn's slot reads transiently fail.
	svcTransport := &faultInjectingTransport{inner: writeClient}
	svcBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: svcTransport, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	svc := recordsServiceFor(owner, svcBackend, recordsClient)

	recorder := &evidence.Recorder{Backend: writeBackend, Fence: seedFence, Lifecycle: svc, Logf: func(f string, a ...any) {
		t.Logf("recorder: "+f, a...)
	}, Policy: func(_ context.Context, r evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "round3", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "seed", ModelID: "det-a"}}, nil
	}}
	seedTurn := func(project, matter, custodian, label, input string) string {
		t.Helper()
		res, err := recorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: project, MatterID: matter, CustodianID: custodian,
			IdempotencyKey: "c07r3-" + label, Input: []byte(input),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("round3 output " + label)}, nil
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
	lowestSlot := func(refs []evidence.VersionRef) (string, string) {
		t.Helper()
		best, bestV, bestSeq := "", "", -1
		for _, r := range refs {
			if s := slotSeqOf(r.Key); s != "" {
				n, _ := strconv.Atoi(s)
				if bestSeq == -1 || n < bestSeq {
					best, bestV, bestSeq = r.Key, r.Version, n
				}
			}
		}
		if bestSeq < 0 {
			t.Fatal("no event slot found")
		}
		return best, bestV
	}
	terminalSlot := func(refs []evidence.VersionRef) (string, string) {
		t.Helper()
		best, bestV, bestSeq := "", "", -1
		for _, r := range refs {
			if s := slotSeqOf(r.Key); s != "" {
				n, _ := strconv.Atoi(s)
				if n > bestSeq {
					best, bestV, bestSeq = r.Key, r.Version, n
				}
			}
		}
		if bestSeq < 0 {
			t.Fatal("no event slot found")
		}
		return best, bestV
	}
	// eventDataOf decodes a slot marker's signed envelope and returns the
	// referenced event-data key/version.
	eventDataOf := func(key, version string) (string, string) {
		t.Helper()
		v, err := writeClient.Read(ctx, key, version)
		must(err)
		var env struct {
			Payload string `json:"payload"`
		}
		must(json.Unmarshal(v.Data, &env))
		var commit struct {
			Event struct {
				Key     string `json:"key"`
				Version string `json:"version"`
			} `json:"event"`
		}
		must(json.Unmarshal([]byte(env.Payload), &commit))
		if commit.Event.Key == "" {
			t.Fatalf("slot %s carries no event receipt", key)
		}
		return commit.Event.Key, commit.Event.Version
	}
	// sharedRefOfInput locates the content-addressed object version of the
	// given input bytes: the object key carries the sha256 digest, not the
	// bytes themselves.
	sharedRefOfInput := func(refs []evidence.VersionRef, input string) evidence.VersionRef {
		t.Helper()
		sum := sha256.Sum256([]byte(input))
		digest := hex.EncodeToString(sum[:])
		for _, r := range refs {
			if strings.Contains(r.Key, "/data/objects/") && strings.HasSuffix(r.Key, digest) {
				return r
			}
		}
		t.Fatalf("no shared object for input %q (digest %s) in %d refs", input, digest, len(refs))
		return evidence.VersionRef{}
	}
	gone := func(key, version string) bool {
		t.Helper()
		err := recordsClient.Head(ctx, key, version)
		return errors.Is(err, s3transport.ErrObjectAbsent)
	}

	// ---- Seed the scenario turns (before the retention wait) ----
	s1A := seedTurn(pS1, mS1, alice, "r3s1-a", "r3s1-shared-input")
	s1B := seedTurn(pS1, mS1, alice, "r3s1-b", "r3s1-shared-input") // same input bytes: one exact shared version, admission-only
	s1bC := seedTurn(pS1bA, mS1bA, alice, "r3s1b-c", "r3s1b-shared-input")
	s1bD := seedTurn(pS1bB, mS1bB, bob, "r3s1b-d", "r3s1b-shared-input")
	s2E := seedTurn(pS2, mS2, alice, "r3s2-e", "r3s2-input")
	s3F := seedTurn(pS3, mS3, alice, "r3s3-f", "r3s3-shared-input")
	s3F2 := seedTurn(pS3Shared, mS3Shared, alice, "r3s3-f2", "r3s3-shared-input") // shares the S3 object; stays live
	s3G := seedTurn(pS3, mS3, alice, "r3s3-g", "r3s3-g-input")
	s3H := seedTurn(pS3, mS3, alice, "r3s3-h", "r3s3-h-input")
	s4I := seedTurn(pS4, mS4, bob, "r3s4-i", "r3s4-input")
	dump("c07r3-seed-turns.json", map[string]string{
		"s1a": s1A, "s1b": s1B, "s1bc": s1bC, "s1bd": s1bD, "s2e": s2E,
		"s3f": s3F, "s3f2": s3F2, "s3g": s3G, "s3h": s3H, "s4i": s4I,
	})
	s1BRefs := refsOf(s1B)
	s1bDRefs := refsOf(s1bD)
	s3FRefs := refsOf(s3F)
	s3GRefs := refsOf(s3G)
	s3HRefs := refsOf(s3H)
	s2ERefs := refsOf(s2E)

	// ---- The storage retention horizon passes for the seed versions ----
	if wait := 75*time.Second - time.Since(seedStarted); wait > 0 {
		time.Sleep(wait)
	}

	// ---- S1: the admission-only shared object survives the sibling disposal ----
	// Break B's subsequent event chain: delete B's lowest event slot (a
	// hole with higher slots - including the terminal - surviving) without
	// any disposal plan for B.
	bSlot, bSlotV := lowestSlot(s1BRefs)
	must(recordsClient.DeleteVersion(ctx, bSlot, bSlotV))
	if _, err := writeBackend.TurnDisposalRefs(ctx, tenant, s1B); err == nil {
		t.Fatal("S1 setup: the chain-broken sibling still enumerates verified")
	}
	if marked, err := svc.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	} else if marked == 0 {
		t.Fatal("S1: no disposal-eligible turn")
	}
	if outcome, err := svc.Store.BeginPurge(ctx, officer2, s1A, func(context.Context, pgx.Tx, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("S1 begin: %s %v", outcome, err)
	}
	if _, _, err := svc.FinishPurge(ctx, &officer2, s1A); err != nil {
		t.Fatalf("S1: the disposal must converge: %v", err)
	}
	if it := itemState(s1A); it != records.ItemDisposed {
		t.Fatalf("S1: disposal did not complete: %s", it)
	}
	sharedS1 := sharedRefOfInput(s1BRefs, "r3s1-shared-input")
	if gone(sharedS1.Key, sharedS1.Version) {
		t.Fatalf("S1 FINDING 1: the shared admission-only object version was deleted by the sibling's disposal - the surviving record's admission evidence is destroyed")
	}
	// The surviving admission evidence is intact and readable.
	if v, err := recordsClient.Read(ctx, s1BRefs[0].Key, s1BRefs[0].Version); err != nil || len(v.Data) == 0 {
		t.Fatalf("S1 FINDING 1: the surviving record's admission marker did not survive: %v", err)
	}
	if v, err := writeClient.Read(ctx, s1BRefs[0].Key, s1BRefs[0].Version); err != nil || len(v.Data) == 0 {
		t.Fatalf("S1 FINDING 1: admission marker unreadable through the write transport: %v", err)
	}
	for _, r := range s1BRefs {
		if r.Key == bSlot {
			continue // the injected chain gap
		}
		if gone(r.Key, r.Version) {
			t.Fatalf("S1 FINDING 1: the surviving record's version %s was deleted by the partner's disposal", r.Key)
		}
	}
	dump("c07r3-s1-admission-shared.json", map[string]any{"disposal_turn": s1A, "sibling": s1B, "shared": sharedS1})

	// ---- S1b: a required record's admission-only reference blocks protection removal ----
	// Both holds established while both turns are intact (each claims the
	// shared version through its own admission).
	hC, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS1bA}, "S1b hold over the first shared reference", "c07r3-s1b-c")
	must(err)
	if hC.State != records.HoldEffective {
		t.Fatalf("S1b: hold C not effective: %+v", hC)
	}
	hD, err := svc.Place(ctx, officer2, records.Scope{MatterID: mS1bB}, "S1b hold over the admission-only reference", "c07r3-s1b-d")
	must(err)
	if hD.State != records.HoldEffective {
		t.Fatalf("S1b: hold D not effective: %+v", hD)
	}
	sharedS1b := sharedRefOfInput(s1bDRefs, "r3s1b-shared-input")
	if state, lerr := recordsClient.LegalHold(ctx, sharedS1b.Key, sharedS1b.Version); lerr != nil || state != "ON" {
		t.Fatalf("S1b setup: shared version not protected under both holds (state %q err %v)", state, lerr)
	}
	// Break D's verified enumeration WITHOUT deleting anything (its
	// versions are protected): a copied slot marker is published at the
	// NEXT, unused sequence (a new key, so the conditional create
	// succeeds). The verified walk refuses (the copied commit's sequence
	// and slot coordinates mismatch the key) while every existing slot
	// stays readable and the namespace fallback still enumerates the
	// admission-carried references.
	dSlot, dSlotV := terminalSlot(s1bDRefs)
	dSeq := slotSeqOf(dSlot)
	nextSeq, err := strconv.Atoi(dSeq)
	must(err)
	nextSeq++
	copiedKey := dSlot[:len(dSlot)-len(dSeq)] + strconv.Itoa(nextSeq)
	slotBytes, err := writeClient.Read(ctx, dSlot, dSlotV)
	must(err)
	_, err = writeClient.Create(ctx, copiedKey, slotBytes.Data, time.Now().Add(24*time.Hour))
	must(err)
	if _, err := writeBackend.TurnDisposalRefs(ctx, tenant, s1bD); err == nil {
		t.Fatal("S1b setup: the corrupted sibling still enumerates verified")
	}
	// H_C releases: the shared version's legal hold must survive, because
	// D - still held by the effective H_D - references it through its
	// admission marker (the fallback must resolve it).
	if _, err := svc.Release(ctx, officer1, hC.ID, "S1b release under an admission-only sibling reference"); err != nil {
		t.Fatal(err)
	}
	if state, lerr := recordsClient.LegalHold(ctx, sharedS1b.Key, sharedS1b.Version); lerr != nil || state != "ON" {
		t.Fatalf("S1b FINDING 1: native protection was removed from the shared version while a required record still references it through its admission marker (state %q err %v)", state, lerr)
	}
	if stored, gerr := svc.Store.GetHold(ctx, officer2, hD.ID); gerr != nil || stored.State != records.HoldEffective {
		t.Fatalf("S1b FINDING 1: the still-applicable hold must stay effective: %v %+v", gerr, stored)
	}
	// Both holds released: the protection converges (cleared - no owner
	// remains).
	if _, err := svc.Release(ctx, officer2, hD.ID, "S1b release 2"); err != nil {
		t.Fatal(err)
	}
	if state, lerr := recordsClient.LegalHold(ctx, sharedS1b.Key, sharedS1b.Version); lerr != nil || state != "OFF" {
		t.Fatalf("S1b: the shared version's protection did not converge after both releases (state %q err %v)", state, lerr)
	}
	dump("c07r3-s1b-protection-removal.json", map[string]any{"turn_c": s1bC, "turn_d": s1bD, "shared": sharedS1b, "corrupted_slot": dSlot})

	// ---- S2: newly applicable claims survive the native-mutation crash ----
	// No hold is applicable when EnsureProtected starts (the initially
	// empty set); one becomes applicable between the phases.
	var s2H2 *records.Hold
	var hookErr error
	svc.Hooks.BeforeApplicableReload = func() {
		svc.Hooks.BeforeApplicableReload = nil
		s2H2, hookErr = svc.Store.PlaceHold(ctx, officer2, records.Scope{MatterID: mS2}, "S2 concurrently applicable hold", "c07r3-s2-h2")
	}
	// Deterministic crash after the native mutation, before the phase-2
	// transaction commits.
	svc.Hooks.StorageFault = func(stage string) error {
		if stage == "readback" {
			svc.Hooks.StorageFault = nil
			return errors.New("injected crash after the native mutation")
		}
		return nil
	}
	if err := svc.EnsureProtected(ctx, tenant, mS2, alice, s2E, time.Now()); err == nil {
		t.Fatal("S2 setup: the injected crash must fail the protection pass")
	}
	svc.Hooks.StorageFault = nil
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	if s2H2 == nil {
		t.Fatal("S2 setup: the concurrent hold was not placed")
	}
	// H2 is released before any effective-hold repair can reconstruct
	// ownership: no version may keep native protection without a
	// committed owner.
	if _, err := svc.Release(ctx, officer2, s2H2.ID, "S2 release before repair"); err != nil {
		t.Fatal(err)
	}
	for _, r := range s2ERefs {
		if state, lerr := recordsClient.LegalHold(ctx, r.Key, r.Version); lerr == nil && state == "ON" {
			t.Fatalf("S2 FINDING 2: native protection left ON for %s with no committed ownership claim (the release could not converge it)", r.Key)
		}
	}
	var s2Claims int
	if err := owner.QueryRow(ctx, `SELECT count(*) FROM hold_version_claims WHERE hold_id=$1`, s2H2.ID).Scan(&s2Claims); err != nil {
		t.Fatal(err)
	}
	if s2Claims != 0 {
		t.Fatalf("S2 FINDING 2: %d claims remain after the released hold's convergence", s2Claims)
	}
	dump("c07r3-s2-durable-claims.json", map[string]any{"turn": s2E, "hold": s2H2.ID})

	// ---- S3: interrupted disposals resume after terminal-evidence loss ----
	resume := func(label, turn string, refs []evidence.VersionRef, wantMissing int, secondDelete func()) {
		t.Helper()
		if _, err := svc.Sweep(ctx, officer1); err != nil {
			t.Fatal(err)
		}
		if it := itemState(turn); it != records.ItemDisposalPending {
			t.Fatalf("%s setup: record not disposal-eligible before the purge (state %s)", label, it)
		}
		if outcome, err := svc.Store.BeginPurge(ctx, officer2, turn, func(context.Context, pgx.Tx, string) (bool, error) {
			return true, nil
		}); err != nil || outcome != "purging" {
			t.Fatalf("%s begin: %s %v", label, outcome, err)
		}
		outcome := ""
		must(svc.Store.FinishPurgePlanTx(ctx, &officer2, tenant, turn, func(ctx context.Context) ([]evidence.VersionRef, error) {
			return svcBackend.TurnDisposalRefs(ctx, tenant, turn)
		}, &outcome))
		// Interrupt: the admission (always) plus the targeted second
		// version are physically deleted; the disposition transaction
		// never commits.
		must(recordsClient.DeleteVersion(ctx, refs[0].Key, refs[0].Version))
		secondDelete()
		// A matching hold is placed: all surviving versions receive native
		// protection and the loss is reported.
		h, perr := svc.Place(ctx, officer1, records.Scope{MatterID: mS3}, label+" hold over an interrupted disposal", "c07r3-"+label)
		if perr != nil || h.State != records.HoldEffective {
			t.Fatalf("%s FINDING 3: hold not effective over the partially disposed record: %v %+v", label, perr, h)
		}
		var item *records.ReportedItem
		for i := range h.Report.Items {
			if h.Report.Items[i].TurnID == turn {
				item = &h.Report.Items[i]
			}
		}
		if item == nil || !item.PartiallyDisposed || item.MissingVersions < wantMissing {
			t.Fatalf("%s FINDING 3: the interrupted disposal's partial loss is not reported: %+v (want >= %d missing)", label, item, wantMissing)
		}
		plan, perr := svc.Store.PlanOf(ctx, tenant, turn)
		if perr != nil {
			t.Fatal(perr)
		}
		if len(plan) != len(refs) {
			t.Fatalf("%s FINDING 3: the durable plan was destroyed (%d of %d versions inventoried)", label, len(plan), len(refs))
		}
		// Surviving planned versions are natively protected.
		for _, row := range plan {
			if row.Disposition == records.OutcomeDeleted || row.Disposition == records.OutcomeAbsent {
				continue
			}
			if state, lerr := recordsClient.LegalHold(ctx, row.Key, row.Version); lerr != nil || state != "ON" {
				t.Fatalf("%s FINDING 3: surviving planned version %s is %q, want native legal hold ON (err %v)", label, row.Key, state, lerr)
			}
		}
		// Release the hold, let retention and grace elapse, and run the
		// ordinary sweep/begin/finish operations: the remaining versions
		// must reach a verified disposition.
		if _, err := svc.Release(ctx, officer1, h.ID, label+" release"); err != nil {
			t.Fatal(err)
		}
		must(svc.Recover(ctx))
		time.Sleep(1100 * time.Millisecond)
		if _, err := svc.Sweep(ctx, officer1); err != nil {
			t.Fatal(err)
		}
		if it := itemState(turn); it != records.ItemDisposalPending {
			t.Fatalf("%s FINDING 3: the sweep never re-marked the interrupted-disposal record (missing durable proof of previously verified terminality; state %s)", label, it)
		}
		if outcome, err := svc.Store.BeginPurge(ctx, officer2, turn, func(context.Context, pgx.Tx, string) (bool, error) {
			return true, nil
		}); err != nil || outcome != "purging" {
			t.Fatalf("%s second begin: %s %v", label, outcome, err)
		}
		o, _, ferr := svc.FinishPurge(ctx, &officer2, turn)
		if ferr != nil {
			t.Fatalf("%s FINDING 3: the eventual disposal of the remaining bytes failed: %v", label, ferr)
		}
		if it := itemState(turn); it != records.ItemDisposed {
			t.Fatalf("%s FINDING 3: the record did not reach a verified disposition: %s (%s)", label, it, o)
		}
		plan, perr = svc.Store.PlanOf(ctx, tenant, turn)
		if perr != nil {
			t.Fatal(perr)
		}
		for _, row := range plan {
			if row.Disposition != records.OutcomeDeleted && row.Disposition != records.OutcomeAbsent && row.Disposition != records.OutcomeRetainedShared {
				t.Fatalf("%s FINDING 3: version %s lacks a verified disposition: %q", label, row.Key, row.Disposition)
			}
		}
		dump("c07r3-"+label+"-resume.json", map[string]any{"turn": turn, "outcome": o, "plan": plan})
	}

	// S3a: the TERMINAL EVENT SLOT was deleted mid-disposal (the live
	// probe now reads a non-terminal highest slot).
	resume("s3a-terminal-slot", s3F, s3FRefs, 2, func() {
		key, version := terminalSlot(s3FRefs)
		must(recordsClient.DeleteVersion(ctx, key, version))
	})
	// The S3 shared control turn keeps the shared object alive (retained).
	// (s3F2 stays live and non-disposed: its admission references the same
	// exact object version as s3F.)
	// S3b: the TERMINAL EVENT DATA was deleted mid-disposal (the slot
	// marker survives; the live probe fails closed).
	resume("s3b-terminal-data", s3G, s3GRefs, 2, func() {
		slotKey, slotVersion := terminalSlot(s3GRefs)
		dataKey, dataVersion := eventDataOf(slotKey, slotVersion)
		must(recordsClient.DeleteVersion(ctx, dataKey, dataVersion))
	})
	// S3c (control, the round-2 S4 shape): only the ADMISSION MARKER was
	// deleted - the terminal evidence survives - so both the reviewed head
	// and the correction converge.
	resume("s3c-admission-only", s3H, s3HRefs, 1, func() {})
	// Verify the physical ground truth of every completed disposal against
	// its verified dispositions: versions dispositioned gone are ACTUALLY
	// absent, and SHARED versions (referenced by other non-disposed
	// records, e.g. the live control turn s3F2 and cross-turn
	// content-deduplicated event objects) SURVIVE.
	checkDisposalCompleteness := func(label, turn string, refs []evidence.VersionRef) {
		t.Helper()
		plan, perr := svc.Store.PlanOf(ctx, tenant, turn)
		if perr != nil {
			t.Fatal(perr)
		}
		byKey := map[string]records.PlanRow{}
		for _, row := range plan {
			byKey[row.Key+"|"+row.Version] = row
		}
		for _, r := range refs {
			row, ok := byKey[r.Key+"|"+r.Version]
			if !ok {
				t.Fatalf("%s FINDING 3: version %s is not in the durable disposal plan", label, r.Key)
			}
			switch row.Disposition {
			case records.OutcomeDeleted, records.OutcomeAbsent:
				if !gone(r.Key, r.Version) {
					t.Fatalf("%s FINDING 3: the dispositioned-gone version %s survived the completed disposal", label, r.Key)
				}
			case records.OutcomeRetainedShared:
				if gone(r.Key, r.Version) {
					t.Fatalf("%s FINDING 3: the SHARED version %s required by another non-disposed record was deleted", label, r.Key)
				}
			default:
				t.Fatalf("%s FINDING 3: version %s lacks a verified disposition: %q", label, r.Key, row.Disposition)
			}
		}
	}
	checkDisposalCompleteness("s3a", s3F, s3FRefs)
	checkDisposalCompleteness("s3b", s3G, s3GRefs)
	checkDisposalCompleteness("s3c", s3H, s3HRefs)
	// The input object shared with the LIVE control turn s3F2 must be
	// explicitly retained (held and shared versions survive).
	sharedS3 := sharedRefOfInput(s3FRefs, "r3s3-shared-input")
	planF, perr := svc.Store.PlanOf(ctx, tenant, s3F)
	if perr != nil {
		t.Fatal(perr)
	}
	sharedDisposition := ""
	for _, row := range planF {
		if row.Key == sharedS3.Key && row.Version == sharedS3.Version {
			sharedDisposition = row.Disposition
		}
	}
	if sharedDisposition != records.OutcomeRetainedShared {
		t.Fatalf("S3 FINDING 3: the version shared with the live control turn was not retained (disposition %q)", sharedDisposition)
	}
	if gone(sharedS3.Key, sharedS3.Version) {
		t.Fatal("S3 FINDING 3: the shared version required by the live control turn was deleted")
	}

	// ---- S4: the effective-hold repair gap is durably recorded ----
	h4, err := svc.Place(ctx, officer1, records.Scope{MatterID: mS4}, "S4 hold with a transient repair gap", "c07r3-s4")
	must(err)
	if h4.State != records.HoldEffective {
		t.Fatalf("S4 setup: hold not effective: %+v", h4)
	}
	// (The s4 turn was seeded while the hold was pending establishment...
	// it was admitted AFTER the hold: the recorder guard protected it.)
	// The lifecycle service's enumeration of the matching record becomes
	// transiently unverifiable (one slot read fails).
	s4Slot, _ := lowestSlot(refsOf(s4I))
	svcTransport.mu.Lock()
	svcTransport.failReadKey = s4Slot
	svcTransport.armed = true
	svcTransport.mu.Unlock()
	must(svc.Recover(ctx))
	stored4, err := svc.Store.GetHold(ctx, officer1, h4.ID)
	must(err)
	if len(stored4.Report.RepairPending) == 0 {
		t.Fatalf("S4 FINDING 4: recovery silently discarded the uncovered condition: the durable hold report carries no repair-pending state (%+v)", stored4.Report)
	}
	var s4PendingAudit int
	must(owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='hold.protection_repair_pending'`).Scan(&s4PendingAudit))
	if s4PendingAudit == 0 {
		t.Fatal("S4 FINDING 4: no attributable repair-pending audit row was written")
	}
	// The condition is not claimed as verified: the repair-pending list is
	// the actionable signal, distinct from the historical establishment
	// coverage the report merge preserves.
	// Storage access is restored: the next recovery resolves the
	// outstanding repair state without erasing the historical evidence.
	svcTransport.mu.Lock()
	svcTransport.armed = false
	svcTransport.mu.Unlock()
	must(svc.Recover(ctx))
	stored4, err = svc.Store.GetHold(ctx, officer1, h4.ID)
	must(err)
	if len(stored4.Report.RepairPending) != 0 {
		t.Fatalf("S4 FINDING 4: the resolved repair state was not cleared: %+v", stored4.Report.RepairPending)
	}
	for _, r := range refsOf(s4I) {
		if state, lerr := recordsClient.LegalHold(ctx, r.Key, r.Version); lerr != nil || state != "ON" {
			t.Fatalf("S4 FINDING 4: the repaired record's version %s is not protected after recovery (state %q err %v)", r.Key, state, lerr)
		}
		if derr := recordsClient.DeleteVersion(ctx, r.Key, r.Version); !errors.Is(derr, s3transport.ErrObjectProtected) {
			t.Fatalf("S4 FINDING 4: direct deletion of a repaired-protected version must be refused, got %v", derr)
		}
	}
	var s4PendingAudit2 int
	must(owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='hold.protection_repair_pending'`).Scan(&s4PendingAudit2))
	if s4PendingAudit2 < s4PendingAudit {
		t.Fatal("S4 FINDING 4: the historical failure evidence was erased")
	}
	if _, err := svc.Release(ctx, officer1, h4.ID, "S4 release"); err != nil {
		t.Fatal(err)
	}
	dump("c07r3-s4-repair-gap.json", map[string]any{"turn": s4I, "hold": h4.ID, "pending_first_recover": s4PendingAudit, "pending_after_repair": s4PendingAudit2})

	if _, err := svc.Release(ctx, officer1, h4.ID, "S4 release"); err != nil {
		t.Fatal(err)
	}
	seedFence.Release()
}
