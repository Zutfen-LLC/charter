//go:build retention_drill

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestC07Round4ReviewDrill is the real-storage qualification of the C07
// round-4 review corrections against the pinned SeaweedFS 4.55 + PostgreSQL
// 16.16 composition inside the isolated no-network runner, with the
// records-scoped storage credential. Unlike the previous rounds, every
// interruption is produced by the ACTUAL FinishPurge behavior (the production
// deletion loop continues after ErrObjectProtected), never by a synthetic
// admission-first deletion:
//
//	F1  the authoritative disposal reference set (finding 1, CRITICAL):
//	    terminal records A and B share an exact content-addressed object
//	    referenced by a SUBSEQUENT event of A and by B's admission; A's
//	    admission marker and event-zero data stay natively protected while
//	    the interrupted FinishPurge deletes every subsequent event marker.
//	    After the protection is removed, the live enumeration SUCCEEDS with
//	    a truncated version set while the durable plan still contains the
//	    surviving versions: the ordinary disposal retry must preserve B's
//	    shared object version.
//	F1b the inverse direction: a partially disposed sibling with a SURVIVING
//	    admission marker whose durable plan contains references omitted by
//	    its truncated live enumeration fences the disposal of another record
//	    referencing the same exact version.
//	F1c the same reference-resolution cases for native legal-hold REMOVAL:
//	    plan-backed coverage of an interrupted record protects the shared
//	    version referenced only by its deleted suffix, and releasing the
//	    other (live-referencing) hold must not clear that protection.
//	F2  a surviving admission marker whose event-zero data was deleted
//	    (finding 2, HIGH) must not wedge the tenant's lifecycle operations:
//	    hold placement over the interrupted record and over an unrelated
//	    intact record both succeed, the partial loss is reported from the
//	    durable plan, and the ordinary disposal resumes after the release.
//	MX  the round-4 interruption fault matrix (section 4 of the review):
//	    blocked terminal/interior markers and data, multiple interspersed
//	    protected versions, an injected storage error mid-deletion
//	    (interrupted database commit), a fresh-service restart at each
//	    boundary, hold placement, overlapping holds, scope narrowing and
//	    release during the interrupted disposal, disposal completion after
//	    the temporary protection is removed, and an unrelated intact record
//	    remaining operational throughout.
func TestC07Round4ReviewDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
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
		t.Fatal("round-4 drill requires the retained profile with the records-scoped storage credential")
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

	idp := syntheticidp.New("charter-retention-drill", "synthetic-r4")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-r4", "c07-round4-drill")
	must(err)
	alice, err := st.CreateUser(ctx, tenant, "r4-alice", "round4 custodian alice")
	must(err)
	bob, err := st.CreateUser(ctx, tenant, "r4-bob", "round4 custodian bob")
	must(err)
	r1, err := st.CreateUser(ctx, tenant, "r4-records-one", "round4 records officer one")
	must(err)
	r2, err := st.CreateUser(ctx, tenant, "r4-records-two", "round4 records officer two")
	must(err)
	mkProject := func(label string) (string, string) {
		t.Helper()
		p, err := st.CreateProject(ctx, tenant, label)
		must(err)
		var matter string
		must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p).Scan(&matter))
		return p, matter
	}
	pF1A, mF1A := mkProject("round4 F1 A")
	pF1B, mF1B := mkProject("round4 F1 B")
	pF1B2, mF1B2 := mkProject("round4 F1b B2")
	pF1A2, mF1A2 := mkProject("round4 F1b A2")
	pF1B3, mF1B3 := mkProject("round4 F1c B3")
	pF1A3, mF1A3 := mkProject("round4 F1c A3")
	pF2, mF2 := mkProject("round4 F2 interrupted")
	pF2U, mF2U := mkProject("round4 F2 unrelated")
	pMX, mMX := mkProject("round4 MX")
	pMXU, mMXU := mkProject("round4 MX unrelated")
	for _, p := range []string{pF1A, pF1A2, pF1A3, pF2, pMX} {
		must(st.SeedMember(ctx, tenant, p, alice))
	}
	for _, p := range []string{pF1B, pF1B2, pF1B3, pF2U, pMXU} {
		must(st.SeedMember(ctx, tenant, p, bob))
	}
	must(st.SeedRole(ctx, tenant, r1, store.RoleRecordsOfficer))
	must(st.SeedRole(ctx, tenant, r2, store.RoleRecordsOfficer))
	officer1 := store.Principal{TenantID: tenant, UserID: r1, Roles: map[string]bool{store.RoleRecordsOfficer: true}}
	officer2 := store.Principal{TenantID: tenant, UserID: r2, Roles: map[string]bool{store.RoleRecordsOfficer: true}}

	evPool, err := pgxpool.New(ctx, os.Getenv("CHARTER_EVIDENCE_DATABASE_URL"))
	must(err)
	defer evPool.Close()
	seedFence, err := (evidence.PG{DB: evPool}).AcquireFence(ctx)
	must(err)
	defer seedFence.Release()
	writeClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(recordsSecret))})
	must(err)
	seedStarted := time.Now()
	deployment := sc.Deployment + "-c07r4"
	writeBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: writeClient, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	// The lifecycle service deletes through a fault-injecting records client
	// so the matrix can inject a transient DELETE failure mid-deletion (the
	// interrupted-database-commit shape) while every other operation is the
	// real pinned storage.
	svcStorage := &faultingRecordsStorage{inner: recordsClient}
	svc, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: writeClient, Deployment: deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey,
		Signer: signer, MinimumRetention: seedStarted.Add(5 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence,
	})
	must(err)
	svcRecords := &records.Service{Store: &records.Store{DB: owner}, Backend: svc, Storage: svcStorage, Retained: true, Logf: func(string, ...any) {}}

	recorder := &evidence.Recorder{Backend: writeBackend, Fence: seedFence, Lifecycle: svcRecords, Logf: func(f string, a ...any) {
		t.Logf("recorder: "+f, a...)
	}, Policy: func(_ context.Context, r evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "round4", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "seed", ModelID: "det-a"}}, nil
	}}
	seedTurn := func(project, matter, custodian, label, input string) string {
		t.Helper()
		res, err := recorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: project, MatterID: matter, CustodianID: custodian,
			IdempotencyKey: "c07r4-" + label, Input: []byte(input),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("round4 output " + label)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		return res.TurnID
	}
	// Fast lifecycle policy: retention 1s, no grace.
	_, err = owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id, retention_seconds, grace_seconds, set_by) VALUES ($1, 1, 0, $2) ON CONFLICT (tenant_id) DO UPDATE SET retention_seconds=1, grace_seconds=0`, tenant, r1)
	must(err)
	itemState := func(turn string) string {
		t.Helper()
		items, err := svcRecords.Store.Items(ctx, officer1)
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
	admissionOf := func(refs []evidence.VersionRef) evidence.VersionRef {
		t.Helper()
		for _, r := range refs {
			if strings.Contains(r.Key, "/admissions/") {
				return r
			}
		}
		t.Fatal("no admission marker in refs")
		return evidence.VersionRef{}
	}
	// slotMarkerOf returns the event-slot marker (key events/<seq>) for the
	// given sequence.
	slotMarkerOf := func(refs []evidence.VersionRef, seq int) evidence.VersionRef {
		t.Helper()
		want := "/events/" + strconv.Itoa(seq)
		for _, r := range refs {
			if strings.HasSuffix(r.Key, want) {
				return r
			}
		}
		t.Fatalf("no event slot %d in refs", seq)
		return evidence.VersionRef{}
	}
	highestSlotSeq := func(refs []evidence.VersionRef) int {
		t.Helper()
		best := -1
		for _, r := range refs {
			if s := slotSeqOf(r.Key); s != "" {
				n, _ := strconv.Atoi(s)
				if n > best {
					best = n
				}
			}
		}
		if best < 0 {
			t.Fatal("no event slots in refs")
		}
		return best
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
	eventZeroDataOf := func(refs []evidence.VersionRef) evidence.VersionRef {
		t.Helper()
		a := admissionOf(refs)
		key, version := eventDataOf(a.Key, a.Version)
		return evidence.VersionRef{Key: key, Version: version}
	}
	eventDataOfSlot := func(refs []evidence.VersionRef, seq int) evidence.VersionRef {
		t.Helper()
		s := slotMarkerOf(refs, seq)
		key, version := eventDataOf(s.Key, s.Version)
		return evidence.VersionRef{Key: key, Version: version}
	}
	// sharedRefOfBytes locates the exact content-addressed object version of
	// the given bytes in a turn's reference set.
	sharedRefOfBytes := func(refs []evidence.VersionRef, data string) evidence.VersionRef {
		t.Helper()
		sum := sha256.Sum256([]byte(data))
		digest := hex.EncodeToString(sum[:])
		for _, r := range refs {
			if strings.Contains(r.Key, "/data/objects/") && strings.HasSuffix(r.Key, digest) {
				return r
			}
		}
		t.Fatalf("no shared object for %d-byte input (digest %s) in %d refs", len(data), digest, len(refs))
		return evidence.VersionRef{}
	}
	gone := func(key, version string) bool {
		t.Helper()
		err := recordsClient.Head(ctx, key, version)
		return errors.Is(err, s3transport.ErrObjectAbsent)
	}
	holdOn := func(r evidence.VersionRef) bool {
		t.Helper()
		state, lerr := recordsClient.LegalHold(ctx, r.Key, r.Version)
		return lerr == nil && state == "ON"
	}
	protect := func(rs ...evidence.VersionRef) {
		t.Helper()
		for _, r := range rs {
			must(recordsClient.SetLegalHold(ctx, r.Key, r.Version, true))
		}
	}
	unprotect := func(rs ...evidence.VersionRef) {
		t.Helper()
		for _, r := range rs {
			must(recordsClient.SetLegalHold(ctx, r.Key, r.Version, false))
		}
	}
	// beginPurgeAndInterrupt drives the AUTHORIZED disposal lifecycle to the
	// purging state, applies the selective native protection, and executes
	// the actual FinishPurge: the production deletion loop continues after
	// ErrObjectProtected, deleting every unprotected version, and the
	// disposition transaction never commits.
	beginPurgeAndInterrupt := func(label, turn string, protected ...evidence.VersionRef) ([]evidence.VersionRef, error) {
		t.Helper()
		if _, err := svcRecords.Sweep(ctx, officer1); err != nil {
			t.Fatal(err)
		}
		if it := itemState(turn); it != records.ItemDisposalPending {
			t.Fatalf("%s setup: record not disposal-eligible before the purge (state %s)", label, it)
		}
		if outcome, err := svcRecords.Store.BeginPurge(ctx, officer2, turn, func(context.Context, pgx.Tx, string) (bool, error) {
			return true, nil
		}); err != nil || outcome != "purging" {
			t.Fatalf("%s begin: %s %v", label, outcome, err)
		}
		refs := refsOf(turn)
		protect(protected...)
		_, _, err := svcRecords.FinishPurge(ctx, &officer2, turn)
		return refs, err
	}

	// ---- Seed the scenario turns (before the retention wait) ----
	f1A := seedTurn(pF1A, mF1A, alice, "r4f1-a", "r4f1-a-input")
	f1B := seedTurn(pF1B, mF1B, bob, "r4f1-b", "round4 output r4f1-a") // B's admission references A's terminal-event output object: one exact shared version
	f1B2 := seedTurn(pF1B2, mF1B2, bob, "r4f1-b2", "r4f1-b2-input")
	f1A2 := seedTurn(pF1A2, mF1A2, alice, "r4f1-a2", "round4 output r4f1-b2") // references B2's subsequent-event output object
	f1B3 := seedTurn(pF1B3, mF1B3, bob, "r4f1-b3", "r4f1-b3-input")
	f1A3 := seedTurn(pF1A3, mF1A3, alice, "r4f1-a3", "round4 output r4f1-b3")
	f2C := seedTurn(pF2, mF2, alice, "r4f2-c", "r4f2-c-input")
	f2U := seedTurn(pF2U, mF2U, bob, "r4f2-u", "r4f2-u-input")
	mx1 := seedTurn(pMX, mMX, alice, "r4mx-1", "r4mx-1-input")
	mx1P := seedTurn(pMX, mMX, alice, "r4mx-1p", "round4 output r4mx-1") // live sharing partner of mx1's output object
	mx2 := seedTurn(pMX, mMX, alice, "r4mx-2", "r4mx-2-input")
	mx3 := seedTurn(pMX, mMX, alice, "r4mx-3", "r4mx-3-input")
	mx4 := seedTurn(pMX, mMX, alice, "r4mx-4", "r4mx-4-input")
	mx5 := seedTurn(pMX, mMX, alice, "r4mx-5", "r4mx-5-input")
	mx6 := seedTurn(pMX, mMX, alice, "r4mx-6", "r4mx-6-input")
	mxU := seedTurn(pMXU, mMXU, bob, "r4mx-u", "r4mx-u-input")
	dump("c07r4-seed-turns.json", map[string]string{
		"f1a": f1A, "f1b": f1B, "f1b2": f1B2, "f1a2": f1A2, "f1b3": f1B3, "f1a3": f1A3,
		"f2c": f2C, "f2u": f2U, "mx1": mx1, "mx1p": mx1P, "mx2": mx2, "mx3": mx3,
		"mx4": mx4, "mx5": mx5, "mx6": mx6, "mxu": mxU,
	})
	f1ARefs := refsOf(f1A)
	f1BRefs := refsOf(f1B)
	f1B2Refs := refsOf(f1B2)
	f1A2Refs := refsOf(f1A2)
	f1B3Refs := refsOf(f1B3)
	f1A3Refs := refsOf(f1A3)
	f2CRefs := refsOf(f2C)
	f2URefs := refsOf(f2U)
	mx1Refs := refsOf(mx1)
	mx1PRefs := refsOf(mx1P)
	mxURefs := refsOf(mxU)
	sharedF1 := sharedRefOfBytes(f1ARefs, "round4 output r4f1-a")
	if !refIn(f1BRefs, sharedF1) {
		t.Fatal("F1 setup: B does not reference the shared object version")
	}
	sharedF1b := sharedRefOfBytes(f1B2Refs, "round4 output r4f1-b2")
	if !refIn(f1A2Refs, sharedF1b) {
		t.Fatal("F1b setup: A2 does not reference the shared object version")
	}
	sharedF1c := sharedRefOfBytes(f1B3Refs, "round4 output r4f1-b3")
	if !refIn(f1A3Refs, sharedF1c) {
		t.Fatal("F1c setup: A3 does not reference the shared object version")
	}
	sharedMX1 := sharedRefOfBytes(mx1Refs, "round4 output r4mx-1")
	if !refIn(mx1PRefs, sharedMX1) {
		t.Fatal("MX setup: the sharing partner does not reference the shared object version")
	}

	// ---- The storage retention horizon passes for the seed versions ----
	if wait := 75*time.Second - time.Since(seedStarted); wait > 0 {
		time.Sleep(wait)
	}

	// ---- F1: the disposal retry preserves the shared version of a deleted suffix ----
	f1Admission := admissionOf(f1ARefs)
	f1Ev0 := eventZeroDataOf(f1ARefs)
	aRefs, err := beginPurgeAndInterrupt("f1", f1A, f1Admission, f1Ev0)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("F1 setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	// The interrupted state: the protected admission and event-zero data
	// survive while every subsequent event marker, data event and own object
	// is physically deleted; the shared object survived the first run.
	if gone(f1Admission.Key, f1Admission.Version) || gone(f1Ev0.Key, f1Ev0.Version) {
		t.Fatal("F1 setup: a protected version was deleted")
	}
	for _, r := range aRefs {
		if r == f1Admission || r == f1Ev0 || r == sharedF1 {
			continue
		}
		if !gone(r.Key, r.Version) {
			t.Fatalf("F1 setup: version %s was not deleted during the interrupted disposal", r.Key)
		}
	}
	if gone(sharedF1.Key, sharedF1.Version) {
		t.Fatal("F1 setup: the shared object did not survive the interrupted disposal")
	}
	// Remove the temporary protection: the live enumeration now SUCCEEDS
	// with a truncated version set while the durable plan still contains
	// the surviving versions.
	unprotect(f1Admission, f1Ev0)
	liveRefs, lerr := writeBackend.TurnDisposalRefs(ctx, tenant, f1A)
	if lerr != nil {
		t.Fatalf("F1: the truncated live enumeration must still succeed (got %v)", lerr)
	}
	planF1, perr := svcRecords.Store.PlanOf(ctx, tenant, f1A)
	if perr != nil {
		t.Fatal(perr)
	}
	if len(liveRefs) >= len(planF1) {
		t.Fatalf("F1: the live enumeration is not truncated (live %d, plan %d)", len(liveRefs), len(planF1))
	}
	// Retry the ordinary disposal.
	outcome, _, ferr := svcRecords.FinishPurge(ctx, &officer2, f1A)
	if ferr != nil || outcome != "disposed" {
		t.Fatalf("F1: the disposal retry failed: outcome %q err %v", outcome, ferr)
	}
	// Verify whether B's shared object survives.
	if gone(sharedF1.Key, sharedF1.Version) {
		t.Fatalf("F1 FINDING 1: the disposal retry deleted the shared object version referenced by the surviving record %s: the deleter used the durable plan's version set while shared-reference protection was evaluated against the truncated live enumeration", f1B)
	}
	for _, r := range f1BRefs {
		if gone(r.Key, r.Version) {
			t.Fatalf("F1 FINDING 1: the surviving record's version %s was deleted by the partner's disposal", r.Key)
		}
	}
	if it := itemState(f1A); it != records.ItemDisposed {
		t.Fatalf("F1: the disposal did not complete: %s", it)
	}
	dump("c07r4-f1-forward.json", map[string]any{"disposal_turn": f1A, "sibling": f1B, "shared": sharedF1, "live_refs": len(liveRefs), "plan_rows": len(planF1)})

	// ---- F1b: a partially disposed sibling's durable plan fences another record's disposal ----
	b2Admission := admissionOf(f1B2Refs)
	b2Ev0 := eventZeroDataOf(f1B2Refs)
	b2Refs, err := beginPurgeAndInterrupt("f1b", f1B2, b2Admission, b2Ev0)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("F1b setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	if gone(sharedF1b.Key, sharedF1b.Version) {
		t.Fatal("F1b setup: the shared object did not survive the interrupted disposal")
	}
	unprotect(b2Admission, b2Ev0)
	// Dispose A2: the partially disposed sibling's durable plan must fence
	// the shared version its truncated live enumeration no longer lists.
	if _, err := svcRecords.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	}
	if outcome, err := svcRecords.Store.BeginPurge(ctx, officer2, f1A2, func(context.Context, pgx.Tx, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("F1b begin: %s %v", outcome, err)
	}
	outcome, _, ferr = svcRecords.FinishPurge(ctx, &officer2, f1A2)
	if ferr != nil || outcome != "disposed" {
		t.Fatalf("F1b: the sibling disposal failed: outcome %q err %v", outcome, ferr)
	}
	if gone(sharedF1b.Key, sharedF1b.Version) {
		t.Fatalf("F1b FINDING 1: the disposal of %s deleted the shared object version that the partially disposed sibling %s still lists in its durable plan: the truncated live enumeration overrode known durable references", f1A2, f1B2)
	}
	// The sibling's own disposal converges afterward from its durable plan.
	outcome, _, ferr = svcRecords.FinishPurge(ctx, &officer2, f1B2)
	if ferr != nil || outcome != "disposed" {
		t.Fatalf("F1b: the sibling convergence failed: outcome %q err %v", outcome, ferr)
	}
	if it := itemState(f1B2); it != records.ItemDisposed {
		t.Fatalf("F1b: the sibling's disposal did not complete: %s", it)
	}
	dump("c07r4-f1b-inverse.json", map[string]any{"disposal_turn": f1A2, "sibling": f1B2, "shared": sharedF1b, "sibling_plan_rows": len(b2Refs)})

	// ---- F1c: the same resolution governs native legal-hold removal ----
	b3Admission := admissionOf(f1B3Refs)
	b3Ev0 := eventZeroDataOf(f1B3Refs)
	_, err = beginPurgeAndInterrupt("f1c", f1B3, b3Admission, b3Ev0)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("F1c setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	unprotect(b3Admission, b3Ev0)
	// A hold over the interrupted record's matter: plan-backed coverage must
	// protect ALL remaining in-scope versions, the shared version referenced
	// only by the deleted suffix included.
	hb, perr := svcRecords.Place(ctx, officer1, records.Scope{MatterID: mF1B3}, "F1c hold over the interrupted record", "c07r4-f1c-b")
	if perr != nil || hb.State != records.HoldEffective {
		t.Fatalf("F1c FINDING 2: hold placement over the interrupted record failed: err %v state %+v", perr, hb)
	}
	if !holdOn(sharedF1c) {
		t.Fatalf("F1c FINDING 2: the interrupted record's remaining shared version is not protected by the hold over it: plan-backed coverage must protect all remaining in-scope versions")
	}
	// An overlapping hold over the LIVE referencing record.
	ha, perr := svcRecords.Place(ctx, officer1, records.Scope{MatterID: mF1A3}, "F1c hold over the live referencing record", "c07r4-f1c-a")
	if perr != nil || ha.State != records.HoldEffective {
		t.Fatalf("F1c setup: hold placement over the live record failed: err %v state %+v", perr, ha)
	}
	if !holdOn(sharedF1c) {
		t.Fatal("F1c setup: the shared version is not protected under both holds")
	}
	// Release the live record's hold: the shared version's protection must
	// survive, because the interrupted (still held) record's durable plan
	// still references the exact version.
	if _, err := svcRecords.Release(ctx, officer1, ha.ID, "F1c release the live reference"); err != nil {
		t.Fatal(err)
	}
	if !holdOn(sharedF1c) {
		t.Fatalf("F1c FINDING 1: protection was removed from the shared version while a held record still references it through its durable disposal plan")
	}
	if _, err := svcRecords.Release(ctx, officer1, hb.ID, "F1c release the interrupted record"); err != nil {
		t.Fatal(err)
	}
	if holdOn(sharedF1c) {
		t.Fatal("F1c: the shared version's protection did not converge after both releases")
	}
	// The interrupted record's disposal completes after the temporary
	// protection is removed (its own authorized disposal may delete the
	// shared version only if no live referent remains - f1A3 is live).
	must(svcRecords.Recover(ctx))
	outcome, _, ferr = svcRecords.FinishPurge(ctx, &officer2, f1B3)
	if ferr != nil || outcome != "disposed" {
		t.Fatalf("F1c: the interrupted record's disposal did not complete: outcome %q err %v", outcome, ferr)
	}
	if gone(sharedF1c.Key, sharedF1c.Version) {
		t.Fatalf("F1c FINDING 1: the interrupted record's disposal deleted the shared version while the live record %s still references it", f1A3)
	}
	dump("c07r4-f1c-hold-removal.json", map[string]any{"interrupted": f1B3, "live_referencing": f1A3, "shared": sharedF1c})

	// ---- F2: a surviving admission with deleted event-zero data must not wedge the tenant ----
	f2Admission := admissionOf(f2CRefs)
	f2Ev0 := eventZeroDataOf(f2CRefs)
	cRefs, err := beginPurgeAndInterrupt("f2", f2C, f2Admission)
	if err == nil || !errors.Is(err, records.ErrBlockedStorage) {
		t.Fatalf("F2 setup: the interrupted FinishPurge must be blocked (got %v)", err)
	}
	// Confirm admission-marker presence and event-zero absence independently.
	if gone(f2Admission.Key, f2Admission.Version) {
		t.Fatal("F2 setup: the protected admission marker was deleted")
	}
	if !gone(f2Ev0.Key, f2Ev0.Version) {
		t.Fatal("F2 setup: the event-zero data was not deleted during the interrupted disposal")
	}
	// The unrelated intact record's evidence is untouched by the interrupted
	// sibling's disposal.
	for _, r := range f2URefs {
		if gone(r.Key, r.Version) {
			t.Fatalf("F2 setup: the unrelated record's version %s was deleted by the interrupted sibling's disposal", r.Key)
		}
	}
	// Hold placement over the UNRELATED intact record must not be blocked.
	hu, perr := svcRecords.Place(ctx, officer1, records.Scope{MatterID: mF2U}, "F2 hold over the unrelated record", "c07r4-f2-u")
	if perr != nil || hu.State != records.HoldEffective {
		t.Fatalf("F2 FINDING 2: hold placement over the unrelated intact record failed (tenant wedge): err %v state %+v", perr, hu)
	}
	// Hold placement over the interrupted record: plan-backed coverage with
	// accurate historical-loss reporting.
	hc, perr := svcRecords.Place(ctx, officer1, records.Scope{MatterID: mF2}, "F2 hold over the interrupted record", "c07r4-f2-c")
	if perr != nil || hc.State != records.HoldEffective {
		t.Fatalf("F2 FINDING 2: hold placement over the interrupted record failed (wedge): err %v state %+v", perr, hc)
	}
	var f2Item *records.ReportedItem
	for i := range hc.Report.Items {
		if hc.Report.Items[i].TurnID == f2C {
			f2Item = &hc.Report.Items[i]
		}
	}
	if f2Item == nil || !f2Item.PartiallyDisposed || f2Item.MissingVersions < len(cRefs)-1 {
		t.Fatalf("F2 FINDING 2: the interrupted disposal's partial loss is not reported from the durable plan: %+v (want >= %d missing)", f2Item, len(cRefs)-1)
	}
	if !holdOn(f2Admission) {
		t.Fatal("F2: the interrupted record's surviving admission is not protected by the hold over it")
	}
	// Exercise release cleanup, recovery and the disposal retry.
	if _, err := svcRecords.Release(ctx, officer1, hc.ID, "F2 release the interrupted record"); err != nil {
		t.Fatal(err)
	}
	if _, err := svcRecords.Release(ctx, officer1, hu.ID, "F2 release the unrelated record"); err != nil {
		t.Fatal(err)
	}
	must(svcRecords.Recover(ctx))
	if it := itemState(f2C); it != records.ItemDisposed {
		t.Fatalf("F2 FINDING 2: the interrupted record's disposal never completed after recovery (state %s)", it)
	}
	if !gone(f2Admission.Key, f2Admission.Version) {
		t.Fatal("F2: the admission marker was not deleted by the converged disposal")
	}
	// The unrelated intact record remains operational.
	time.Sleep(1100 * time.Millisecond)
	if _, err := svcRecords.Sweep(ctx, officer1); err != nil {
		t.Fatalf("F2 FINDING 2: sweep remains wedged after the interrupted record converged: %v", err)
	}
	if outcome, err := svcRecords.Store.BeginPurge(ctx, officer2, f2U, func(context.Context, pgx.Tx, string) (bool, error) {
		return true, nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("F2 unrelated record: begin outcome %s err %v", outcome, err)
	}
	outcome, _, ferr = svcRecords.FinishPurge(ctx, &officer2, f2U)
	if ferr != nil || outcome != "disposed" {
		t.Fatalf("F2 FINDING 2: the unrelated record's disposal failed: outcome %q err %v", outcome, ferr)
	}

	dump("c07r4-f2-inventory-reconciliation.json", map[string]any{"interrupted": f2C, "unrelated": f2U, "plan_rows": len(cRefs), "missing_reported": f2Item.MissingVersions})

	// ---- MX: the round-4 interruption fault matrix ----
	// Each scenario interrupts the ACTUAL FinishPurge at a different
	// boundary, reconciles through a FRESH service instance (process
	// restart) plus recovery, and completes the disposal after the
	// temporary protection is removed.
	restartedStorage := &faultingRecordsStorage{inner: recordsClient}
	restart := func() *records.Service {
		return &records.Service{Store: &records.Store{DB: owner}, Backend: svc, Storage: restartedStorage, Retained: true, Logf: func(string, ...any) {}}
	}
	// checkDisposal verifies EVERY surviving required version individually
	// against the durable plan's verified dispositions, including shared
	// versions referenced only by deleted portions of a previously verified
	// chain.
	checkDisposal := func(label, turn string, refs []evidence.VersionRef) {
		t.Helper()
		plan, perr := svcRecords.Store.PlanOf(ctx, tenant, turn)
		if perr != nil {
			t.Fatal(perr)
		}
		byID := map[string]records.PlanRow{}
		for _, row := range plan {
			byID[row.Key+"|"+row.Version] = row
		}
		for _, r := range refs {
			row, ok := byID[r.Key+"|"+r.Version]
			if !ok {
				t.Fatalf("%s: version %s is not in the durable disposal plan", label, r.Key)
			}
			switch row.Disposition {
			case records.OutcomeDeleted, records.OutcomeAbsent:
				if !gone(r.Key, r.Version) {
					t.Fatalf("%s: the dispositioned-gone version %s survived the completed disposal", label, r.Key)
				}
			case records.OutcomeRetainedShared:
				if gone(r.Key, r.Version) {
					t.Fatalf("%s: the SHARED version %s required by another non-disposed record was deleted", label, r.Key)
				}
			default:
				t.Fatalf("%s: version %s lacks a verified disposition: %q", label, r.Key, row.Disposition)
			}
		}
	}
	completeDisposal := func(label, turn string) {
		t.Helper()
		rs := restart()
		must(rs.Recover(ctx))
		if it := itemState(turn); it != records.ItemDisposed {
			// Recovery re-evaluated the item (a hold moved the matter
			// epoch): drive the ordinary sweep/begin/finish tail.
			if it == records.ItemActive {
				time.Sleep(1100 * time.Millisecond) // retention (1s) re-expires
				if _, serr := rs.Sweep(ctx, officer1); serr != nil {
					t.Fatal(serr)
				}
				it = itemState(turn)
			}
			if it != records.ItemDisposalPending {
				t.Fatalf("%s: the record is not disposal-eligible after recovery (state %s)", label, it)
			}
			if outcome, serr := svcRecords.Store.BeginPurge(ctx, officer2, turn, func(context.Context, pgx.Tx, string) (bool, error) {
				return true, nil
			}); serr != nil || outcome != "purging" {
				t.Fatalf("%s second begin: %s %v", label, outcome, serr)
			}
			outcome, _, ferr := rs.FinishPurge(ctx, &officer2, turn)
			if ferr != nil || outcome != "disposed" {
				t.Fatalf("%s: the disposal did not complete after the temporary protection was removed: outcome %q err %v", label, outcome, ferr)
			}
		}
		if it := itemState(turn); it != records.ItemDisposed {
			t.Fatalf("%s: the record did not reach a verified disposition: %s", label, it)
		}
	}

	// M1: admission marker and event-zero data blocked; subsequent event
	// markers deleted; the shared object is retained while its referencing
	// marker is deleted (the F1 shape, direct-retry tail).
	{
		m1Admission := admissionOf(mx1Refs)
		m1Ev0 := eventZeroDataOf(mx1Refs)
		m1Refs, ierr := beginPurgeAndInterrupt("mx1", mx1, m1Admission, m1Ev0)
		if ierr == nil || !errors.Is(ierr, records.ErrBlockedStorage) {
			t.Fatalf("mx1 setup: the interrupted FinishPurge must be blocked (got %v)", ierr)
		}
		if gone(sharedMX1.Key, sharedMX1.Version) {
			t.Fatal("mx1 setup: the shared object did not survive the interrupted disposal")
		}
		unprotect(m1Admission, m1Ev0)
		completeDisposal("mx1", mx1)
		checkDisposal("mx1", mx1, m1Refs)
		if gone(sharedMX1.Key, sharedMX1.Version) {
			t.Fatalf("mx1 FINDING 1: the shared version referenced by the deleted suffix and the live partner %s was deleted", mx1P)
		}
		dump("c07r4-mx1-admission-ev0-blocked.json", map[string]any{"turn": mx1, "partner": mx1P, "shared": sharedMX1})
	}
	// M2: the TERMINAL event marker blocked (admission and event-zero data
	// protected as well): the deletion loop deletes the interior markers
	// and data while the terminal marker survives.
	{
		mx2Refs := refsOf(mx2)
		m2Admission := admissionOf(mx2Refs)
		m2Ev0 := eventZeroDataOf(mx2Refs)
		m2Terminal := slotMarkerOf(mx2Refs, highestSlotSeq(mx2Refs))
		m2Refs, ierr := beginPurgeAndInterrupt("mx2", mx2, m2Admission, m2Ev0, m2Terminal)
		if ierr == nil || !errors.Is(ierr, records.ErrBlockedStorage) {
			t.Fatalf("mx2 setup: the interrupted FinishPurge must be blocked (got %v)", ierr)
		}
		if gone(m2Terminal.Key, m2Terminal.Version) {
			t.Fatal("mx2 setup: the protected terminal marker was deleted")
		}
		unprotect(m2Admission, m2Ev0, m2Terminal)
		completeDisposal("mx2", mx2)
		checkDisposal("mx2", mx2, m2Refs)
		dump("c07r4-mx2-terminal-marker-blocked.json", map[string]any{"turn": mx2, "terminal": m2Terminal})
	}
	// M3: the TERMINAL event data blocked: the terminal slot marker is
	// deleted while its data bytes survive.
	{
		mx3Refs := refsOf(mx3)
		m3Admission := admissionOf(mx3Refs)
		m3Ev0 := eventZeroDataOf(mx3Refs)
		m3TerminalSeq := highestSlotSeq(mx3Refs)
		m3TerminalData := eventDataOfSlot(mx3Refs, m3TerminalSeq)
		m3Refs, ierr := beginPurgeAndInterrupt("mx3", mx3, m3Admission, m3Ev0, m3TerminalData)
		if ierr == nil || !errors.Is(ierr, records.ErrBlockedStorage) {
			t.Fatalf("mx3 setup: the interrupted FinishPurge must be blocked (got %v)", ierr)
		}
		if gone(m3TerminalData.Key, m3TerminalData.Version) {
			t.Fatal("mx3 setup: the protected terminal data was deleted")
		}
		unprotect(m3Admission, m3Ev0, m3TerminalData)
		completeDisposal("mx3", mx3)
		checkDisposal("mx3", mx3, m3Refs)
		dump("c07r4-mx3-terminal-data-blocked.json", map[string]any{"turn": mx3, "terminal_data": m3TerminalData})
	}
	// M4: an INTERIOR event marker blocked (a hole with a surviving higher
	// slot: the verified enumeration refuses, the durable plan governs).
	{
		mx4Refs := refsOf(mx4)
		m4Admission := admissionOf(mx4Refs)
		m4Ev0 := eventZeroDataOf(mx4Refs)
		m4Interior := slotMarkerOf(mx4Refs, 1)
		m4Refs, ierr := beginPurgeAndInterrupt("mx4", mx4, m4Admission, m4Ev0, m4Interior)
		if ierr == nil || !errors.Is(ierr, records.ErrBlockedStorage) {
			t.Fatalf("mx4 setup: the interrupted FinishPurge must be blocked (got %v)", ierr)
		}
		if gone(m4Interior.Key, m4Interior.Version) {
			t.Fatal("mx4 setup: the protected interior marker was deleted")
		}
		unprotect(m4Admission, m4Ev0, m4Interior)
		completeDisposal("mx4", mx4)
		checkDisposal("mx4", mx4, m4Refs)
		dump("c07r4-mx4-interior-marker-blocked.json", map[string]any{"turn": mx4, "interior": m4Interior})
	}
	// M5: MULTIPLE protected versions interspersed with deletable versions
	// (admission, event-zero data and the terminal marker), reconciled
	// through hold placement, OVERLAPPING holds, scope narrowing, release
	// and recovery during the interrupted disposal.
	{
		mx5Refs := refsOf(mx5)
		m5Admission := admissionOf(mx5Refs)
		m5Ev0 := eventZeroDataOf(mx5Refs)
		m5Terminal := slotMarkerOf(mx5Refs, highestSlotSeq(mx5Refs))
		m5Refs, ierr := beginPurgeAndInterrupt("mx5", mx5, m5Admission, m5Ev0, m5Terminal)
		if ierr == nil || !errors.Is(ierr, records.ErrBlockedStorage) {
			t.Fatalf("mx5 setup: the interrupted FinishPurge must be blocked (got %v)", ierr)
		}
		// Two overlapping holds over the interrupted record: one
		// all-custodian, one custodian-narrowed.
		h5a, perr := svcRecords.Place(ctx, officer1, records.Scope{MatterID: mMX}, "MX5 overlapping hold (all custodians)", "c07r4-mx5-a")
		if perr != nil || h5a.State != records.HoldEffective {
			t.Fatalf("mx5 FINDING 2: hold placement over the interrupted record failed: err %v state %+v", perr, h5a)
		}
		h5b, perr := svcRecords.Place(ctx, officer2, records.Scope{MatterID: mMX, CustodianIDs: []string{alice}}, "MX5 overlapping hold (narrow)", "c07r4-mx5-b")
		if perr != nil || h5b.State != records.HoldEffective {
			t.Fatalf("mx5 FINDING 2: the overlapping hold placement failed: err %v state %+v", perr, h5b)
		}
		// Scope narrowing: the all-custodian hold narrows away from the
		// record's custodian while the disposal stays interrupted.
		if _, serr := svcRecords.Store.ChangeScope(ctx, officer1, h5a.ID, records.Scope{MatterID: mMX, CustodianIDs: []string{bob}}, "MX5 narrow away from the interrupted record"); serr != nil {
			t.Fatalf("mx5: scope narrowing failed: %v", serr)
		}
		// Surviving in-scope versions stay protected by the remaining
		// (narrow) hold.
		if !holdOn(m5Admission) {
			t.Fatal("mx5: the interrupted record's surviving admission lost protection under the remaining overlapping hold")
		}
		// Release the remaining hold and complete the disposal.
		if _, serr := svcRecords.Release(ctx, officer2, h5b.ID, "MX5 release the narrow hold"); serr != nil {
			t.Fatal(serr)
		}
		if _, serr := svcRecords.Release(ctx, officer1, h5a.ID, "MX5 release the narrowed hold"); serr != nil {
			t.Fatal(serr)
		}
		unprotect(m5Admission, m5Ev0, m5Terminal)
		time.Sleep(1100 * time.Millisecond)
		rs := restart()
		must(rs.Recover(ctx))
		if _, serr := rs.Sweep(ctx, officer1); serr != nil {
			t.Fatal(serr)
		}
		if it := itemState(mx5); it != records.ItemDisposalPending {
			t.Fatalf("mx5: the interrupted-disposal record was not re-marked after the holds released (state %s)", it)
		}
		if outcome, serr := svcRecords.Store.BeginPurge(ctx, officer2, mx5, func(context.Context, pgx.Tx, string) (bool, error) {
			return true, nil
		}); serr != nil || outcome != "purging" {
			t.Fatalf("mx5 second begin: %s %v", outcome, serr)
		}
		outcome, _, ferr := rs.FinishPurge(ctx, &officer2, mx5)
		if ferr != nil || outcome != "disposed" {
			t.Fatalf("mx5: the disposal did not complete after the holds released: outcome %q err %v", outcome, ferr)
		}
		checkDisposal("mx5", mx5, m5Refs)
		dump("c07r4-mx5-overlapping-holds.json", map[string]any{"turn": mx5, "holds": []string{h5a.ID, h5b.ID}})
	}
	// M6: a STORAGE ERROR mid-deletion (injected transient delete failure):
	// the deletion transaction never commits (interrupted database commit)
	// although some deletes already took physical effect.
	{
		mx6Refs := refsOf(mx6)
		m6Admission := admissionOf(mx6Refs)
		m6Ev0 := eventZeroDataOf(mx6Refs)
		protect(m6Admission, m6Ev0)
		if _, err := svcRecords.Sweep(ctx, officer1); err != nil {
			t.Fatal(err)
		}
		if outcome, serr := svcRecords.Store.BeginPurge(ctx, officer2, mx6, func(context.Context, pgx.Tx, string) (bool, error) {
			return true, nil
		}); serr != nil || outcome != "purging" {
			t.Fatalf("mx6 begin: %s %v", outcome, serr)
		}
		m6Terminal := slotMarkerOf(mx6Refs, highestSlotSeq(mx6Refs))
		svcStorage.mu.Lock()
		svcStorage.failDeleteKV = m6Terminal.Key + "|" + m6Terminal.Version
		svcStorage.armed = true
		svcStorage.mu.Unlock()
		_, _, ierr := svcRecords.FinishPurge(ctx, &officer2, mx6)
		svcStorage.mu.Lock()
		svcStorage.armed = false
		svcStorage.mu.Unlock()
		if ierr == nil || !strings.Contains(ierr.Error(), "injected transient delete failure") {
			t.Fatalf("mx6 setup: the interrupted FinishPurge must fail on the injected storage error (got %v)", ierr)
		}
		// The versions before the fault in deletion order are physically
		// deleted while the disposition transaction rolled back: the
		// interrupted-database-commit shape.
		if it := itemState(mx6); it != records.ItemPurging {
			t.Fatalf("mx6 setup: the record must stay purging after the interrupted commit (state %s)", it)
		}
		unprotect(m6Admission, m6Ev0)
		completeDisposal("mx6", mx6)
		checkDisposal("mx6", mx6, mx6Refs)
		dump("c07r4-mx6-storage-error.json", map[string]any{"turn": mx6, "faulted_delete": m6Terminal.Key})
	}
	// The unrelated intact record remained operational throughout the
	// matrix: its disposal converges through the ordinary path.
	{
		if _, err := svcRecords.Sweep(ctx, officer1); err != nil {
			t.Fatal(err)
		}
		if outcome, serr := svcRecords.Store.BeginPurge(ctx, officer2, mxU, func(context.Context, pgx.Tx, string) (bool, error) {
			return true, nil
		}); serr != nil || outcome != "purging" {
			t.Fatalf("mx-unrelated begin: %s %v", outcome, serr)
		}
		outcome, _, ferr := svcRecords.FinishPurge(ctx, &officer2, mxU)
		if ferr != nil || outcome != "disposed" {
			t.Fatalf("MX: the unrelated intact record's disposal failed: outcome %q err %v", outcome, ferr)
		}
		checkDisposal("mx-unrelated", mxU, mxURefs)
		dump("c07r4-mx-unrelated-operational.json", map[string]any{"turn": mxU})
	}
}

func refIn(refs []evidence.VersionRef, r evidence.VersionRef) bool {
	for _, x := range refs {
		if x == r {
			return true
		}
	}
	return false
}

// faultingRecordsStorage wraps the records-scoped storage client with a
// transient DELETE failure for one exact version (the matrix's
// storage-error/interrupted-commit injection). Every other operation is the
// real pinned storage.
type faultingRecordsStorage struct {
	inner        records.RecordsStorage
	mu           sync.Mutex
	failDeleteKV string
	armed        bool
}

func (f *faultingRecordsStorage) LegalHold(ctx context.Context, key, version string) (string, error) {
	return f.inner.LegalHold(ctx, key, version)
}

func (f *faultingRecordsStorage) SetLegalHold(ctx context.Context, key, version string, on bool) error {
	return f.inner.SetLegalHold(ctx, key, version, on)
}

func (f *faultingRecordsStorage) Head(ctx context.Context, key, version string) error {
	return f.inner.Head(ctx, key, version)
}

func (f *faultingRecordsStorage) DeleteVersion(ctx context.Context, key, version string) error {
	f.mu.Lock()
	armed, kv := f.armed, f.failDeleteKV
	f.mu.Unlock()
	if armed && kv == key+"|"+version {
		return fmt.Errorf("injected transient delete failure for %s", key)
	}
	return f.inner.DeleteVersion(ctx, key, version)
}
