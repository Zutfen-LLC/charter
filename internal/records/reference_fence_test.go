package records_test

// Finding 6B reproduction (RED at REVIEWED_HEAD): the shared-reference scan
// of a disposal and a concurrent capture that acquires a reference to the
// SAME exact content-addressed object version are not serialized. A capture
// that stages + publishes between the disposal's reference snapshot and its
// irreversible delete ends up referencing deleted bytes: its acknowledged
// evidence chain no longer verifies.
//
// The disposal is frozen deterministically at its first content-addressed
// object delete (service hook). The capture then admits; the interleaving is
// forced with channels. At the corrected head the capture serializes on the
// tenant protection fence and stages a fresh version instead.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

// fenceMem is an in-memory retained transport with the storage-native
// protection semantics the lifecycle depends on: version-specific deletes,
// legal holds blocking deletes, idempotent absence, and version listings
// that no longer contain deleted versions.
type fenceMem struct {
	mu        sync.Mutex
	objects   map[string]map[string]s3transport.Version
	legalHold map[string]string
	deleted   map[string]bool
	version   int
}

func newFenceMem() *fenceMem {
	return &fenceMem{objects: map[string]map[string]s3transport.Version{}, legalHold: map[string]string{}, deleted: map[string]bool{}}
}

func (m *fenceMem) Bucket() string { return "archive" }

func (m *fenceMem) Create(_ context.Context, key string, b []byte, until time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.version++
	id := fmt.Sprintf("v%d", m.version)
	if m.objects[key] == nil {
		m.objects[key] = map[string]s3transport.Version{}
	}
	m.objects[key][id] = s3transport.Version{ID: id, Data: append([]byte(nil), b...), Mode: "COMPLIANCE", Until: until}
	return id, nil
}

func (m *fenceMem) Read(_ context.Context, key, id string) (s3transport.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleted[key+"|"+id] {
		return s3transport.Version{}, s3transport.ErrObjectAbsent
	}
	v, ok := m.objects[key][id]
	if !ok {
		return s3transport.Version{}, s3transport.ErrObjectAbsent
	}
	return v, nil
}

func (m *fenceMem) Versions(_ context.Context, prefix string) ([]s3transport.Ref, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []s3transport.Ref
	for k, vs := range m.objects {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		ids := make([]string, 0, len(vs))
		for id := range vs {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if m.deleted[k+"|"+id] {
				continue
			}
			out = append(out, s3transport.Ref{Key: k, VersionID: id})
		}
	}
	return out, nil
}

func (m *fenceMem) LegalHold(_ context.Context, key, version string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleted[key+"|"+version] {
		return "", s3transport.ErrObjectAbsent
	}
	return m.legalHold[key+"|"+version], nil
}

func (m *fenceMem) Head(_ context.Context, key, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleted[key+"|"+version] {
		return s3transport.ErrObjectAbsent
	}
	return nil
}

func (m *fenceMem) SetLegalHold(_ context.Context, key, version string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.deleted[key+"|"+version] {
		return s3transport.ErrObjectAbsent
	}
	if on {
		m.legalHold[key+"|"+version] = "ON"
	} else {
		m.legalHold[key+"|"+version] = "OFF"
	}
	return nil
}

func (m *fenceMem) DeleteVersion(_ context.Context, key, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := key + "|" + version
	if m.deleted[k] {
		return s3transport.ErrObjectAbsent
	}
	if m.legalHold[k] == "ON" {
		return s3transport.ErrObjectProtected
	}
	m.deleted[k] = true
	return nil
}

// rfxRetained is a records fixture whose backend is a REAL RetentionBackend
// over the in-memory transport, driven through the REAL recorder.
type rfxRetained struct {
	t        *testing.T
	pool2    *pgxpool.Pool
	rs       *records.Store
	svc      *records.Service
	st       *store.Store
	mem      *fenceMem
	backend  *evidence.RetentionBackend
	recorder *evidence.Recorder
	fence    *evidence.Fence

	tenant, project, matter, custodian string
	carol, erin                        string
}

func newRfxRetained(t *testing.T) *rfxRetained {
	t.Helper()
	ctx := context.Background()
	pool := testdb.New(t)
	st := &store.Store{DB: pool}
	mem := newFenceMem()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pg := evidence.PG{DB: pool}
	fence, err := pg.AcquireFence(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fence.Release)
	b, err := evidence.NewRetentionBackend(evidence.RetentionOptions{
		Store: mem, Deployment: "synthetic", Bucket: mem.Bucket(), TrustedCommitKey: pub,
		Signer: priv, Fence: fence, RetainFor: time.Hour, MinimumRetention: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	f := &rfxRetained{t: t, st: st, mem: mem, backend: b, fence: fence, pool2: pool}
	ok := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	f.tenant = ok(st.CreateTenant(ctx, issuer, "tid-r", "R"))
	p := ok(st.CreateProject(ctx, f.tenant, "PR"))
	f.project = p
	var matter string
	if err := pool.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	f.matter = matter
	f.carol = ok(st.CreateUser(ctx, f.tenant, "sub-carol", "carol"))
	f.erin = ok(st.CreateUser(ctx, f.tenant, "sub-erin", "erin"))
	f.custodian = ok(st.CreateUser(ctx, f.tenant, "sub-cust", "cust"))
	if err := st.SeedMember(ctx, f.tenant, p, f.custodian); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{f.carol, f.erin} {
		if err := st.SeedRole(ctx, f.tenant, n, store.RoleRecordsOfficer); err != nil {
			t.Fatal(err)
		}
	}
	f.rs = &records.Store{DB: pool}
	f.svc = &records.Service{Store: f.rs, Backend: b, Storage: mem, Retained: true, Logf: func(string, ...any) {}}
	f.recorder = &evidence.Recorder{Fence: fence, Backend: b, Lifecycle: f.svc, Logf: func(string, ...any) {},
		Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
			return evidence.Decision{Allow: true, PolicyVersion: "policy", ReserveUnits: 3, Destination: evidence.Destination{Provider: "mock", EndpointID: "local", ModelID: "model"}}, nil
		}}
	// Fast synthetic lifecycle policy: retention 1s, no grace.
	if err := f.rs.SetPolicy(ctx, f.principal("carol"), 1, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *rfxRetained) principal(name string) store.Principal {
	f.t.Helper()
	sub := "sub-" + name
	if name == "cust" {
		sub = "sub-cust"
	}
	p, err := f.st.Resolve(context.Background(), issuer, "tid-r", sub)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *rfxRetained) processTurn(idem string, inT2 *atomic.Bool, modelSignal, modelProceed chan struct{}) (string, error) {
	input := []byte("shared exact synthetic input")
	output := []byte("shared exact output")
	call := func(context.Context, []byte) (evidence.ModelOutcome, error) {
		if inT2 != nil && modelSignal != nil && inT2.Load() {
			close(modelSignal)
			<-modelProceed
		}
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: output}, nil
	}
	res, err := f.recorder.Process(context.Background(), evidence.Request{
		TenantID: f.tenant, ProjectID: f.project, MatterID: f.matter, CustodianID: f.custodian,
		IdempotencyKey: idem, RequestID: "req-" + idem, Input: input,
	}, call, func(context.Context) error { return nil })
	if err != nil {
		return "", err
	}
	return res.TurnID, nil
}

func TestDisposalCannotDeleteVersionAcquiredByConcurrentCapture(t *testing.T) {
	f := newRfxRetained(t)
	ctx := context.Background()

	// T1: a complete turn whose input and output objects are content-addressed.
	t1, err := f.processTurn("idem-t1", nil, nil, nil)
	if err != nil {
		t.Fatalf("T1 capture failed: %v", err)
	}
	// Retention expiry for the lifecycle (storage-side retention is already
	// expired in the synthetic transport).
	time.Sleep(1200 * time.Millisecond)
	if marked, err := f.svc.Sweep(ctx, f.principal("carol")); err != nil || marked != 1 {
		t.Fatalf("sweep marked %d (err %v), want 1", marked, err)
	}
	if outcome, err := f.rs.BeginPurge(ctx, f.principal("erin"), t1, func(c context.Context, turnID string) (bool, error) {
		return f.svc.VersionPresent(c, f.tenant, turnID), nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("begin outcome %s err %v", outcome, err)
	}

	// Freeze the disposal immediately before its first content-addressed
	// object delete (after the shared-reference snapshot).
	paused := make(chan struct{})
	resume := make(chan struct{})
	var once sync.Once
	f.svc.Hooks.BeforeStorageDelete = func(key, version string) {
		if strings.Contains(key, "/data/objects/") {
			once.Do(func() {
				close(paused)
				<-resume
			})
		}
	}
	disposalDone := make(chan error, 1)
	var outcome atomic.Value
	go func() {
		o, _, err := f.svc.FinishPurge(ctx, nil, t1)
		outcome.Store(o)
		disposalDone <- err
	}()
	<-paused

	// T2: concurrent capture of the SAME content (same content-addressed
	// object versions).
	inT2 := &atomic.Bool{}
	inT2.Store(true)
	modelSignal := make(chan struct{})
	modelProceed := make(chan struct{})
	t2done := make(chan error, 1)
	var t2turn atomic.Value
	go func() {
		id, err := f.processTurn("idem-t2", inT2, modelSignal, modelProceed)
		t2turn.Store(id)
		t2done <- err
	}()

	// Either T2 publishes its reference during the frozen disposal (the racy
	// interleaving, at the reviewed head), or T2 is blocked on the protection
	// fence waiting for the disposal (at the corrected head: its own lock
	// waiter appears in pg_stat_activity under this test's schema name).
	lockWaiter := make(chan struct{})
	schema := f.svc.Store.DB.Config().ConnConfig.RuntimeParams["search_path"]
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			var n int
			if err := f.svc.Store.DB.Ping(ctx); err == nil {
				if err := f.svc.Store.DB.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'`, schema).Scan(&n); err == nil && n > 0 {
					close(lockWaiter)
					return
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	admitted := make(chan struct{})
	go func() {
		<-modelSignal // T2's admission is fully published before the model call
		close(admitted)
	}()
	select {
	case <-admitted:
		// RED interleaving: T2's reference is published while the disposal
		// is frozen at its delete.
	case <-lockWaiter:
		// GREEN interleaving: T2 is fenced out until the disposal completes.
	case <-time.After(5 * time.Second):
		t.Fatal("neither admission nor fence wait observed")
	}
	close(resume)
	// Let T2's model call finish after the disposal has committed its deletes.
	if err := <-disposalDone; err != nil {
		t.Fatalf("disposal failed: %v", err)
	}
	close(modelProceed)
	if err := <-t2done; err != nil {
		t.Fatalf("T2 capture failed: %v", err)
	}
	t2, _ := t2turn.Load().(string)
	if t2 == "" {
		t.Fatal("T2 turn id missing")
	}

	// The disposal itself completed.
	if o, _ := outcome.Load().(string); o != "disposed" {
		t.Fatalf("disposal outcome %q, want disposed", o)
	}
	// THE invariant: the acknowledged, unheld, completed turn T2 keeps a
	// verifiable evidence chain with its retained objects available.
	if _, err := f.backend.Load(ctx, f.tenant, t2); err != nil {
		t.Fatalf("FINDING 6B: concurrent capture's evidence chain broken by another turn's disposal: %v", err)
	}
	events, err := f.backend.Load(ctx, f.tenant, t2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.backend.LoadRetainedObjects(ctx, f.tenant, t2, events); err != nil {
		t.Fatalf("FINDING 6B: concurrent capture's retained objects unavailable: %v", err)
	}
}

var _ = errors.New

// TestGuardedCaptureUnderEffectiveHold completes: the R3 drill shape (a hold
// effective over the matter, then new matching work through the recorder).
func TestGuardedCaptureUnderEffectiveHold(t *testing.T) {
	f := newRfxRetained(t)
	ctx := context.Background()
	t1, err := f.processTurn("idem-g1", nil, nil, nil)
	if err != nil {
		t.Fatalf("baseline capture failed: %v", err)
	}
	var matter string
	if err := f.pool2.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.project).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	h, err := f.svc.Place(ctx, f.principal("carol"), records.Scope{MatterID: matter}, "R3 local", "idem-g-hold")
	if err != nil {
		t.Fatalf("hold placement failed: %v", err)
	}
	if h.State != records.HoldEffective {
		t.Fatalf("hold state %s", h.State)
	}
	// New matching work admitted while the hold is effective.
	_, err = f.processTurn("idem-g2", nil, nil, nil)
	if err != nil {
		t.Fatalf("FINDING R3: guarded capture failed: %v", err)
	}
	_ = t1
}
