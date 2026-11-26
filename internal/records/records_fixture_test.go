package records_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

const issuer = "https://idp.test"

// fakeBackend supplies the authoritative inventory and version enumeration
// the lifecycle needs. Evidence write methods are never called by the
// lifecycle; the embedded nil keeps the interface satisfied.
type fakeBackend struct {
	evidence.Backend
	mu      sync.Mutex
	turns   map[string][]evidence.TurnIdentity // tenant -> turns
	refs    map[string][]evidence.VersionRef   // turn -> versions
	missing map[string]bool                    // turn -> versions gone
	noRefs  map[string]bool                    // turn listed but versions fail
}

func newFakeBackend() *fakeBackend {
	return &fakeBackend{turns: map[string][]evidence.TurnIdentity{}, refs: map[string][]evidence.VersionRef{}, missing: map[string]bool{}, noRefs: map[string]bool{}}
}

func (b *fakeBackend) addTurn(t evidence.TurnIdentity, refs []evidence.VersionRef) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.turns[t.TenantID] = append(b.turns[t.TenantID], t)
	b.refs[t.TurnID] = refs
}

func (b *fakeBackend) InventoryTurns(ctx context.Context, tenantID string) ([]evidence.TurnIdentity, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]evidence.TurnIdentity(nil), b.turns[tenantID]...), nil
}

func (b *fakeBackend) TurnVersionRefs(ctx context.Context, tenantID, turnID string) ([]evidence.VersionRef, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.missing[turnID] || b.noRefs[turnID] {
		return nil, evidence.ErrNotFound
	}
	refs, ok := b.refs[turnID]
	if !ok {
		return nil, evidence.ErrNotFound
	}
	return append([]evidence.VersionRef(nil), refs...), nil
}

// fakeStorage implements RecordsStorage with the pinned storage's verified
// native semantics: a version under legal hold ON cannot be deleted, deletes
// are refused while base retention is unexpired, deletion is idempotent.
type fakeStorage struct {
	mu               sync.Mutex
	legalHold        map[string]string // key|version -> ON/OFF/""
	deleted          map[string]bool
	protect          map[string]time.Time // key|version -> base retention until
	failSet          error
	failRead         error
	failDelete       error
	failOnce         sync.Map
	legalHoldAfter   string // when set, readback reports this regardless of writes
	partialDeleteKey string // when set with failOnce, this key deletes; others fail
}

func newFakeStorage() *fakeStorage {
	return &fakeStorage{legalHold: map[string]string{}, deleted: map[string]bool{}, protect: map[string]time.Time{}}
}

func vkey(key, version string) string { return key + "|" + version }

func (f *fakeStorage) LegalHold(ctx context.Context, key, version string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRead != nil {
		if once, _ := f.failOnce.LoadOrStore("read", true); once.(bool) && f.failRead != errClearOnce {
			return "", f.failRead
		}
	}
	if f.deleted[vkey(key, version)] {
		return "", s3transport.ErrObjectAbsent
	}
	if f.legalHoldAfter != "" {
		return f.legalHoldAfter, nil
	}
	return f.legalHold[vkey(key, version)], nil
}

func (f *fakeStorage) SetLegalHold(ctx context.Context, key, version string, on bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSet != nil {
		if once, _ := f.failOnce.LoadOrStore("set", true); once.(bool) && f.failSet != errClearOnce {
			return f.failSet
		}
	}
	if f.deleted[vkey(key, version)] {
		return s3transport.ErrObjectAbsent
	}
	if on {
		f.legalHold[vkey(key, version)] = "ON"
	} else {
		f.legalHold[vkey(key, version)] = "OFF"
	}
	return nil
}

func (f *fakeStorage) DeleteVersion(ctx context.Context, key, version string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDelete != nil {
		if once, _ := f.failOnce.LoadOrStore("delete", true); once.(bool) && f.failDelete != errClearOnce {
			if f.partialDeleteKey == "" || f.partialDeleteKey != vkey(key, version) {
				return f.failDelete
			}
		}
	}
	k := vkey(key, version)
	if f.deleted[k] {
		return s3transport.ErrObjectAbsent
	}
	if f.legalHold[k] == "ON" {
		return s3transport.ErrObjectProtected
	}
	if until, ok := f.protect[k]; ok && until.After(time.Now()) {
		return s3transport.ErrObjectProtected
	}
	f.deleted[k] = true
	return nil
}

func (f *fakeStorage) isDeleted(key, version string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deleted[vkey(key, version)]
}

func (f *fakeStorage) holdState(key, version string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.legalHold[vkey(key, version)]
}

var errClearOnce = errors.New("clear-once")

// rfx is the C07 lifecycle fixture: one tenant with two matters (m1 has
// projects p1/p2 mapped to it for shared-matter tests), records officers
// carol and erin (separation of duties), admin dave, members alice/bob, and
// a second tenant (zed) for cross-tenant controls.
type rfx struct {
	t    *testing.T
	pool *pgxpool.Pool
	st   *store.Store
	rs   *records.Store
	svc  *records.Service
	fb   *fakeBackend
	fs   *fakeStorage

	tenant, other string
	u             map[string]string
	p1, p2        string // p1 and p2 both map to matter m1
	m1, m2        string
	turns         []string
	labelled      map[string]string
	byLabel       map[string]string
}

func newRfx(t *testing.T) *rfx {
	t.Helper()
	pool := testdb.New(t)
	ctx := context.Background()
	st := &store.Store{DB: pool}
	f := &rfx{t: t, pool: pool, st: st, u: map[string]string{}, fb: newFakeBackend(), fs: newFakeStorage(), labelled: map[string]string{}, byLabel: map[string]string{}}
	ok := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	f.tenant = ok(st.CreateTenant(ctx, issuer, "tid-a", "A"))
	f.other = ok(st.CreateTenant(ctx, issuer, "tid-b", "B"))
	for _, n := range []string{"alice", "bob", "carol", "erin", "dave", "frank"} {
		f.u[n] = ok(st.CreateUser(ctx, f.tenant, "sub-"+n, n))
	}
	f.u["zed"] = ok(st.CreateUser(ctx, f.other, "sub-zed", "zed"))
	f.p1 = ok(st.CreateProject(ctx, f.tenant, "P1"))
	f.p2 = ok(st.CreateProject(ctx, f.tenant, "P2"))
	pOther := ok(st.CreateProject(ctx, f.other, "PB"))
	// Bind matters: both projects of tenant A map to matter m1 except p2,
	// which gets its own matter m2 (two matters, two projects).
	if _, err := pool.Exec(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.p1); err != nil {
		t.Fatal(err)
	}
	var m1, m2 string
	if err := pool.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.p1).Scan(&m1); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, f.p2).Scan(&m2); err != nil {
		t.Fatal(err)
	}
	f.m1, f.m2 = m1, m2
	// p2 keeps its own matter; tests that want both matters separate rely on it.
	for _, m := range [][2]string{{"alice", f.p1}, {"bob", f.p2}} {
		if err := st.SeedMember(ctx, f.tenant, m[1], f.u[m[0]]); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SeedMember(ctx, f.other, pOther, f.u["zed"]); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"carol", "erin"} {
		if err := st.SeedRole(ctx, f.tenant, f.u[n], store.RoleRecordsOfficer); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.SeedRole(ctx, f.tenant, f.u["dave"], store.RoleTenantAdmin); err != nil {
		t.Fatal(err)
	}
	if err := st.SeedRole(ctx, f.tenant, f.u["frank"], store.RoleOperator); err != nil {
		t.Fatal(err)
	}
	f.rs = &records.Store{DB: pool}
	f.svc = &records.Service{Store: f.rs, Backend: f.fb, Storage: f.fs, Retained: true, Logf: func(string, ...any) {}}
	// Fast synthetic policy: retention 1s, no grace.
	if err := f.rs.SetPolicy(ctx, f.principal("carol"), 1, 0); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *rfx) principal(name string) store.Principal {
	f.t.Helper()
	tid := "tid-a"
	if name == "zed" {
		tid = "tid-b"
	}
	p, err := f.st.Resolve(context.Background(), issuer, tid, "sub-"+name)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

// seedTurn adds a synthetic admitted turn whose recorded_at is already past
// retention expiry so sweeps can act immediately. The id is a stable UUID
// derived from the label (retention_items.turn_id is a uuid column).
func (f *rfx) seedTurn(label, project, matter, custodian string, shared ...string) string {
	f.t.Helper()
	id := evidence.NewUUID()
	f.labelled[id] = label
	f.byLabel[label] = id
	now := time.Now().UTC()
	t := evidence.TurnIdentity{
		TenantID: f.tenant, ProjectID: project, MatterID: matter,
		CustodianID: custodian, TurnID: id, RecordedAt: now.Add(-2 * time.Hour),
	}
	var refs []evidence.VersionRef
	refs = append(refs, evidence.VersionRef{Key: "ns/" + id + "/admissions/x", Version: "v-" + id + "-0"})
	refs = append(refs, evidence.VersionRef{Key: "ns/" + id + "/events/0", Version: "v-" + id + "-1"})
	refs = append(refs, evidence.VersionRef{Key: "ns/" + id + "/data/events/h", Version: "v-" + id + "-2"})
	refs = append(refs, evidence.VersionRef{Key: "ns/" + id + "/objects/own", Version: "v-" + id + "-3"})
	for i, s := range shared {
		refs = append(refs, evidence.VersionRef{Key: "ns/objects/" + s, Version: "v-shared-" + fmt.Sprint(i) + "-" + s})
	}
	f.fb.addTurn(t, refs)
	f.turns = append(f.turns, id)
	return id
}

func (f *rfx) sweepAs(name string) int {
	f.t.Helper()
	turns, err := f.svc.Inventory(context.Background(), f.principal(name))
	if err != nil {
		f.t.Fatal(err)
	}
	policy, err := f.rs.Policy(context.Background(), f.tenant)
	if err != nil {
		f.t.Fatal(err)
	}
	marked, err := f.rs.Sweep(context.Background(), f.principal(name), turns, policy)
	if err != nil {
		f.t.Fatal(err)
	}
	return marked
}

func (f *rfx) item(label string) records.Item {
	f.t.Helper()
	return f.itemByID(f.turnID(label))
}

func (f *rfx) itemByID(turn string) records.Item {
	f.t.Helper()
	items, err := f.rs.Items(context.Background(), f.principal("carol"))
	if err != nil {
		f.t.Fatal(err)
	}
	for _, it := range items {
		if it.TurnID == turn {
			return it
		}
	}
	f.t.Fatalf("item %s not in catalog", turn)
	return records.Item{}
}

func (f *rfx) placeHold(name, matter, reason string, custodians ...string) *records.Hold {
	f.t.Helper()
	h, err := f.svc.Place(context.Background(), f.principal(name), records.Scope{MatterID: matter, CustodianIDs: custodians}, reason, "idem-"+reason+"-"+fmt.Sprint(len(custodians)))
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *rfx) ctx() context.Context { return context.Background() }

// ---- ADR 0001 section 7 hold matching, shared with the Python fixtures ----

func loadHoldsFixture(t *testing.T) map[string]any {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "fixtures", "contracts", "holds.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f map[string]any
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestHoldMatchingFollowsSharedFixture(t *testing.T) {
	f := loadHoldsFixture(t)
	holds, _ := f["holds"].([]any)
	items, _ := f["items"].([]any)
	// H1: all custodians of m-0001; H2: custodian c1 only.
	mustMatch := map[string][]string{
		"A": {"H1", "H2"},
		"B": {"H1"},
	}
	for _, iv := range items {
		it := iv.(map[string]any)
		id := it["id"].(string)
		matter := it["matter_id"].(string)
		custodian := it["custodian_id"].(string)
		recorded, err := time.Parse("2006-01-02", it["recorded_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		var matched []string
		for _, hv := range holds {
			h := hv.(map[string]any)
			hold := &records.Hold{MatterID: h["matter_id"].(string)}
			if cs, ok := h["custodian_ids"].([]any); ok {
				for _, c := range cs {
					hold.CustodianIDs = append(hold.CustodianIDs, c.(string))
				}
			}
			if ws, ok := h["window_start"].(string); ok {
				w, err := time.Parse("2006-01-02", ws)
				if err != nil {
					t.Fatal(err)
				}
				hold.WindowStart = &w
			}
			if records.Matches(hold, matter, custodian, recorded) {
				matched = append(matched, h["id"].(string))
			}
		}
		sortStrings(matched)
		want := mustMatch[id]
		if want == nil {
			want = []string{}
		}
		if !equalStrings(matched, want) {
			t.Fatalf("item %s matched %v, want %v", id, matched, want)
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestWindowMatchingBoundaries(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	h := &records.Hold{MatterID: "m", WindowStart: &start, WindowEnd: &end}
	in := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	before := start.Add(-time.Second)
	atStart := start
	atEnd := end
	after := end.Add(time.Second)
	if !records.Matches(h, "m", "c", in) {
		t.Fatal("in-window record must match")
	}
	if records.Matches(h, "m", "c", before) {
		t.Fatal("record before window_start must not match")
	}
	if !records.Matches(h, "m", "c", atStart) {
		t.Fatal("window_start is inclusive")
	}
	if records.Matches(h, "m", "c", atEnd) {
		t.Fatal("window_end is exclusive (future work stops at window_end)")
	}
	if records.Matches(h, "m", "c", after) {
		t.Fatal("record after window_end must not match")
	}
	// Open-ended window covers future work until release.
	open := &records.Hold{MatterID: "m"}
	if !records.Matches(open, "m", "c", time.Now().Add(time.Hour)) {
		t.Fatal("open-ended hold must cover future work")
	}
}

// turnID resolves a fixture label to its UUID turn id.
func (f *rfx) turnID(label string) string {
	f.t.Helper()
	id, ok := f.byLabel[label]
	if !ok {
		f.t.Fatalf("no seeded turn %q", label)
	}
	return id
}
