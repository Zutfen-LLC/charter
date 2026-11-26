package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/routing"
	"github.com/Zutfen-LLC/charter/internal/sharepoint"
	"github.com/jackc/pgx/v5"
	"testing"
)

func TestC06ExternalSourcesDisabledByDefault(t *testing.T) {
	e := newEnv(t)
	status, out, _ := e.post("alice", e.p1, `{"input":"synthetic","sharepoint_sources":[{"document_id":"synthetic-doc","version":"1.0","offset":0,"length":4}]}`, "Idempotency-Key", "c06-disabled")
	if status != http.StatusServiceUnavailable {
		t.Fatalf("expected recognized but disabled SharePoint boundary, got %d: %s", status, out)
	}
}

const c06Source = `{"document_id":"sp-document","version":"1.0","offset":3,"length":9}`
const c06Body = `{"input":"summary","sharepoint_sources":[` + c06Source + `]}`

func c06Document(id, version, etag, body string) sharepoint.Document {
	return sharepoint.Document{Metadata: sharepoint.Metadata{TenantID: "external-tenant", SiteID: "site", LibraryID: "library", DocumentID: id, Version: version, ETag: etag}, Content: []byte(body)}
}

func c06Fixture(t *testing.T) (*env, *sharepoint.Fake, *atomic.Int32) {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.SeedMember(ctx, e.tenant, e.p1, e.users["bob"]); err != nil {
		t.Fatal(err)
	}
	b := evidence.PG{DB: e.st.DB}
	if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: e.tenant, ProjectID: e.p1, LocalOnly: true, AllowedModels: []string{"det-a"}, ProjectCap: 10000000}); err != nil {
		t.Fatal(err)
	}
	f := sharepoint.NewFake()
	f.Put(c06Document("sp-document", "1.0", "etag-1", "abcRESTRICT!xyz"))
	f.Put(c06Document("second-doc", "8.2", "etag-8", "second restricted doc"))
	f.Grant("sp-document", "provider-alice", true)
	f.Grant("second-doc", "provider-alice", true)
	f.Grant("second-doc", "provider-bob", true)
	connector, err := sharepoint.New(sharepoint.Scope{ConnectorID: "one-library", TenantID: e.tenant, ProjectID: e.p1, ExternalTenantID: "external-tenant", SiteID: "site", LibraryID: "library", Delegates: map[string]string{e.users["alice"]: "provider-alice", e.users["bob"]: "provider-bob"}}, f)
	if err != nil {
		t.Fatal(err)
	}
	e.auth.SharePoint = connector
	calls := new(atomic.Int32)
	e.auth.Evidence = &evidence.Recorder{Backend: b, Governance: routing.Governance(routing.DefaultConfig(), b, true, func() { calls.Add(1) }), Accounting: b.ReconcileBudget}
	return e, f, calls
}

func c06Post(t *testing.T, e *env, user, p, key, body string, want int) map[string]any {
	t.Helper()
	status, out, _ := e.post(user, p, body, "Idempotency-Key", key)
	if status != want {
		t.Fatalf("%s/%s: %d want %d (%s)", user, key, status, want, out)
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	if want != 200 && result["output"] != nil {
		t.Fatal("denied call returned output")
	}
	return result
}

func TestC06MixedSourcesReplayAndWorkspaceIsolation(t *testing.T) {
	e, f, calls := c06Fixture(t)
	sub := `{"document_id":"second-doc","version":"8.2","offset":0,"length":6}`
	body := `{"input":"summary","artifact_ids":["` + e.a1 + `"],"sharepoint_sources":[` + c06Source + `,` + sub + `]}`
	first := c06Post(t, e, "alice", e.p1, "mixed", body, 200)
	turn := first["turn_id"].(string)
	b := evidence.PG{DB: e.st.DB}
	for _, ev := range e.verify(turn) {
		if ev["type"] != "context_sealed" {
			continue
		}
		seal := ev["payload"].(map[string]any)
		objects := seal["sources"].([]any)
		for i, want := range []string{"needle-one alpha", "RESTRICT!", "second"} {
			ref := objects[i].(map[string]any)
			if ref["sha256"] != evidence.SHA256([]byte(want)) {
				t.Fatalf("excerpt %d not bound", i)
			}
		}
		sent, err := b.Object(context.Background(), e.tenant, seal["request_sha256"].(string))
		if err != nil || !strings.Contains(string(sent), `"provider_version":"1.0","source_id":"sp-document","text":"RESTRICT!"`) || first["output"] != "synthetic c04 response for "+evidence.SHA256(sent) {
			t.Fatalf("exact provider binding failed (%v)", err)
		}
		t.Logf("source digest=%s request digest=%s", evidence.SHA256([]byte("RESTRICT!")), evidence.SHA256(sent))
	}
	replay := c06Post(t, e, "alice", e.p1, "mixed", body, 200)
	if replay["output"] != first["output"] || replay["turn_id"] != turn || replay["replayed"] != true || calls.Load() != 1 {
		t.Fatal("not an exact delivery-only replay")
	}
	c06Post(t, e, "alice", e.p1, "mixed", strings.Replace(body, c06Source+`,`+sub, sub+`,`+c06Source, 1), 422)
	c06Post(t, e, "bob", e.p1, "mixed", body, 404)
	c06Post(t, e, "alice", e.p1, "reuse-derivative", `{"input":"reuse","artifact_ids":["`+turn+`"]}`, 404)
	e.want("alice", "POST", "/v1/artifacts/"+turn+"/share", 404)
	c06Post(t, e, "alice", e.p2, "mixed", body, 404)
	for _, u := range []string{"carol", "dave", "frank"} {
		if err := e.st.SeedMember(context.Background(), e.tenant, e.p1, e.users[u]); err != nil {
			t.Fatal(err)
		}
		c06Post(t, e, u, e.p1, "mixed", body, 404)
	}
	for _, u := range []string{"alice", "bob"} {
		for _, id := range []string{turn, "sp-document"} {
			e.want(u, "GET", "/v1/artifacts/"+id, 404)
			e.want(u, "GET", "/v1/artifacts/"+id+"/content", 404)
		}
		for _, path := range []string{"/v1/projects/" + e.p1 + "/artifacts", "/v1/search?q=RESTRICT"} {
			if list := e.want(u, "GET", path, 200); strings.Contains(list, "RESTRICT") || strings.Contains(list, turn) {
				t.Fatal("workspace contained a restricted derivative")
			}
		}
	}
	f.Put(c06Document("sp-document", "1.0", "etag-1", "abcMODIFIED!xyz"))
	c06Post(t, e, "alice", e.p1, "mixed", body, 422)
	f.Put(c06Document("sp-document", "2.0", "etag-2", "abcMODIFIED!xyz"))
	c06Post(t, e, "alice", e.p1, "mixed", body, 409)
	c06Post(t, e, "alice", e.p1, "mixed", strings.Replace(body, `"1.0"`, `"2.0"`, 1), 422)
	f.Put(c06Document("sp-document", "1.0", "etag-1", "abcRESTRICT!xyz"))
	f.SetOutage(errors.New("synthetic outage"))
	c06Post(t, e, "alice", e.p1, "mixed", body, 503)
	f.SetOutage(nil)
	f.Grant("second-doc", "provider-alice", false)
	c06Post(t, e, "alice", e.p1, "mixed", body, 404)
	if calls.Load() != 1 {
		t.Fatal("unverified source or replay invoked the model")
	}
	sum, err := b.Summary(context.Background(), e.tenant, e.p1)
	if err != nil || sum.Outstanding != 0 || sum.Settled == 0 || sum.Unknown != 0 {
		t.Fatalf("unexpected accounting: %+v %v", sum, err)
	}
	t.Logf("model calls=%d source metadata operations=%d settled=%d", calls.Load(), f.MetadataCalls.Load(), sum.Settled)
}

func TestC06ConcurrentSameKeyAndUnauthorizedCaller(t *testing.T) {
	e, _, calls := c06Fixture(t)
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make(chan int, 9)
	for _, user := range []string{"alice", "alice", "alice", "alice", "alice", "alice", "alice", "alice", "bob"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			status, _, _ := e.post(user, e.p1, c06Body, "Idempotency-Key", "overlap")
			results <- status
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	counts := map[int]int{}
	for status := range results {
		counts[status]++
	}
	if counts[200] == 0 || counts[404] != 1 || counts[200]+counts[409] != 8 || calls.Load() != 1 {
		t.Fatalf("statuses=%v model=%d", counts, calls.Load())
	}
	c06Post(t, e, "alice", e.p1, "overlap", c06Body, 200)
	if calls.Load() != 1 {
		t.Fatal("retry redispatched")
	}
	t.Logf("statuses=%v model=%d", counts, calls.Load())
}

func TestC06RevocationAtEachBoundary(t *testing.T) {
	for _, tc := range []struct {
		name        string
		phase       int64
		invocations int32
		released    bool
	}{
		{"selection", 1, 0, false},
		{"context-eligibility", 2, 0, false},
		{"dispatch", 3, 0, false},
		{"release", 4, 1, false},
		{"delivery", 5, 1, true},
		{"http-delivery", 6, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, f, calls := c06Fixture(t)
			f.AfterRead = func() {
				if f.ReadCalls.Load() == tc.phase {
					f.Grant("sp-document", "provider-alice", false)
				}
			}
			c06Post(t, e, "alice", e.p1, "revoke", c06Body, 404)
			if calls.Load() != tc.invocations || f.ReadCalls.Load() != tc.phase {
				t.Fatalf("reached wrong stage: model=%d reads=%d", calls.Load(), f.ReadCalls.Load())
			}
			turns := e.turns()
			if tc.phase == 1 {
				if len(turns) != 0 {
					t.Fatal("failed selection admitted a turn")
				}
				return
			}
			if len(turns) != 1 {
				t.Fatal("expected one admitted turn")
			}
			evs := e.verify(turns[0])
			released := false
			for _, ev := range evs {
				if ev["type"] == "response_released" {
					released = true
				}
			}
			if released != tc.released {
				t.Fatalf("release authorization=%t", released)
			}
			var charge int64
			err := e.st.DB.QueryRow(context.Background(), `SELECT actual_amount FROM evidence_budget_reservations WHERE project_id=$1 AND idempotency_key='revoke'`, e.p1).Scan(&charge)
			if err != nil || (charge > 0) != (tc.invocations != 0) {
				t.Fatalf("charge=%d err=%v", charge, err)
			}
			c06Post(t, e, "alice", e.p1, "revoke", c06Body, 404)
			f.Grant("sp-document", "provider-alice", true)
			status := 409
			if tc.released {
				status = 200
			}
			c06Post(t, e, "alice", e.p1, "revoke", c06Body, status)
			if calls.Load() != tc.invocations {
				t.Fatal("permission restoration redispatched a turn")
			}
			t.Logf("phase=%s connector reads=%d model invocations=%d charge=%d release authorization=%t", tc.name, f.ReadCalls.Load(), calls.Load(), charge, released)
		})
	}
}

// Fail the actual evidence write without replacing its other PostgreSQL operations.
type c06WriteFault struct {
	evidence.Backend
	event, object string
	persistent    bool
	fired         bool
}

func (b *c06WriteFault) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	if (!b.fired || b.persistent) && b.event == e["type"] {
		b.fired = true
		return evidence.Receipt{}, errors.New("synthetic event failure")
	}
	return b.Backend.Append(ctx, e)
}
func (b *c06WriteFault) PutObject(ctx context.Context, tenant string, data []byte) (evidence.Receipt, error) {
	if !b.fired && b.object != "" && strings.HasPrefix(string(data), b.object) {
		b.fired = true
		return evidence.Receipt{}, errors.New("synthetic object failure")
	}
	return b.Backend.PutObject(ctx, tenant, data)
}
func TestC06DurabilityFailuresWithholdOutput(t *testing.T) {
	for _, tc := range []struct {
		name, event, object string
		invocations         int32
	}{
		{"source-object", "", "RESTRICT!", 0},
		{"context-seal", "context_sealed", "", 0},
		{"intent-ack", "evidence_ack", "", 0},
		{"output-object", "", "synthetic c04 response for ", 1},
		{"output-event", "output_recorded", "", 1},
		{"release-authorization", "response_released", "", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _, calls := c06Fixture(t)
			fault := &c06WriteFault{Backend: e.auth.Evidence.Backend, event: tc.event, object: tc.object}
			e.auth.Evidence.Backend = fault
			c06Post(t, e, "alice", e.p1, "fault", c06Body, 503)
			if !fault.fired || calls.Load() != tc.invocations {
				t.Fatalf("fault fired=%t model=%d", fault.fired, calls.Load())
			}
			turns := e.turns()
			if len(turns) != 1 {
				t.Fatal("expected one turn")
			}
			e.verify(turns[0])
			c06Post(t, e, "alice", e.p1, "fault", c06Body, 409)
			if calls.Load() != tc.invocations {
				t.Fatal("retry redispatched")
			}
		})
	}
}

// c06IntentAckObserver records when the disclosure intent has been durably
// acknowledged so a test can commit policy state during the final delegated
// source revalidation that follows it, deterministically, at any head.
type c06IntentAckObserver struct {
	evidence.Backend
	seenIntent bool
	acked      atomic.Bool
}

func (b *c06IntentAckObserver) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	if typ, ok := e["type"].(string); ok {
		switch typ {
		case "disclosure_intent":
			b.seenIntent = true
		case "evidence_ack":
			if b.seenIntent {
				b.acked.Store(true)
			}
		}
	}
	return b.Backend.Append(ctx, e)
}

// TestC06RouteRevocationDuringFinalSourceRevalidation pins the dispatch
// ordering: a project routing-policy change committed while the final
// delegated source revalidation is in flight (after the intent is durable,
// with source ACLs, version, bytes and membership still valid) must prevent
// the model invocation. Route authorization is re-resolved after the
// connector operations, as close to invocation as practicable.
func TestC06RouteRevocationDuringFinalSourceRevalidation(t *testing.T) {
	e, f, calls := c06Fixture(t)
	b := evidence.PG{DB: e.st.DB}
	observer := &c06IntentAckObserver{Backend: e.auth.Evidence.Backend}
	e.auth.Evidence.Backend = observer
	revoked := false
	f.AfterRead = func() {
		if observer.acked.Load() && !revoked {
			revoked = true
			if err := b.SetPolicy(context.Background(), evidence.BudgetPolicy{
				TenantID: e.tenant, ProjectID: e.p1, LocalOnly: true,
				AllowedModels: []string{"det-b"}, ProjectCap: 10000000,
			}); err != nil {
				t.Error(err)
			}
		}
	}
	c06Post(t, e, "alice", e.p1, "route-revoke", c06Body, http.StatusForbidden)
	if !revoked {
		t.Fatal("routing-policy change was never committed during source revalidation")
	}
	if calls.Load() != 0 {
		t.Fatalf("model invoked despite committed route revocation: %d invocations", calls.Load())
	}
	turns := e.turns()
	if len(turns) != 1 {
		t.Fatalf("expected one admitted turn, got %d", len(turns))
	}
	evs := e.verify(turns[0])
	for _, ev := range evs {
		switch ev["type"] {
		case "provider_accepted", "output_recorded", "response_released":
			t.Fatalf("output or release authorization followed the route revocation: %v", ev["type"])
		}
	}
	last := evs[len(evs)-1]
	if last["type"] != evidence.TypeTurnInterrupted {
		t.Fatalf("turn did not end interrupted: %v", last["type"])
	}
	if reason := last["payload"].(map[string]any)["reason"]; reason != "route_revoked_before_dispatch" {
		t.Fatalf("interrupt reason = %v", reason)
	}
	// Proven non-dispatch: zero settled charge, no stranded reservation, no
	// unknown exposure, and no fallback or alternate-model dispatch (calls
	// counts every synthetic adapter invocation).
	sum, err := b.Summary(context.Background(), e.tenant, e.p1)
	if err != nil || sum.Outstanding != 0 || sum.Unknown != 0 {
		t.Fatalf("accounting after non-dispatch: %+v %v", sum, err)
	}
	var charge int64
	if err := e.st.DB.QueryRow(context.Background(),
		`SELECT actual_amount FROM evidence_budget_reservations WHERE project_id=$1 AND idempotency_key='route-revoke'`, e.p1).Scan(&charge); err != nil || charge != 0 {
		t.Fatalf("charge=%d err=%v", charge, err)
	}
	t.Logf("route revoked during final revalidation: reads=%d model invocations=%d charge=%d", f.ReadCalls.Load(), calls.Load(), charge)
}

// TestC06ContextEligibilityPrecedesSealing pins the context-eligibility
// ordering: a source revoked after the initial selection read completed, but
// before the first context-eligibility revalidation, can never become sealed
// model context. The full evidence chain and referenced objects are inspected,
// not only the HTTP status and invocation count.
func TestC06ContextEligibilityPrecedesSealing(t *testing.T) {
	e, f, calls := c06Fixture(t)
	// Revoke the delegated source grant between the completed selection read
	// and the first context-eligibility revalidation: BeforeRead fires inside
	// the second connector read, after the selection read fully completed.
	f.BeforeRead = func() {
		if f.ReadCalls.Load() == 2 {
			f.Grant("sp-document", "provider-alice", false)
		}
	}
	c06Post(t, e, "alice", e.p1, "eligibility", c06Body, http.StatusNotFound)
	if calls.Load() != 0 {
		t.Fatalf("ineligible source dispatched: %d invocations", calls.Load())
	}
	turns := e.turns()
	if len(turns) != 1 {
		t.Fatalf("expected one admitted turn, got %d", len(turns))
	}
	evs := e.verify(turns[0])
	for _, ev := range evs {
		switch ev["type"] {
		case "context_sealed":
			t.Fatal("revoked source became sealed model context")
		case "disclosure_intent":
			t.Fatal("disclosure intent recorded for an ineligible source")
		}
	}
	last := evs[len(evs)-1]
	if last["type"] != evidence.TypeTurnInterrupted {
		t.Fatalf("turn did not end interrupted: %v", last["type"])
	}
	p := last["payload"].(map[string]any)
	if p["disclosure"] != "none" {
		t.Fatalf("disclosure = %v", p["disclosure"])
	}
	if reason := p["reason"]; reason != "context_eligibility_denied" {
		t.Fatalf("interrupt reason = %v", reason)
	}
	// Admission evidence (turn_received and its exact input object) is lawfully
	// captured; nothing else may exist. No reservation, charge or exposure.
	for _, ev := range evs[1 : len(evs)-1] {
		t.Fatalf("unexpected event between admission and interruption: %v", ev["type"])
	}
	var charge int64
	err := e.st.DB.QueryRow(context.Background(),
		`SELECT actual_amount FROM evidence_budget_reservations WHERE project_id=$1 AND idempotency_key='eligibility'`, e.p1).Scan(&charge)
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("reservation exists after pre-sealing refusal: charge=%d err=%v", charge, err)
	}
	ledger := evidence.PG{DB: e.st.DB}
	sum, err := ledger.Summary(context.Background(), e.tenant, e.p1)
	if err != nil || sum.Outstanding != 0 || sum.Unknown != 0 {
		t.Fatalf("accounting after pre-sealing refusal: %+v %v", sum, err)
	}
	t.Logf("source revoked before eligibility: reads=%d events=%d invocations=%d", f.ReadCalls.Load(), len(evs), calls.Load())
}

func TestC06RestartWithUnfinalizedReleaseAndDeletedSource(t *testing.T) {
	e, f, calls := c06Fixture(t)
	original := e.auth.Evidence
	fault := &c06WriteFault{Backend: original.Backend, event: evidence.TypeTurnCompleted, persistent: true}
	original.Backend = fault
	c06Post(t, e, "alice", e.p1, "restart", c06Body, 503)
	if calls.Load() != 1 || !fault.fired {
		t.Fatal("did not exercise finalization after model work")
	}
	f.Delete("sp-document")
	f.SetOutage(errors.New("connector unavailable"))
	start := f.MetadataCalls.Load()
	db := evidence.PG{DB: e.st.DB}
	rc := &evidence.Recorder{Backend: db, Governance: original.Governance, Accounting: db.ReconcileBudget}
	n, err := rc.Recover(context.Background(), time.Time{})
	if err != nil || n != 1 || calls.Load() != 1 || f.MetadataCalls.Load() != start {
		t.Fatalf("recovered=%d invocations=%d err=%v", n, calls.Load(), err)
	}
	e.auth.Evidence = rc
	turn := e.turns()[0]
	evs := e.verify(turn)
	if evs[len(evs)-1]["type"] != evidence.TypeTurnCompleted {
		t.Fatal("release was not finalized on recovery")
	}
	c06Post(t, e, "alice", e.p1, "restart", c06Body, 503)
	f.SetOutage(nil)
	c06Post(t, e, "alice", e.p1, "restart", c06Body, 404)
}

func TestC06ConcurrentSourceAccessAndRevocation(t *testing.T) {
	e, f, calls := c06Fixture(t)
	reading, revoked := make(chan struct{}), make(chan struct{})
	f.AfterRead = func() {
		if f.ReadCalls.Load() == 1 {
			close(reading)
			<-revoked
		}
	}
	go func() { <-reading; f.Grant("sp-document", "provider-alice", false); close(revoked) }()
	c06Post(t, e, "alice", e.p1, "race-revoke", c06Body, 404)
	if len(e.turns()) != 0 || calls.Load() != 0 {
		t.Fatal("revoked selection admitted or dispatched")
	}
	f.Grant("sp-document", "provider-alice", true)
	c06Post(t, e, "alice", e.p1, "race-revoke", c06Body, 200)
	for _, m := range []sharepoint.Metadata{
		{TenantID: "other-tenant", SiteID: "site", LibraryID: "library"},
		{TenantID: "external-tenant", SiteID: "site", LibraryID: "other-library"},
	} {
		m.DocumentID = "sp-document"
		m.Version = "1.0"
		m.ETag = "etag-1"
		f.Put(sharepoint.Document{Metadata: m, Content: []byte("abcRESTRICT!xyz")})
		c06Post(t, e, "alice", e.p1, "foreign", c06Body, 404)
	}
	if calls.Load() != 1 {
		t.Fatal("source scope substitution sent a model request")
	}
}
