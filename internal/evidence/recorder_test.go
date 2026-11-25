package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fx struct {
	t      *testing.T
	pool   *pgxpool.Pool
	pg     evidence.PG
	be     evidence.Backend
	rec    *evidence.Recorder
	calls  atomic.Int32
	sent   [][]byte
	tenant string
	proj   string
	matter string
	user   string
	now    time.Time
	mu     sync.Mutex
	policy evidence.Decision
}

func newFx(t *testing.T, wrap func(evidence.Backend) evidence.Backend) *fx {
	t.Helper()
	pool := testdb.New(t)
	f := &fx{t: t, pool: pool, pg: evidence.PG{DB: pool}, tenant: evidence.NewUUID(), proj: evidence.NewUUID(),
		matter: evidence.NewUUID(), user: evidence.NewUUID(), now: time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)}
	f.be = f.pg
	if wrap != nil {
		f.be = wrap(f.pg)
	}
	f.policy = evidence.Decision{Allow: true, PolicyVersion: "pol-1", ReserveUnits: 1000,
		Destination: evidence.Destination{Provider: "test-a", EndpointID: "ep-1", ModelID: "test-model-a"}}
	f.rec = &evidence.Recorder{Backend: f.be,
		Policy: func(context.Context, evidence.Request) (evidence.Decision, error) { return f.policy, nil },
		Clock: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.now = f.now.Add(time.Millisecond)
			return f.now
		}}
	return f
}

func (f *fx) req(key, input string) evidence.Request {
	return evidence.Request{TenantID: f.tenant, ProjectID: f.proj, MatterID: f.matter, CustodianID: f.user,
		IdempotencyKey: key, RequestID: "req-" + key, Input: []byte(input),
		Sources: []evidence.Source{{ID: "doc-1", Version: 2, Bytes: []byte("SYNTHETIC-DOC-1 version 2 content")}}}
}

// model is a deterministic fake provider that counts real dispatches.
func (f *fx) model(out string) evidence.ModelFunc {
	return func(_ context.Context, sent []byte) (evidence.ModelOutcome, error) {
		f.calls.Add(1)
		f.sent = append(f.sent, sent)
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte(out)}, nil
	}
}

func (f *fx) log(turn string) []evidence.Event {
	f.t.Helper()
	evs, err := f.pg.Load(context.Background(), f.tenant, turn)
	if err != nil {
		f.t.Fatal(err)
	}
	return evs
}

func (f *fx) objects(evs []evidence.Event) map[string][]byte {
	f.t.Helper()
	out := map[string][]byte{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if s, ok := x["sha256"].(string); ok {
				b, err := f.pg.Object(context.Background(), f.tenant, s)
				if err != nil {
					f.t.Fatalf("object %s: %v", s, err)
				}
				out[s] = b
			}
			if s, ok := x["request_sha256"].(string); ok {
				b, _ := f.pg.Object(context.Background(), f.tenant, s)
				out[s] = b
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	for _, e := range evs {
		walk(e["payload"])
	}
	return out
}

func types(evs []evidence.Event) string {
	var s []string
	for _, e := range evs {
		s = append(s, e["type"].(string))
	}
	return strings.Join(s, ",")
}

func (f *fx) verified(turn string) []evidence.Event {
	f.t.Helper()
	evs := f.log(turn)
	if errs := evidence.Verify(evs, f.objects(evs)); len(errs) != 0 {
		f.t.Fatalf("log does not verify: %v\n%s", errs, types(evs))
	}
	return evs
}

func (f *fx) onlyTurn() string {
	f.t.Helper()
	var id string
	if err := f.pool.QueryRow(context.Background(), `SELECT turn_id::text FROM evidence_turns`).Scan(&id); err != nil {
		f.t.Fatal(err)
	}
	return id
}

const happy = "turn_received,policy_decision,usage_reserved,context_sealed,disclosure_intent,evidence_ack," +
	"provider_accepted,output_recorded,evidence_ack,response_released,usage_settled,turn_completed"

func TestHappyPathRecordsEverythingAndVerifies(t *testing.T) {
	f := newFx(t, nil)
	res, err := f.rec.Process(context.Background(), f.req("k1", "Summarize SYNTHETIC-DOC-1 v2"), f.model("Synthetic summary."), nil)
	if err != nil || string(res.Output) != "Synthetic summary." {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	evs := f.verified(res.TurnID)
	if types(evs) != happy {
		t.Fatalf("event sequence:\n got %s\nwant %s", types(evs), happy)
	}
	if evidence.DeriveDisclosure(evs) != evidence.DisclosureDisclosed {
		t.Fatal("expected disclosed")
	}
	first := evs[0]
	for k, want := range map[string]string{"tenant_id": f.tenant, "project_id": f.proj, "matter_id": f.matter, "turn_id": res.TurnID} {
		if first[k] != want {
			t.Errorf("%s = %v, want %s", k, first[k], want)
		}
	}
	if a := first["actor"].(map[string]any); a["id"] != f.user || a["kind"] != "user" {
		t.Errorf("custodian/actor not recorded: %v", a)
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", first["recorded_at"].(string)); err != nil {
		t.Errorf("recorded_at not RFC3339 ms Z: %v", err)
	}
	if first["payload"].(map[string]any)["request_id"] != "req-k1" {
		t.Error("request id missing")
	}
	// Exact inputs: the stored request object is byte-identical to what the
	// provider received, and the stored input/excerpt/output objects are exact.
	sealed := evs[3]["payload"].(map[string]any)
	stored, err := f.pg.Object(context.Background(), f.tenant, sealed["request_sha256"].(string))
	if err != nil || string(stored) != string(f.sent[0]) {
		t.Fatalf("stored request != sent request: %q vs %q (%v)", stored, f.sent[0], err)
	}
	if !strings.Contains(string(stored), "Summarize SYNTHETIC-DOC-1 v2") || !strings.Contains(string(stored), "SYNTHETIC-DOC-1 version 2 content") {
		t.Errorf("request lacks input or excerpt: %s", stored)
	}
	src := sealed["sources"].([]any)[0].(map[string]any)
	if src["source_id"] != "doc-1" || src["sha256"] != evidence.SHA256([]byte("SYNTHETIC-DOC-1 version 2 content")) {
		t.Errorf("source reference wrong: %v", src)
	}
	// Destination is the actual endpoint/model, on both decision and intent.
	if d := evs[1]["payload"].(map[string]any)["destination"].(map[string]any); d["model_id"] != "test-model-a" || d["provider"] != "test-a" {
		t.Errorf("destination: %v", d)
	}
	if in := evs[4]["payload"].(map[string]any); in["model_id"] != "test-model-a" || in["endpoint_id"] != "ep-1" {
		t.Errorf("intent: %v", in)
	}
	outHash := evs[7]["payload"].(map[string]any)["objects"].([]any)[0].(map[string]any)["sha256"]
	if outHash != evidence.SHA256([]byte("Synthetic summary.")) {
		t.Error("output hash not recorded")
	}
	// Acks carry a receipt and the storage level actually in force.
	ack := evs[5]["payload"].(map[string]any)
	if !strings.HasPrefix(ack["receipt"].(string), "sha256:") || ack["storage_level"] != "postgres:fsync=on,synchronous_commit=on" {
		t.Errorf("ack receipt/level: %v", ack)
	}
}

// R1 and admission: when the model is called, the turn is already admitted and
// the intent is durably acknowledged.
func TestAdmissionAndIntentDurableBeforeDispatch(t *testing.T) {
	f := newFx(t, nil)
	var seen string
	call := func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
		seen = types(f.log(f.onlyTurn()))
		return f.model("ok")(ctx, sent)
	}
	if _, err := f.rec.Process(context.Background(), f.req("k", "in"), call, nil); err != nil {
		t.Fatal(err)
	}
	want := "turn_received,policy_decision,usage_reserved,context_sealed,disclosure_intent,evidence_ack"
	if seen != want {
		t.Fatalf("at dispatch the log was\n %s\nwant\n %s", seen, want)
	}
}

// R2: the output is durable and acknowledged before the release gate runs, and
// a veto releases nothing and records why.
func TestOutputDurableBeforeReleaseAndGateVeto(t *testing.T) {
	f := newFx(t, nil)
	// The gate runs twice: before the release is recorded, and again after every
	// evidence write, immediately before delivery.
	var atGate []string
	gate := func(context.Context) error { atGate = append(atGate, types(f.log(f.onlyTurn()))); return nil }
	if _, err := f.rec.Process(context.Background(), f.req("a", "in"), f.model("ok"), gate); err != nil {
		t.Fatal(err)
	}
	if len(atGate) != 2 || !strings.HasSuffix(atGate[0], "output_recorded,evidence_ack") ||
		!strings.HasSuffix(atGate[1], "response_released,usage_settled,turn_completed") {
		t.Fatalf("logs at the two gates: %v", atGate)
	}
	veto := errors.New("revoked")
	res, err := f.rec.Process(context.Background(), f.req("b", "in2"), f.model("secret-output"), func(context.Context) error { return veto })
	if !errors.Is(err, veto) || len(res.Output) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var id string
	_ = f.pool.QueryRow(context.Background(), `SELECT turn_id::text FROM evidence_turns WHERE idempotency_key='b'`).Scan(&id)
	evs := f.verified(id)
	last := evs[len(evs)-1]
	if last["type"] != "turn_interrupted" || last["payload"].(map[string]any)["reason"] != "release_denied" ||
		last["payload"].(map[string]any)["disclosure"] != "disclosed" {
		t.Fatalf("terminal: %v", last["payload"])
	}
	if strings.Contains(types(evs), "response_released") {
		t.Fatal("released despite veto")
	}
}

func TestPolicyEvaluationFailureIsDurableDenialWithoutRedispatch(t *testing.T) {
	f := newFx(t, nil)
	policyErr := errors.New("policy unavailable")
	f.rec.Policy = func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{}, policyErr
	}
	res, err := f.rec.Process(context.Background(), f.req("policy-failure", "in"), f.model("must-not-run"), nil)
	if !errors.Is(err, policyErr) || len(res.Output) != 0 || f.calls.Load() != 0 {
		t.Fatalf("res=%+v err=%v calls=%d", res, err, f.calls.Load())
	}
	evs := f.verified(f.onlyTurn())
	if got := types(evs); got != "turn_received,policy_decision,turn_completed" {
		t.Fatalf("policy failure lifecycle: %s", got)
	}
	decision := evs[1]["payload"].(map[string]any)
	terminal := evs[2]["payload"].(map[string]any)
	if decision["decision"] != "deny" || decision["reason"] != "policy_evaluation_failed" || terminal["outcome"] != "denied" || evidence.DeriveDisclosure(evs) != evidence.DisclosureNone {
		t.Fatalf("failure was not durably denied: decision=%v terminal=%v", decision, terminal)
	}
	if _, err := f.rec.Process(context.Background(), f.req("policy-failure", "in"), f.model("must-not-run"), nil); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("retry of durable denial: %v", err)
	}
	if f.calls.Load() != 0 {
		t.Fatalf("denied request redispatched: %d", f.calls.Load())
	}
}

func TestDenyDisclosesNothing(t *testing.T) {
	f := newFx(t, nil)
	f.policy = evidence.Decision{Allow: false, Reason: "model not approved", PolicyVersion: "pol-1"}
	_, err := f.rec.Process(context.Background(), f.req("k", "in"), f.model("x"), nil)
	if !errors.Is(err, evidence.ErrDenied) || f.calls.Load() != 0 {
		t.Fatalf("err=%v calls=%d", err, f.calls.Load())
	}
	evs := f.verified(f.onlyTurn())
	if types(evs) != "turn_received,policy_decision,turn_completed" || evidence.DeriveDisclosure(evs) != "none" {
		t.Fatalf("log: %s", types(evs))
	}
	// A replay of a denied turn stays denied and never dispatches.
	if _, err := f.rec.Process(context.Background(), f.req("k", "in"), f.model("x"), nil); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("replay: %v", err)
	}
}

func TestProviderFailuresAreRecordedNotReleased(t *testing.T) {
	t.Run("error before any acceptance is unknown disclosure", func(t *testing.T) {
		f := newFx(t, nil)
		call := func(context.Context, []byte) (evidence.ModelOutcome, error) {
			f.calls.Add(1)
			return evidence.ModelOutcome{}, errors.New("connection reset")
		}
		res, err := f.rec.Process(context.Background(), f.req("k", "in"), call, nil)
		if !evidence.IsProviderError(err) || len(res.Output) != 0 {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		evs := f.verified(f.onlyTurn())
		term := evs[len(evs)-1]["payload"].(map[string]any)
		if evidence.DeriveDisclosure(evs) != "unknown" || term["disclosure"] != "unknown" || term["reason"] != "provider_error" {
			t.Fatalf("log %s terminal %v", types(evs), term)
		}
		st := evs[len(evs)-2]
		if st["type"] != "usage_settled" || st["payload"].(map[string]any)["basis"] != "reserved_max" {
			t.Fatalf("unknown outcome must settle at reserved max: %v", st)
		}
	})
	t.Run("partial output mid-stream", func(t *testing.T) {
		f := newFx(t, nil)
		call := func(context.Context, []byte) (evidence.ModelOutcome, error) {
			f.calls.Add(1)
			return evidence.ModelOutcome{Accepted: true, Output: []byte("Synthetic summary of SYNTH")}, errors.New("stream cut")
		}
		res, err := f.rec.Process(context.Background(), f.req("k", "in"), call, nil)
		if !evidence.IsProviderError(err) || len(res.Output) != 0 {
			t.Fatalf("res=%+v err=%v", res, err)
		}
		evs := f.verified(f.onlyTurn())
		if !strings.Contains(types(evs), "output_recorded,evidence_ack,usage_settled,turn_interrupted") ||
			evs[len(evs)-1]["payload"].(map[string]any)["reason"] != "provider_stream_error" {
			t.Fatalf("log %s", types(evs))
		}
		var out map[string]any
		for _, e := range evs {
			if e["type"] == "output_recorded" {
				out = e["payload"].(map[string]any)
			}
		}
		if out["complete"] != false {
			t.Fatal("partial output must be recorded as incomplete")
		}
		b, _ := f.pg.Object(context.Background(), f.tenant, evidence.SHA256([]byte("Synthetic summary of SYNTH")))
		if string(b) != "Synthetic summary of SYNTH" {
			t.Fatal("partial output bytes not preserved")
		}
	})
}

func TestIdempotentReplayNeverRedispatches(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	r1, err := f.rec.Process(ctx, f.req("same", "in"), f.model("answer"), nil)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := f.rec.Process(ctx, f.req("same", "in"), f.model("DIFFERENT"), nil)
	if err != nil || !r2.Replayed || r2.TurnID != r1.TurnID || string(r2.Output) != "answer" || f.calls.Load() != 1 {
		t.Fatalf("replay: %+v err=%v calls=%d", r2, err, f.calls.Load())
	}
	if _, err := f.rec.Process(ctx, f.req("same", "other input"), f.model("x"), nil); !errors.Is(err, evidence.ErrIdempotencyMismatch) {
		t.Fatalf("mismatch: %v", err)
	}
	if got := types(f.verified(r1.TurnID)); got != happy {
		t.Fatalf("replay must not append events: %s", got)
	}
	// A different custodian may reuse the key: keys are scoped per custodian.
	other := f.req("same", "in")
	other.CustodianID = evidence.NewUUID()
	if r3, err := f.rec.Process(ctx, other, f.model("x"), nil); err != nil || r3.Replayed {
		t.Fatalf("other custodian: %+v %v", r3, err)
	}
	// The replay is still subject to the release gate.
	veto := errors.New("revoked")
	if _, err := f.rec.Process(ctx, f.req("same", "in"), f.model("x"), func(context.Context) error { return veto }); !errors.Is(err, veto) {
		t.Fatalf("replay bypassed gate: %v", err)
	}
}

// A crash after the intent ack leaves disclosure UNKNOWN. Recovery says so
// explicitly, never re-dispatches, and a retry with the same key is refused.
func TestCrashAfterIntentRecoversAsUnknownWithoutReplay(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	func() {
		defer func() { _ = recover() }() // the "process death"
		_, _ = f.rec.Process(ctx, f.req("k", "in"), func(context.Context, []byte) (evidence.ModelOutcome, error) {
			f.calls.Add(1)
			panic("simulated crash after the request left the building")
		}, nil)
	}()
	turn := f.onlyTurn()
	if _, err := f.rec.Process(ctx, f.req("k", "in"), f.model("x"), nil); !errors.Is(err, evidence.ErrTurnInFlight) {
		t.Fatalf("in-flight retry must not dispatch: %v", err)
	}
	n, err := f.rec.Recover(ctx, time.Now().Add(time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("recover n=%d err=%v", n, err)
	}
	evs := f.verified(turn)
	term := evs[len(evs)-1]
	p := term["payload"].(map[string]any)
	if term["type"] != "turn_interrupted" || p["reason"] != "crash_recovery" || p["disclosure"] != "unknown" {
		t.Fatalf("terminal: %v", term)
	}
	if a := term["actor"].(map[string]any); a["kind"] != "service" {
		t.Fatalf("recovery actor must be the service, got %v", a)
	}
	if st := evs[len(evs)-2]; st["type"] != "usage_settled" || st["payload"].(map[string]any)["basis"] != "reserved_max" {
		t.Fatalf("unknown disclosure must settle at reserved max: %v", st)
	}
	var ie *evidence.InterruptedError
	if _, err := f.rec.Process(ctx, f.req("k", "in"), f.model("x"), nil); !errors.As(err, &ie) || ie.Disclosure != "unknown" {
		t.Fatalf("retry after recovery: %v", err)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("live model call replayed: %d calls", f.calls.Load())
	}
	if n, _ := f.rec.Recover(ctx, time.Now().Add(time.Hour)); n != 0 {
		t.Fatal("recovery must be idempotent")
	}
}

func TestRecoverCompletesTurnAlreadyRecordedAsReleased(t *testing.T) {
	// The log says response_released but the terminal event was lost: R3 says
	// that turn must end completed, not interrupted.
	f := newFx(t, func(b evidence.Backend) evidence.Backend {
		return &faulty{Backend: b, failTypes: map[string]bool{"turn_completed": true}, forever: true}
	})
	res, err := f.rec.Process(context.Background(), f.req("k", "in"), f.model("answer"), nil)
	if !errors.Is(err, evidence.ErrFinalizeFailed) || len(res.Output) != 0 {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	f.rec.Backend = f.pg // store is back
	if n, err := f.rec.Recover(context.Background(), time.Now().Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	evs := f.verified(f.onlyTurn())
	if evs[len(evs)-1]["type"] != "turn_completed" {
		t.Fatalf("log: %s", types(evs))
	}
	// response_released records that release was AUTHORIZED, not that bytes
	// reached the client. The withheld output is therefore deliverable by a
	// delivery-only retry (idempotent replay), which is gated again and never
	// re-dispatches.
	veto := errors.New("revoked since")
	if res, err := f.rec.Process(context.Background(), f.req("k", "in"), f.model("x"), func(context.Context) error { return veto }); !errors.Is(err, veto) || len(res.Output) != 0 {
		t.Fatalf("delivery retry bypassed the gate: %+v %v", res, err)
	}
	res, err = f.rec.Process(context.Background(), f.req("k", "in"), f.model("x"), nil)
	if err != nil || !res.Replayed || string(res.Output) != "answer" || f.calls.Load() != 1 {
		t.Fatalf("delivery-only retry: %+v %v calls=%d", res, err, f.calls.Load())
	}
}

// ---- fault injection -------------------------------------------------------

// faulty wraps a backend and breaks the nth WRITE (PutObject/Admit/Append).
type faulty struct {
	evidence.Backend
	mu          sync.Mutex
	n, at       int
	afterCommit bool
	outage      bool // fail every write from `at` onward
	failTypes   map[string]bool
	forever     bool
}

var errInjected = errors.New("injected evidence store failure")

func (f *faulty) hit(typ string) (bool, bool) { // (fail, commitFirst)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	if f.failTypes != nil {
		return f.failTypes[typ], false
	}
	if f.at == 0 {
		return false, false
	}
	if f.outage {
		return f.n >= f.at, false
	}
	return f.n == f.at, f.afterCommit
}

func (f *faulty) PutObject(ctx context.Context, t string, d []byte) (evidence.Receipt, error) {
	fail, after := f.hit("")
	if fail && !after {
		return evidence.Receipt{}, errInjected
	}
	r, err := f.Backend.PutObject(ctx, t, d)
	if fail {
		return evidence.Receipt{}, errInjected
	}
	return r, err
}

func (f *faulty) Admit(ctx context.Context, a evidence.Admission, e evidence.Event, o [][]byte) (evidence.AdmitResult, error) {
	fail, after := f.hit("")
	if fail && !after {
		return evidence.AdmitResult{}, errInjected
	}
	r, err := f.Backend.Admit(ctx, a, e, o)
	if fail {
		return evidence.AdmitResult{}, errInjected
	}
	return r, err
}

func (f *faulty) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	fail, after := f.hit(e["type"].(string))
	if fail && !after {
		return evidence.Receipt{}, errInjected
	}
	r, err := f.Backend.Append(ctx, e)
	if fail {
		return evidence.Receipt{}, errInjected
	}
	return r, err
}

// Every single write in a complete turn is failed in turn, in three ways
// (rejected, committed-but-reported-failed, and a permanent outage from that
// point). In every case: nothing escapes without evidence, a model call implies
// the log says disclosure is not "none", and after recovery the log is terminal
// and verifies.
func TestFaultInjectionAtEveryWrite(t *testing.T) {
	// Count the writes of a clean turn.
	probe := newFx(t, func(b evidence.Backend) evidence.Backend { return &faulty{Backend: b} })
	if _, err := probe.rec.Process(context.Background(), probe.req("k", "in"), probe.model("ok"), nil); err != nil {
		t.Fatal(err)
	}
	total := probe.be.(*faulty).n
	if total < 12 {
		t.Fatalf("suspiciously few writes: %d", total)
	}
	for _, mode := range []string{"reject", "commit-then-error", "outage"} {
		for at := 1; at <= total; at++ {
			t.Run(fmt.Sprintf("%s/write-%02d", mode, at), func(t *testing.T) {
				fb := &faulty{at: at, afterCommit: mode == "commit-then-error", outage: mode == "outage"}
				f := newFx(t, func(b evidence.Backend) evidence.Backend { fb.Backend = b; return fb })
				var gateRan bool
				res, err := f.rec.Process(context.Background(), f.req("k", "in"), f.model("answer"),
					func(context.Context) error { gateRan = true; return nil })
				if err != nil && len(res.Output) != 0 {
					t.Fatalf("output released alongside error %v", err)
				}
				if err == nil && mode == "outage" {
					t.Fatalf("a permanent outage from write %d still reported success", at)
				}
				// A turn may exist only if admission committed.
				var n int
				_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM evidence_turns`).Scan(&n)
				if n == 0 {
					if f.calls.Load() != 0 || res.Output != nil {
						t.Fatal("dispatch or output without an admitted turn")
					}
					return
				}
				// Heal the store and recover.
				fb.at = 0
				if _, err := f.rec.Recover(context.Background(), time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("recover: %v", err)
				}
				evs := f.verified(f.onlyTurn())
				disc := evidence.DeriveDisclosure(evs)
				if f.calls.Load() > 0 && disc == evidence.DisclosureNone {
					t.Fatalf("model was called but the log claims no disclosure:\n%s", types(evs))
				}
				// The reverse is deliberately NOT required: an acked intent whose
				// ack was reported as failed derives "unknown" although nothing was
				// sent (ADR 0001 section 8: fail-closed after R1 may waste a
				// reservation). Over-reporting disclosure is safe; under-reporting
				// is the failure this test exists to catch.
				if err == nil {
					if !strings.Contains(types(evs), "response_released") || evs[len(evs)-1]["type"] != "turn_completed" {
						t.Fatalf("success without a recorded release:\n%s", types(evs))
					}
				}
				if len(res.Output) > 0 {
					// Release only after the output ack, which the gate saw.
					if !gateRan || !strings.Contains(types(evs), "output_recorded,evidence_ack,response_released") {
						t.Fatalf("output released without durable ack: %s", types(evs))
					}
				}
				if f.calls.Load() > 1 {
					t.Fatal("model dispatched more than once")
				}
			})
		}
	}
}

// ---- backend behaviour -----------------------------------------------------

func TestAppendIsIdempotentAndChainEnforced(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	res, err := f.rec.Process(ctx, f.req("k", "in"), f.model("ok"), nil)
	if err != nil {
		t.Fatal(err)
	}
	evs := f.log(res.TurnID)
	// Replaying an already stored event returns the same deterministic receipt.
	r1, err := f.pg.Append(ctx, evs[2])
	r2, err2 := f.pg.Append(ctx, evs[2])
	if err != nil || err2 != nil || r1 != r2 || r1.ID == "" {
		t.Fatalf("replay: %v %v %v %v", r1, r2, err, err2)
	}
	// Same position, different content: refused.
	forged := evidence.Event{}
	for k, v := range evs[2] {
		forged[k] = v
	}
	forged["recorded_at"] = "2030-01-01T00:00:00.000Z"
	if err := evidence.Seal(forged); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pg.Append(ctx, forged); !errors.Is(err, evidence.ErrConflict) {
		t.Fatalf("forged rewrite: %v", err)
	}
	// Unsealed events are refused outright.
	bad := evidence.Event{}
	for k, v := range evs[0] {
		bad[k] = v
	}
	bad["seq"] = 99
	if _, err := f.pg.Append(ctx, bad); err == nil {
		t.Fatal("unsealed event accepted")
	}
	// Nothing may follow a terminal event.
	next := evidence.Event{"schema_version": "1.0.0", "tenant_id": f.tenant, "project_id": f.proj, "matter_id": f.matter,
		"turn_id": res.TurnID, "seq": len(evs), "type": "usage_settled", "recorded_at": "2026-01-15T10:00:30.000Z",
		"actor": map[string]any{"kind": "service", "id": "x"}, "payload": map[string]any{}, "prev_hash": evs[len(evs)-1]["event_hash"]}
	_ = evidence.Seal(next)
	if _, err := f.pg.Append(ctx, next); !errors.Is(err, evidence.ErrTerminal) {
		t.Fatalf("append after terminal: %v", err)
	}
	// A gap or wrong prev_hash cannot extend a live chain either.
	f2 := newFx(t, nil)
	e0 := evidence.Event{"schema_version": "1.0.0", "tenant_id": f2.tenant, "project_id": f2.proj, "matter_id": f2.matter,
		"turn_id": evidence.NewUUID(), "seq": 0, "type": "turn_received", "recorded_at": "2026-01-15T10:00:00.000Z",
		"actor": map[string]any{"kind": "user", "id": f2.user}, "payload": map[string]any{}, "prev_hash": nil}
	_ = evidence.Seal(e0)
	if _, err := f2.pg.Admit(ctx, evidence.Admission{TenantID: f2.tenant, ProjectID: f2.proj, MatterID: f2.matter,
		CustodianID: f2.user, IdempotencyKey: "z", TurnID: e0["turn_id"].(string), Fingerprint: evidence.SHA256(nil)}, e0, nil); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(e evidence.Event){
		"seq gap":    func(e evidence.Event) { e["seq"] = 2 },
		"wrong prev": func(e evidence.Event) { e["prev_hash"] = evidence.SHA256([]byte("nope")) },
	} {
		e1 := evidence.Event{"schema_version": "1.0.0", "tenant_id": f2.tenant, "project_id": f2.proj, "matter_id": f2.matter,
			"turn_id": e0["turn_id"], "seq": 1, "type": "policy_decision", "recorded_at": "2026-01-15T10:00:01.000Z",
			"actor": map[string]any{"kind": "service", "id": "x"}, "payload": map[string]any{"decision": "allow"}, "prev_hash": e0["event_hash"]}
		mut(e1)
		_ = evidence.Seal(e1)
		if _, err := f2.pg.Append(ctx, e1); err == nil {
			t.Errorf("%s: chain violation accepted", name)
		}
	}
}

func TestReceiptLevelIsForcedDurableEvenIfSessionIsLax(t *testing.T) {
	pool := testdb.New(t)
	if _, err := pool.Exec(context.Background(), `ALTER ROLE CURRENT_USER SET synchronous_commit = off`); err != nil {
		t.Skip("cannot change role default: ", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `ALTER ROLE CURRENT_USER RESET synchronous_commit`) })
	pg := evidence.PG{DB: pool}
	r, err := pg.PutObject(context.Background(), evidence.NewUUID(), []byte("x"))
	if err != nil || r.Level != "postgres:fsync=on,synchronous_commit=on" {
		t.Fatalf("receipt %+v err %v", r, err)
	}
}

func TestObjectsAreContentAddressedAndStoredOnce(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	r1, err1 := f.pg.PutObject(ctx, f.tenant, []byte("same bytes"))
	r2, err2 := f.pg.PutObject(ctx, f.tenant, []byte("same bytes"))
	if err1 != nil || err2 != nil || r1 != r2 {
		t.Fatalf("%v %v %v %v", r1, r2, err1, err2)
	}
	// The database refuses bytes that do not hash to their address.
	_, err := f.pool.Exec(ctx, `INSERT INTO evidence_objects(tenant_id, sha256, length, bytes) VALUES ($1::uuid,$2,1,'\x01')`,
		f.tenant, evidence.SHA256([]byte("other")))
	if err == nil {
		t.Fatal("mismatched object accepted")
	}
	// Tenants are separate address spaces: another tenant cannot read it.
	if _, err := f.pg.Object(ctx, evidence.NewUUID(), evidence.SHA256([]byte("same bytes"))); !errors.Is(err, evidence.ErrNotFound) {
		t.Fatalf("cross-tenant object read: %v", err)
	}
}

func TestEvidenceIsSeparateFromWorkspaceTables(t *testing.T) {
	f := newFx(t, nil)
	rows, err := f.pool.Query(context.Background(), `
		SELECT c.conrelid::regclass::text, c.confrelid::regclass::text FROM pg_constraint c
		WHERE c.contype='f' AND (c.conrelid::regclass::text LIKE 'evidence\_%' OR c.confrelid::regclass::text LIKE 'evidence\_%')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var from, to string
		_ = rows.Scan(&from, &to)
		if !strings.Contains(from, "evidence_") || !strings.Contains(to, "evidence_") {
			t.Errorf("evidence is coupled to a workspace table: %s -> %s", from, to)
		}
	}
}

func TestPayloadScreenKeepsCredentialsAndTelemetryOut(t *testing.T) {
	f := newFx(t, nil)
	// The recorder builds payloads itself; prove that the screen would stop a
	// regression by using the policy reason path with a poisoned key via a
	// custom destination is impossible, so test the exported behaviour: an
	// event with a credential-like key never reaches the store.
	for _, key := range []string{"authorization", "Authorization_header", "access_token", "Cookie", "client_secret", "api_key", "user_agent", "ip_address"} {
		if err := evidence.Screen(map[string]any{"a": []any{map[string]any{key: "x"}}}); err == nil {
			t.Errorf("key %q accepted", key)
		}
	}
	if err := evidence.Screen(map[string]any{"decision": "allow", "objects": []any{map[string]any{"sha256": "x"}}}); err != nil {
		t.Errorf("legitimate payload rejected: %v", err)
	}
	_ = f
}
