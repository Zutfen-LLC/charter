package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/routing"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

type c05EvidenceFailure struct {
	evidence.Backend
	event     string
	objectsIf func() bool
}

func (b c05EvidenceFailure) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	if e["type"] == b.event {
		return evidence.Receipt{}, errors.New("synthetic persistence fault")
	}
	return b.Backend.Append(ctx, e)
}
func (b c05EvidenceFailure) PutObject(ctx context.Context, tenant string, data []byte) (evidence.Receipt, error) {
	if b.objectsIf != nil && b.objectsIf() {
		return evidence.Receipt{}, errors.New("synthetic object persistence fault")
	}
	return b.Backend.PutObject(ctx, tenant, data)
}

func TestC05RecoveryDoesNotDispatchAndReconcilesAcrossStores(t *testing.T) {
	for _, event := range []string{"disclosure_intent", "turn_completed", "provider_accepted", "output_bytes"} {
		t.Run(event, func(t *testing.T) {
			f := newEnv(t)
			ctx := context.Background()
			b := evidence.PG{DB: f.st.DB}
			if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: f.tenant, ProjectID: f.p1, ProjectCap: 2000000, LocalOnly: true, AllowedModels: []string{"det-a"}}); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			policy := routing.Governance(routing.DefaultConfig(), b, true, func() { calls.Add(1) })
			auth := *f.auth
			auth.routes = nil
			fault := c05EvidenceFailure{Backend: b, event: event}
			if event == "output_bytes" {
				fault.objectsIf = func() bool { return calls.Load() > 0 }
			}
			auth.Evidence = &evidence.Recorder{Backend: fault, Governance: policy, Accounting: b.ReconcileBudget}
			f.h = New(f.st.DB, PostgresEvidenceBackend(), WithAuth(&auth))
			const request = `{"input":"recovery synthetic","model_id":"det-a"}`
			if code, _, _ := f.post("alice", f.p1, request, "Idempotency-Key", "stable"); code != 503 {
				t.Fatalf("failure leaked success code: %d", code)
			}
			want := int32(1)
			if event == "disclosure_intent" {
				want = 0
			}
			if calls.Load() != want {
				t.Fatalf("before recovery calls=%d", calls.Load())
			}
			if event == "turn_completed" {
				pending, err := b.Outstanding(ctx)
				if err != nil || len(pending) != 1 || !pending[0].DispatchPossible {
					t.Fatalf("lost pending obligation: %+v %v", pending, err)
				}
			}
			r := &evidence.Recorder{Backend: b, Governance: policy, Accounting: b.ReconcileBudget}
			if _, err := r.Recover(ctx, time.Time{}); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := b.RecoverBudget(ctx, b); err != nil {
					t.Fatal(err)
				}
			}
			if calls.Load() != want {
				t.Fatal("recovery invoked provider")
			}
			sum, err := b.Summary(ctx, f.tenant, f.p1)
			if err != nil || sum.Outstanding != 0 {
				t.Fatalf("still pending: %+v %v", sum, err)
			}
			if event == "disclosure_intent" && (sum.Settled != 0 || sum.Unknown != 0) {
				t.Fatal("unarmed reservation remained charged")
			}
			if event == "turn_completed" && (sum.Settled <= 0 || sum.Unknown != 0) {
				t.Fatal("lost verified actual cost")
			}
			if (event == "provider_accepted" || event == "output_bytes") && (sum.Settled != 0 || sum.Unknown <= 0) {
				t.Fatal("ambiguous accepted turn not conservatively charged")
			}
		})
	}
}

func TestC05AmbiguousBudgetCommitAcknowledgments(t *testing.T) {
	for _, step := range []string{"reserve", "arm"} {
		t.Run(step, func(t *testing.T) {
			f := newEnv(t)
			ctx := context.Background()
			b := evidence.PG{DB: f.st.DB}
			if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: f.tenant, ProjectID: f.p1, ProjectCap: 2000000, LocalOnly: true, AllowedModels: []string{"det-a"}}); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			delegate := routing.Governance(routing.DefaultConfig(), b, true, func() { calls.Add(1) })
			governance := func(ctx context.Context, req evidence.Request) (evidence.GovernedPlan, error) {
				p, err := delegate(ctx, req)
				if err != nil {
					return p, err
				}
				if step == "reserve" {
					real := p.Reserve
					p.Reserve = func(ctx context.Context, turn string, body []byte) (int, error) {
						n, err := real(ctx, turn, body)
						if err != nil {
							return n, err
						}
						return 0, errors.New("synthetic lost reservation response after actual commit")
					}
				} else {
					real := p.Arm
					p.Arm = func(ctx context.Context, turn string) error {
						if err := real(ctx, turn); err != nil {
							return err
						}
						return errors.New("synthetic lost arm response after actual commit")
					}
				}
				return p, nil
			}
			f.auth.Evidence = &evidence.Recorder{Backend: b, Governance: governance, Accounting: b.ReconcileBudget}
			const request = `{"input":"synthetic","model_id":"det-a"}`
			if code, _, _ := f.post("alice", f.p1, request, "Idempotency-Key", "stable"); code != 503 {
				t.Fatalf("unexpected code %d", code)
			}
			if code, _, _ := f.post("alice", f.p1, request, "Idempotency-Key", "stable"); code != 409 {
				t.Fatalf("unexpected repeat code %d", code)
			}
			if err := b.RecoverBudget(ctx, b); err != nil {
				t.Fatal(err)
			}
			s, err := b.Summary(ctx, f.tenant, f.p1)
			if err != nil || calls.Load() != 0 || s.Outstanding != 0 || s.Settled != 0 || (s.Unknown > 0) != (step == "arm") {
				t.Fatalf("calls=%d budget=%+v err=%v", calls.Load(), s, err)
			}
		})
	}
}

type c05LostOverrunAck struct {
	evidence.PG
	injected *atomic.Int32
}

func (b c05LostOverrunAck) NoteOverrun(ctx context.Context, id string, units int64) error {
	if err := b.PG.NoteOverrun(ctx, id, units); err != nil {
		return err
	}
	b.injected.Add(1)
	return errors.New("synthetic lost acknowledgment after committed overrun")
}

func TestC05OverrunCrossStoreRecovery(t *testing.T) {
	for _, mode := range []string{"floor-before-evidence-failure", "floor-write-rejected", "floor-and-evidence-rejected", "committed-ack-lost", "malformed", "envelope-overflow"} {
		t.Run(mode, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			b := evidence.PG{DB: e.st.DB}
			cap := int64(1000)
			if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: e.tenant, ProjectID: e.p1, ProjectCap: cap, LocalOnly: true, AllowedModels: []string{"local-http"}}); err != nil {
				t.Fatal(err)
			}
			if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: e.tenant, ProjectID: e.p2, ProjectCap: cap, LocalOnly: true, AllowedModels: []string{"local-http"}}); err != nil {
				t.Fatal(err)
			}
			var calls, sentBytes atomic.Int64
			const oversized = "synthetic oversized output"
			response := `{"output":"` + oversized + `"}`
			switch mode {
			case "malformed":
				response = `{"output":"unclosed`
			case "envelope-overflow":
				response = `{"output":"` + strings.Repeat("x", 70000) + `"}`
			}
			receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sent, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					http.Error(w, "read failure", 400)
					return
				}
				calls.Add(1)
				sentBytes.Store(int64(len(sent)))
				_, _ = io.WriteString(w, response)
			}))
			defer receiver.Close()
			cfg := routing.DefaultConfig()
			cfg.Endpoint = receiver.URL
			cfg.MaxOutputBytes = 8
			backend := evidence.Backend(b)
			if mode == "floor-before-evidence-failure" || mode == "committed-ack-lost" || mode == "floor-and-evidence-rejected" {
				backend = c05EvidenceFailure{Backend: b, event: "usage_settled"}
			}
			if mode == "floor-write-rejected" || mode == "floor-and-evidence-rejected" {
				_, err := e.st.DB.Exec(ctx, `CREATE FUNCTION reject_floor() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic floor write rejected'; END $$;
      CREATE TRIGGER reject_floor BEFORE UPDATE OF overrun_floor ON evidence_budget_reservations FOR EACH ROW EXECUTE FUNCTION reject_floor()`)
				if err != nil {
					t.Fatal(err)
				}
			}
			var injected atomic.Int32
			var ledger routing.Budget = b
			if mode == "committed-ack-lost" {
				ledger = c05LostOverrunAck{PG: b, injected: &injected}
			}
			e.auth.Evidence = &evidence.Recorder{Backend: backend, Governance: routing.Governance(cfg, ledger, false, nil), Accounting: b.ReconcileBudget}
			const body = `{"input":"synthetic","model_id":"local-http"}`
			if code, out, _ := e.post("alice", e.p1, body, "Idempotency-Key", "stable"); code != 503 || strings.Contains(out, oversized) {
				t.Fatalf("withholding: %d %s", code, out)
			}
			read := func(phase string) (floor int64, actual *int64, state string, unknown, frozen bool) {
				t.Helper()
				var reserved int64
				if err := e.st.DB.QueryRow(ctx, `SELECT r.reserved_amount,r.overrun_floor,r.actual_amount,r.status,r.unknown,p.frozen FROM evidence_budget_reservations r JOIN evidence_budget_policy p USING (tenant_id,project_id) WHERE r.project_id=$1 AND r.idempotency_key='stable'`, e.p1).Scan(&reserved, &floor, &actual, &state, &unknown, &frozen); err != nil {
					t.Fatal(err)
				}
				t.Logf("phase=%s calls=%d input=%d envelope=%d reserved=%d floor=%d actual=%v state=%s unknown=%t frozen=%t", phase, calls.Load(), sentBytes.Load(), len(response), reserved, floor, fmtActual(actual), state, unknown, frozen)
				return
			}
			wantFloor := sentBytes.Load() + int64(len(oversized))
			wantCharge := wantFloor
			floor, actual, state, unknown, frozen := read("before-restart")
			switch mode {
			case "floor-before-evidence-failure", "committed-ack-lost":
				if floor != wantFloor || actual != nil || state != "open" || !frozen {
					t.Error("floor and freeze must survive loss of terminal evidence")
				}
			case "floor-write-rejected", "floor-and-evidence-rejected":
				if floor != 0 || actual != nil || state != "open" || !frozen {
					t.Error("failed floor write must freeze with no below-floor settlement")
				}
				if code, _, _ := e.post("alice", e.p1, body, "Idempotency-Key", "while-floor-unavailable"); code != 403 {
					t.Errorf("new admission allowed during failed floor persistence: %d", code)
				}
				if _, err := e.st.DB.Exec(ctx, `DROP TRIGGER reject_floor ON evidence_budget_reservations`); err != nil {
					t.Fatal(err)
				}
			default:
				wantFloor = 0
				wantCharge = sentBytes.Load() + cfg.MaxOutputBytes
				if !frozen || floor != 0 || !unknown {
					t.Error("unquantifiable exposure must freeze without inventing a floor or exact cost")
				}
			}
			wantLost := int32(0)
			if mode == "committed-ack-lost" {
				wantLost = 1
			}
			if injected.Load() != wantLost {
				t.Fatalf("committed-ack injection count=%d", injected.Load())
			}
			t.Logf("committed_overrun_ack_losses=%d", injected.Load())
			restarted := evidence.PG{DB: testdb.Clone(t, e.st.DB)}
			rr := &evidence.Recorder{Backend: restarted, Accounting: restarted.ReconcileBudget}
			for range 2 {
				if _, err := rr.Recover(ctx, time.Time{}); err != nil {
					t.Fatal(err)
				}
				err := restarted.RecoverBudget(ctx, restarted)
				if mode == "floor-and-evidence-rejected" {
					if !errors.Is(err, evidence.ErrBudgetConflict) {
						t.Fatalf("lost observation should retain pending hold: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			floor, actual, state, unknown, frozen = read("after-two-reconciliations")
			if mode == "floor-and-evidence-rejected" {
				if floor != 0 || actual != nil || state != "open" || !frozen {
					t.Error("lost accounting observation must remain frozen and outstanding")
				}
			} else if floor != wantFloor || actual == nil || *actual != wantCharge || state != "settled" || !unknown || !frozen {
				t.Error("incorrect terminal ledger after recovery")
			}
			e.auth.Evidence = &evidence.Recorder{Backend: b, Governance: routing.Governance(cfg, b, false, nil), Accounting: b.ReconcileBudget}
			retry, _, _ := e.post("alice", e.p1, body, "Idempotency-Key", "stable")
			fresh, _, _ := e.post("alice", e.p1, body, "Idempotency-Key", "fresh")
			sibling, err := b.Summary(ctx, e.tenant, e.p2)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("retry=%d fresh=%d receiver_calls=%d uncapped_sibling_frozen=%t", retry, fresh, calls.Load(), sibling.Frozen)
			if retry != 409 || fresh != 403 || calls.Load() != 1 || sibling.Frozen {
				t.Error("recovery or frozen admission dispatched, or freeze exceeded scope")
			}
		})
	}
}

func fmtActual(n *int64) any {
	if n == nil {
		return nil
	}
	return *n
}
