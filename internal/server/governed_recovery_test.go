package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/routing"
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
