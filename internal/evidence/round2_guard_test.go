package evidence_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// C07 round-2 finding 2: hold protection must cover ALL matching evidence,
// not merely evidence associated with successful client responses. Policy
// denial, interruption, failed finalization and crash recovery can append
// evidence versions without reaching the release/delivery protection gate;
// every terminal path must establish protection for the complete published
// version set.

const (
	r2Tenant    = "11111111-1111-1111-1111-111111111111"
	r2Project   = "22222222-2222-2222-2222-222222222222"
	r2Matter    = "33333333-3333-3333-3333-333333333333"
	r2Custodian = "44444444-4444-4444-4444-444444444444"
)

func r2Request(key string) evidence.Request {
	return evidence.Request{
		TenantID: r2Tenant, ProjectID: r2Project, MatterID: r2Matter, CustodianID: r2Custodian,
		IdempotencyKey: key, Input: []byte("round2 input " + key),
	}
}

// A policy-denied turn appends a terminal event without ever reaching the
// release gate: its published versions must still be protected (the guard
// is consulted after the terminal event).
func TestDeniedTurnIsProtectedAfterTerminalEvent(t *testing.T) {
	pool := testdb.New(t)
	g := &guardSpy{applies: true}
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: false, Reason: "policy denial", PolicyVersion: "t"}, nil
	}, Lifecycle: g}
	if _, err := rec.Process(context.Background(), r2Request("round2-denied"), func(context.Context, []byte) (evidence.ModelOutcome, error) {
		t.Fatal("a denied turn must not dispatch")
		return evidence.ModelOutcome{}, nil
	}, func(context.Context) error { return nil }); !errors.Is(err, evidence.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	// Admission guard + the post-terminal protection pass.
	if len(g.calls) < 2 {
		t.Fatalf("FINDING 2: the denied turn's protection was consulted %d times, want admission + post-terminal (2)", len(g.calls))
	}
}

// A provider failure with partial output stores the partial output object
// and terminal-interrupt events without any client response: protection
// must be established for those versions.
func TestProviderFailureTurnIsProtectedAfterTerminalEvent(t *testing.T) {
	pool := testdb.New(t)
	g := &guardSpy{applies: true}
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "t", Destination: evidence.Destination{Provider: "p", EndpointID: "e", ModelID: "m"}}, nil
	}, Lifecycle: g}
	if _, err := rec.Process(context.Background(), r2Request("round2-provider-failure"), func(context.Context, []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: false, Output: []byte("partial output")}, errors.New("provider stream error")
	}, func(context.Context) error { return nil }); err == nil || !evidence.IsProviderError(err) {
		t.Fatalf("want provider error, got %v", err)
	}
	if len(g.calls) < 2 {
		t.Fatalf("FINDING 2: the interrupted turn's protection was consulted %d times, want admission + post-terminal (2)", len(g.calls))
	}
}

// A release veto (interruption before response release) leaves a terminal
// turn: the protection pass must run after the terminal event even though
// nothing was released.
func TestReleaseVetoTurnIsProtectedAfterTerminalEvent(t *testing.T) {
	pool := testdb.New(t)
	g := &guardSpy{applies: true}
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "t", Destination: evidence.Destination{Provider: "p", EndpointID: "e", ModelID: "m"}}, nil
	}, Lifecycle: g}
	if _, err := rec.Process(context.Background(), r2Request("round2-release-veto"), func(context.Context, []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("vetoed output")}, nil
	}, func(context.Context) error { return errors.New("release denied") }); err == nil {
		t.Fatal("the vetoed release must fail")
	}
	// Admission + release-gate + the post-terminal protection pass.
	if len(g.calls) < 3 {
		t.Fatalf("FINDING 2: the release-vetoed turn's protection was consulted %d times, want admission + release-gate + post-terminal (3)", len(g.calls))
	}
}

// A C06 context-eligibility refusal after admission (the delegated source
// fails the pre-sealing eligibility check) leaves a terminal turn whose
// published versions must still be protected.
func TestContextEligibilityRefusalIsProtectedAfterTerminalEvent(t *testing.T) {
	f := newFx(t, nil)
	g := &guardSpy{applies: true}
	f.rec.Lifecycle = g
	f.rec.Governance = func(_ context.Context, _ evidence.Request) (evidence.GovernedPlan, error) {
		return evidence.GovernedPlan{
			Destination: f.policy.Destination, PolicyVersion: "round2-c06", RegistryModel: "test-model-a",
			Build: func(r evidence.Request) ([]byte, error) {
				return evidence.RenderRequest(f.policy.Destination, r.Input, r.Sources)
			},
			Reserve:    func(context.Context, string, []byte) (int, error) { return 100, nil },
			Arm:        func(context.Context, string) error { return nil },
			CheckRoute: func(context.Context) error { return nil },
			Invoke:     f.model("never reached"),
		}, nil
	}
	f.rec.Accounting = func(context.Context, evidence.Backend, string, string) error { return nil }
	req := f.req("round2-c06-eligibility", "round2 external context input")
	req.Sources = []evidence.Source{{
		ID: "ext-1", Version: 0, Bytes: []byte("SYNTHETIC-EXTERNAL-DOC-1"),
		External: &evidence.ExternalSource{
			ConnectorID: "synthetic-connector", SiteID: "synthetic-site", LibraryID: "synthetic-library",
			DocumentID: "ext-doc-1", ProviderVersion: "2", ETag: "synthetic-etag",
			DocumentSHA256:   evidence.SHA256([]byte("SYNTHETIC-EXTERNAL-DOC-1")),
			DelegatedSubject: "synthetic-subject", CustodianID: f.user, ObservedAt: "2026-01-15T10:00:00Z",
			Offset: 0, Length: len("SYNTHETIC-EXTERNAL-DOC-1"),
		},
	}}
	req.AuthorizeSources = func(context.Context) error { return nil }
	gateCalls := 0
	if _, err := f.rec.Process(context.Background(), req, f.model("bypass"), func(context.Context) error {
		gateCalls++
		if gateCalls == 1 {
			// The C06 context-eligibility refusal after admission.
			return errors.New("context eligibility denied")
		}
		return nil
	}); err == nil {
		t.Fatal("the context-eligibility refusal must fail the turn")
	}
	if f.calls.Load() != 0 {
		t.Fatalf("the model must not be dispatched after the eligibility refusal (%d calls)", f.calls.Load())
	}
	if len(g.calls) < 2 {
		t.Fatalf("FINDING 2: the eligibility-refused turn's protection was consulted %d times, want admission + post-terminal (2)", len(g.calls))
	}
}

// faultingPG drops one terminal-event append so the turn stays OPEN (the
// crash-before-terminal window); the next recovery resolves it.
type faultingPG struct {
	evidence.PG
	mu       sync.Mutex
	failed   bool
	failNext bool
}

func (b *faultingPG) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	if typ, _ := e["type"].(string); typ == "turn_interrupted" {
		b.mu.Lock()
		fail := b.failNext && !b.failed
		if fail {
			b.failed = true
		}
		b.mu.Unlock()
		if fail {
			return evidence.Receipt{}, errors.New("injected terminal append fault")
		}
	}
	return b.PG.Append(ctx, e)
}

// Recovery of an admitted open turn (crash before any terminal event)
// resolves the turn and must establish protection for the complete
// published version set WITHOUT redispatching the model.
func TestRecoveredOpenTurnIsProtectedAfterTerminalEvent(t *testing.T) {
	pool := testdb.New(t)
	g := &guardSpy{applies: true}
	backend := &faultingPG{PG: evidence.PG{DB: pool}, failNext: true}
	rec := &evidence.Recorder{Backend: backend, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "t", Destination: evidence.Destination{Provider: "p", EndpointID: "e", ModelID: "m"}}, nil
	}, Lifecycle: g}
	dispatches := 0
	if _, err := rec.Process(context.Background(), r2Request("round2-recovery"), func(context.Context, []byte) (evidence.ModelOutcome, error) {
		dispatches++
		return evidence.ModelOutcome{Accepted: true, Complete: false, Output: []byte("partial")}, errors.New("provider failure")
	}, func(context.Context) error { return nil }); err == nil || !evidence.IsProviderError(err) {
		t.Fatalf("want provider error, got %v", err)
	}
	// The terminal append faulted: the turn is open. Recovery resolves it
	// (case E) and then establishes protection.
	backend.mu.Lock()
	backend.failNext = false
	backend.mu.Unlock()
	if _, err := rec.Recover(context.Background(), time.Time{}); err != nil {
		t.Fatal(err)
	}
	if dispatches != 1 {
		t.Fatalf("FINDING 2: recovery redispatched the model (%d dispatches)", dispatches)
	}
	if len(g.calls) < 2 {
		t.Fatalf("FINDING 2: the recovered turn's protection was consulted %d times, want admission + post-recovery (2)", len(g.calls))
	}
}
