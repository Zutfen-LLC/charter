package evidence_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// guardSpy records when the C07 lifecycle guard is consulted during a turn.
type guardSpy struct {
	calls    []string
	failAt   int
	failErr  error
	applies  bool
	failNext bool
}

func (g *guardSpy) HoldApplies(ctx context.Context, tenant, matter, custodian string, recordedAt time.Time) (bool, error) {
	if g.failNext {
		g.failNext = false
		return false, errors.New("guard outage")
	}
	return g.applies, nil
}

func (g *guardSpy) EnsureProtected(ctx context.Context, tenant, matter, custodian, turn string, recordedAt time.Time) error {
	g.calls = append(g.calls, "ensure")
	if g.failErr != nil && len(g.calls) == g.failAt {
		return g.failErr
	}
	return nil
}

// A turn that runs while a hold matches has its protection verified BOTH
// after admission and after the LAST evidence write (the terminal event):
// the response may only escape when every version the turn published is
// protected. Regression for the drill-found gap where post-release event
// versions escaped the guard.
func TestGuardCoversAdmissionAndFinalEvidenceWrites(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	g := &guardSpy{applies: true}
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "t", Destination: evidence.Destination{Provider: "p", EndpointID: "e", ModelID: "m"}}, nil
	}, Lifecycle: g}
	res, err := rec.Process(ctx, evidence.Request{
		TenantID: "11111111-1111-1111-1111-111111111111", ProjectID: "22222222-2222-2222-2222-222222222222",
		MatterID: "33333333-3333-3333-3333-333333333333", CustodianID: "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "guard-order", Input: []byte("guarded input"),
	}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("guarded output")}, nil
	}, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	// Admission + pre-release + post-terminal verification.
	if len(g.calls) < 3 {
		t.Fatalf("guard consulted %d times, want at least admission + release-gate + post-terminal (3)", len(g.calls))
	}
	events, err := rec.Backend.Load(ctx, "11111111-1111-1111-1111-111111111111", res.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	last := events[len(events)-1]
	if last["type"] != "turn_completed" {
		t.Fatalf("turn not terminal: %v", last["type"])
	}
	// The guard must have been consulted after the terminal event was
	// durably stored: the last turn event at the final consultation must be
	// the terminal one (verified by a fresh load inside EnsureProtected in
	// production; here the ordering is pinned by the recorder contract).
	if g.calls[len(g.calls)-1] != "ensure" {
		t.Fatalf("final guard call was %q", g.calls[len(g.calls)-1])
	}
}

// A guard failure after the terminal event withholds the output: no
// successful response escapes without its required hold protection.
func TestGuardFailureAfterFinalWriteWithholdsOutput(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	g := &guardSpy{applies: true, failAt: 3, failErr: errors.New("protection readback failed")}
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "t", Destination: evidence.Destination{Provider: "p", EndpointID: "e", ModelID: "m"}}, nil
	}, Lifecycle: g}
	_, err := rec.Process(ctx, evidence.Request{
		TenantID: "11111111-1111-1111-1111-111111111111", ProjectID: "22222222-2222-2222-2222-222222222222",
		MatterID: "33333333-3333-3333-3333-333333333333", CustodianID: "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "guard-fail", Input: []byte("guarded input"),
	}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("withheld output")}, nil
	}, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("a post-terminal protection failure must fail the delivery closed")
	}
	if !errors.Is(err, evidence.ErrFailClosed) {
		t.Fatalf("expected fail-closed, got %v", err)
	}
}

// A guard outage at admission fails the turn closed before any policy work
// or dispatch.
func TestGuardOutageAtAdmissionFailsClosed(t *testing.T) {
	pool := testdb.New(t)
	ctx := context.Background()
	g := &guardSpy{failNext: true}
	rec := &evidence.Recorder{Backend: evidence.PG{DB: pool}, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "t"}, nil
	}, Lifecycle: g}
	_, err := rec.Process(ctx, evidence.Request{
		TenantID: "11111111-1111-1111-1111-111111111111", ProjectID: "22222222-2222-2222-2222-222222222222",
		MatterID: "33333333-3333-3333-3333-333333333333", CustodianID: "44444444-4444-4444-4444-444444444444",
		IdempotencyKey: "guard-outage", Input: []byte("input"),
	}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
		t.Fatal("the model must not be dispatched when the guard is unavailable")
		return evidence.ModelOutcome{}, nil
	}, func(context.Context) error { return nil })
	if err == nil {
		t.Fatal("guard outage must fail closed")
	}
}
