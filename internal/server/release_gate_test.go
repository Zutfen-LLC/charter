package server

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// hookBackend runs deterministic hooks around evidence writes: before(typ) runs
// just before the named event type is appended, after(typ) just after it is
// durable. Hooks cancel contexts, revoke access or close pools at an exact point
// of the write path; there are no sleeps.
type hookBackend struct {
	evidence.Backend
	before func(typ string) error
	after  func(typ string)
}

func (h hookBackend) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	typ := e["type"].(string)
	if h.before != nil {
		if err := h.before(typ); err != nil {
			return evidence.Receipt{}, err
		}
	}
	r, err := h.Backend.Append(ctx, e)
	if err == nil && h.after != nil {
		h.after(typ)
	}
	return r, err
}

func (h hookBackend) Admit(ctx context.Context, a evidence.Admission, e evidence.Event, o [][]byte) (evidence.AdmitResult, error) {
	if h.before != nil {
		if err := h.before("admit"); err != nil {
			return evidence.AdmitResult{}, err
		}
	}
	return h.Backend.Admit(ctx, a, e, o)
}

// gateEnv is an env whose evidence recorder uses its own pool and a counting
// model, so authorization and evidence storage can fail independently.
type gateEnv struct {
	*env
	calls atomic.Int32
	ev    evidence.PG
}

func newGateEnv(t *testing.T) *gateEnv {
	t.Helper()
	g := &gateEnv{env: newEnv(t)}
	g.ev = evidence.PG{DB: testdb.Clone(t, g.st.DB)}
	g.auth.Evidence.Backend = g.ev
	g.auth.Model = func(context.Context, []byte) (evidence.ModelOutcome, error) {
		g.calls.Add(1)
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte(sensitive)}, nil
	}
	return g
}

func (g *gateEnv) hook(before func(string) error, after func(string)) {
	g.auth.Evidence.Backend = hookBackend{Backend: g.ev, before: before, after: after}
}

func (g *gateEnv) refused(code int, body string, want int) {
	g.t.Helper()
	if code != want || strings.Contains(body, sensitive) {
		g.t.Fatalf("code=%d (want %d) body=%s", code, want, body)
	}
}

func (g *gateEnv) lastTurnEvents() []evidence.Event {
	g.t.Helper()
	ids := g.turns()
	if len(ids) == 0 {
		g.t.Fatal("no turn")
	}
	return g.verify(ids[len(ids)-1])
}

func types(evs []evidence.Event) string {
	var s []string
	for _, e := range evs {
		s = append(s, e["type"].(string))
	}
	return strings.Join(s, ",")
}

// C03 linearization: output must not be returned if the request ended while
// the release was being persisted, settled or terminated. Each case cancels or
// revokes exactly at the named evidence write.
func TestReleaseGateHoldsDuringEvidenceFinalization(t *testing.T) {
	for _, at := range []string{"response_released", "usage_settled", "turn_completed"} {
		t.Run("cancelled during "+at, func(t *testing.T) {
			g := newGateEnv(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			g.hook(func(typ string) error {
				if typ == at {
					cancel()
				}
				return nil
			}, nil)
			code, body := g.modelCall("alice", ctx)
			g.refused(code, body, http.StatusServiceUnavailable)
			if g.calls.Load() != 1 {
				t.Fatalf("model calls = %d", g.calls.Load())
			}
			// Already-disclosed work is still fully recorded despite the cancel.
			if evs := g.lastTurnEvents(); evs[len(evs)-1]["type"] != "turn_completed" && evs[len(evs)-1]["type"] != "turn_interrupted" {
				t.Fatalf("turn left open: %s", types(evs))
			}
		})
	}
	t.Run("deadline expires during release persistence", func(t *testing.T) {
		g := newGateEnv(t)
		g.auth.WorkTimeout = 100 * time.Millisecond
		var workCtx context.Context
		g.auth.Model = func(ctx context.Context, _ []byte) (evidence.ModelOutcome, error) {
			workCtx = ctx
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte(sensitive)}, nil
		}
		g.hook(func(typ string) error {
			if typ == "response_released" {
				<-workCtx.Done() // the deadline, not a sleep, releases us
			}
			return nil
		}, nil)
		code, body := g.modelCall("alice", context.Background())
		g.refused(code, body, http.StatusGatewayTimeout)
	})
	t.Run("cancelled during terminal persistence with a retry", func(t *testing.T) {
		g := newGateEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var failed atomic.Bool
		g.hook(func(typ string) error {
			if typ == "turn_completed" && failed.CompareAndSwap(false, true) {
				cancel()
				return context.DeadlineExceeded // first terminal attempt fails; recorder retries
			}
			return nil
		}, nil)
		code, body := g.modelCall("alice", ctx)
		g.refused(code, body, http.StatusServiceUnavailable)
		evs := g.lastTurnEvents()
		if evs[len(evs)-1]["type"] != "turn_completed" {
			t.Fatalf("retry did not finish the turn: %s", types(evs))
		}
	})
	t.Run("membership revoked during finalization", func(t *testing.T) {
		g := newGateEnv(t)
		g.hook(func(typ string) error {
			if typ == "usage_settled" {
				_, err := g.st.DB.Exec(context.Background(), `DELETE FROM project_members WHERE user_id=$1 AND project_id=$2`, g.users["alice"], g.p1)
				return err
			}
			return nil
		}, nil)
		code, body := g.modelCall("alice", context.Background())
		g.refused(code, body, http.StatusForbidden)
	})
	t.Run("account disabled during finalization", func(t *testing.T) {
		g := newGateEnv(t)
		g.hook(func(typ string) error {
			if typ == "turn_completed" {
				_, err := g.st.DB.Exec(context.Background(), `UPDATE users SET disabled_at=now() WHERE id=$1`, g.users["alice"])
				return err
			}
			return nil
		}, nil)
		code, body := g.modelCall("alice", context.Background())
		g.refused(code, body, http.StatusForbidden)
	})
	t.Run("authorization database outage at final authorization", func(t *testing.T) {
		g := newGateEnv(t)
		g.hook(nil, func(typ string) {
			if typ == "turn_completed" {
				g.st.DB.Close() // authorization store dies after the last evidence write
			}
		})
		code, body := g.modelCall("alice", context.Background())
		g.refused(code, body, http.StatusServiceUnavailable)
	})
	t.Run("authorized delivery succeeds", func(t *testing.T) {
		g := newGateEnv(t)
		code, body := g.modelCall("alice", context.Background())
		if code != 200 || !strings.Contains(body, sensitive) {
			t.Fatalf("%d %s", code, body)
		}
		if got := types(g.lastTurnEvents()); !strings.HasSuffix(got, "response_released,usage_settled,turn_completed") {
			t.Fatal(got)
		}
	})
}

// Cancellation or expiry after the intent is acknowledged, or during admission,
// must stop dispatch: zero provider invocations, nothing released, and the
// turn is closed truthfully (acked intent derives "unknown").
func TestNoDispatchAfterCancellationOrExpiry(t *testing.T) {
	t.Run("cancelled right after the intent ack", func(t *testing.T) {
		g := newGateEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g.hook(nil, func(typ string) {
			if typ == "evidence_ack" {
				cancel()
			}
		})
		code, body := g.modelCall("alice", ctx)
		g.refused(code, body, http.StatusServiceUnavailable)
		if g.calls.Load() != 0 {
			t.Fatalf("provider invoked %d times after cancellation", g.calls.Load())
		}
		evs := g.lastTurnEvents()
		last := evs[len(evs)-1]
		if last["type"] != "turn_interrupted" || evidence.DeriveDisclosure(evs) != evidence.DisclosureUnknown {
			t.Fatalf("log: %s", types(evs))
		}
	})
	t.Run("cancelled during admission", func(t *testing.T) {
		g := newGateEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		g.hook(func(typ string) error {
			if typ == "admit" {
				cancel()
			}
			return nil
		}, nil)
		code, body := g.modelCall("alice", ctx)
		g.refused(code, body, http.StatusServiceUnavailable)
		if g.calls.Load() != 0 {
			t.Fatalf("provider invoked %d times", g.calls.Load())
		}
		if ids := g.turns(); len(ids) == 1 {
			evs := g.verify(ids[0])
			if evs[len(evs)-1]["type"] != "turn_interrupted" || evidence.DeriveDisclosure(evs) != evidence.DisclosureNone {
				t.Fatalf("log: %s", types(evs))
			}
		}
	})
	t.Run("deadline expires while evidence is written before dispatch", func(t *testing.T) {
		g := newGateEnv(t)
		g.auth.WorkTimeout = 100 * time.Millisecond
		ctxSeen := make(chan context.Context, 1)
		g.auth.Evidence.Policy = func(ctx context.Context, r evidence.Request) (evidence.Decision, error) {
			ctxSeen <- ctx
			return StubPolicy()(ctx, r)
		}
		g.hook(func(typ string) error {
			if typ == "disclosure_intent" {
				<-(<-ctxSeen).Done()
			}
			return nil
		}, nil)
		code, body := g.modelCall("alice", context.Background())
		g.refused(code, body, http.StatusGatewayTimeout)
		if g.calls.Load() != 0 {
			t.Fatalf("provider invoked %d times after the deadline", g.calls.Load())
		}
	})
}

// Store-level authorization (C03): ProjectMatter must itself require an active
// account and project membership, with absent and unauthorized indistinguishable.
func TestProjectMatterRequiresActiveMembership(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := store.Principal{UserID: e.users["alice"], TenantID: e.tenant}
	if m, err := e.st.ProjectMatter(ctx, alice, e.p1); err != nil || m == "" {
		t.Fatalf("positive control: %q %v", m, err)
	}
	if m, err := e.st.ProjectMatter(ctx, alice, strings.ToUpper(e.p1)); err != nil || m == "" {
		t.Fatalf("uppercase equivalence: %q %v", m, err)
	}
	bob := store.Principal{UserID: e.users["bob"], TenantID: e.tenant}       // member of P2 only
	zed := store.Principal{UserID: e.users["zed"], TenantID: e.otherTen}     // other tenant
	stale := store.Principal{UserID: e.users["alice"], TenantID: e.otherTen} // wrong tenant for the user
	absent := "00000000-0000-0000-0000-000000000000"
	var base error
	for name, c := range map[string]struct {
		p   store.Principal
		pid string
	}{"non-member": {bob, e.p1}, "cross-tenant": {zed, e.p1}, "wrong tenant": {stale, e.p1}, "absent": {alice, absent}} {
		m, err := e.st.ProjectMatter(ctx, c.p, c.pid)
		if err != store.ErrNotFound || m != "" {
			t.Errorf("%s: got %q %v, want ErrNotFound", name, m, err)
		}
		if base == nil {
			base = err
		} else if err != base {
			t.Errorf("%s: distinguishable error", name)
		}
	}
	// Account disabled after the Principal was resolved.
	if _, err := e.st.DB.Exec(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1`, e.users["alice"]); err != nil {
		t.Fatal(err)
	}
	if m, err := e.st.ProjectMatter(ctx, alice, e.p1); err != store.ErrNotFound || m != "" {
		t.Fatalf("disabled account: %q %v", m, err)
	}
}

// Identifiers are canonicalized before comparison and de-duplication.
func TestModelCallAcceptsMixedCaseIDsAndDedupes(t *testing.T) {
	e := newEnv(t)
	var sent []byte
	e.auth.Model = func(_ context.Context, b []byte) (evidence.ModelOutcome, error) {
		sent = b
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("ok")}, nil
	}
	up := strings.ToUpper
	body := `{"input":"x","artifact_ids":["` + up(e.a1) + `","` + e.a1 + `"]}`
	code, resp, _ := e.post("alice", up(e.p1), body)
	if code != 200 {
		t.Fatalf("%d %s", code, resp)
	}
	if n := strings.Count(string(sent), "needle-one alpha"); n != 1 {
		t.Fatalf("artifact duplicated or missing in the sealed request (%d): %s", n, sent)
	}
	evs := e.verify(e.turns()[0])
	if evs[0]["project_id"] != e.p1 {
		t.Fatalf("project id not canonical: %v", evs[0]["project_id"])
	}
}
