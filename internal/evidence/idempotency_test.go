package evidence_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func twoSources(f *fx) evidence.Request {
	r := f.req("key", "the input")
	r.Sources = []evidence.Source{
		{ID: "doc-1", Version: 2, Bytes: []byte("first source")},
		{ID: "doc-2", Version: 1, Bytes: []byte("second source")},
	}
	return r
}

// A repeated key is the same request only if EVERYTHING that shaped the
// disclosure is the same: input, source ids, versions, content, order, matter.
func TestIdempotencyKeyBindsTheWholeRequest(t *testing.T) {
	f := newFx(t, nil)
	ctx := context.Background()
	if _, err := f.rec.Process(ctx, twoSources(f), f.model("answer"), nil); err != nil {
		t.Fatal(err)
	}
	mut := map[string]func(r *evidence.Request){
		"source id":      func(r *evidence.Request) { r.Sources[0].ID = "doc-9" },
		"source content": func(r *evidence.Request) { r.Sources[0].Bytes = []byte("first source, edited") },
		"source version": func(r *evidence.Request) { r.Sources[0].Version = 3 },
		"source order":   func(r *evidence.Request) { r.Sources[0], r.Sources[1] = r.Sources[1], r.Sources[0] },
		"extra source": func(r *evidence.Request) {
			r.Sources = append(r.Sources, evidence.Source{ID: "d3", Version: 1, Bytes: []byte("x")})
		},
		"dropped source": func(r *evidence.Request) { r.Sources = r.Sources[:1] },
		"matter":         func(r *evidence.Request) { r.MatterID = evidence.NewUUID() },
		"input":          func(r *evidence.Request) { r.Input = []byte("a different input") },
	}
	for name, m := range mut {
		r := twoSources(f)
		m(&r)
		if _, err := f.rec.Process(ctx, r, f.model("x"), nil); !errors.Is(err, evidence.ErrIdempotencyMismatch) {
			t.Errorf("%s: changed request accepted under the same key: %v", name, err)
		}
	}
	// Volatile fields are NOT part of identity.
	r := twoSources(f)
	r.RequestID = "a-completely-different-request-id"
	res, err := f.rec.Process(ctx, r, f.model("x"), nil)
	if err != nil || !res.Replayed || string(res.Output) != "answer" {
		t.Fatalf("identical request with a new request id: %+v %v", res, err)
	}
	if f.calls.Load() != 1 {
		t.Fatalf("model calls = %d", f.calls.Load())
	}
	// The same key in another project or tenant is a different turn.
	for name, m := range map[string]func(r *evidence.Request){
		"project": func(r *evidence.Request) { r.ProjectID = evidence.NewUUID() },
		"tenant":  func(r *evidence.Request) { r.TenantID = evidence.NewUUID() },
	} {
		r := twoSources(f)
		m(&r)
		res, err := f.rec.Process(ctx, r, f.model("other"), nil)
		if err != nil || res.Replayed {
			t.Errorf("%s: key leaked across scopes: %+v %v", name, res, err)
		}
	}
}

// Exactly-once admission under concurrency: identical requests dispatch once;
// conflicting requests under one key admit one and refuse the other.
func TestConcurrentAdmissionsDispatchOnce(t *testing.T) {
	run := func(t *testing.T, conflicting bool) {
		f := newFx(t, nil)
		ctx := context.Background()
		const n = 8
		type outcome struct {
			res evidence.Result
			err error
		}
		results := make([]outcome, n)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				r := f.req("same-key", "input")
				if conflicting && i%2 == 1 {
					r.Input = []byte("different input")
				}
				<-start
				res, err := f.rec.Process(ctx, r, f.model("answer"), nil)
				results[i] = outcome{res, err}
			}(i)
		}
		close(start)
		wg.Wait()
		if f.calls.Load() != 1 {
			t.Fatalf("model dispatched %d times for one idempotency key", f.calls.Load())
		}
		var turns int
		_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM evidence_turns`).Scan(&turns)
		if turns != 1 {
			t.Fatalf("admitted %d turns", turns)
		}
		for i, o := range results {
			switch {
			case o.err == nil:
			case errors.Is(o.err, evidence.ErrTurnInFlight):
			case conflicting && errors.Is(o.err, evidence.ErrIdempotencyMismatch):
			default:
				t.Errorf("request %d: unexpected error %v", i, o.err)
			}
		}
		f.verified(f.onlyTurn())
	}
	t.Run("identical", func(t *testing.T) { run(t, false) })
	t.Run("conflicting", func(t *testing.T) { run(t, true) })
}

// corruptingBackend returns altered or missing objects on read.
type corruptingBackend struct {
	evidence.Backend
	mode string
}

func (c corruptingBackend) Object(ctx context.Context, tenant, sha string) ([]byte, error) {
	b, err := c.Backend.Object(ctx, tenant, sha)
	if err != nil {
		return nil, err
	}
	switch c.mode {
	case "missing":
		if string(b) == "the answer" {
			return nil, evidence.ErrNotFound
		}
	case "corrupt":
		if string(b) == "the answer" {
			return []byte("a forged answer"), nil
		}
	case "truncated":
		if string(b) == "the answer" {
			return b[:3], nil
		}
	}
	return b, nil
}

func TestReplayRefusesMissingOrInconsistentEvidence(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "truncated"} {
		t.Run(mode, func(t *testing.T) {
			f := newFx(t, nil)
			ctx := context.Background()
			if _, err := f.rec.Process(ctx, f.req("k", "in"), f.model("the answer"), nil); err != nil {
				t.Fatal(err)
			}
			f.rec.Backend = corruptingBackend{Backend: f.pg, mode: mode}
			res, err := f.rec.Process(ctx, f.req("k", "in"), f.model("x"), nil)
			if !errors.Is(err, evidence.ErrFailClosed) || len(res.Output) != 0 {
				t.Fatalf("replayed unverifiable evidence: %+v %v", res, err)
			}
			if f.calls.Load() != 1 {
				t.Fatal("replay dispatched")
			}
		})
	}
}
