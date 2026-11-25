package evidence_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

type blockedIntentAck struct {
	evidence.Backend
	before          bool
	entered, resume chan struct{}
}

func (b blockedIntentAck) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	// seq 5 acknowledges disclosure_intent (seq 4) on the ordinary stub path.
	if e["type"] != "evidence_ack" || e["seq"] != 5 {
		return b.Backend.Append(ctx, e)
	}
	if b.before {
		close(b.entered)
		<-b.resume
		return b.Backend.Append(ctx, e)
	}
	r, err := b.Backend.Append(ctx, e)
	close(b.entered)
	<-b.resume
	return r, err
}

func TestFenceLossAtTurnBoundaries(t *testing.T) {
	for _, stage := range []string{"before-intent-ack", "after-intent-ack", "in-model", "both-connections-after-ack"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			f := newFx(t, nil)
			c := testdb.Runtime(t, f.pool)
			backend := evidence.PG{DB: c.Evidence}
			fence, err := backend.AcquireFence(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer fence.Release()
			f.rec.Fence = fence
			f.rec.Backend = backend.WithFence(fence)
			entered, resume := make(chan struct{}), make(chan struct{})
			var once sync.Once
			unblock := func() { once.Do(func() { close(resume) }) }
			defer unblock()
			if stage != "in-model" {
				f.rec.Backend = blockedIntentAck{f.rec.Backend, stage == "before-intent-ack", entered, resume}
			}
			type outcome struct {
				r   evidence.Result
				err error
			}
			result := make(chan outcome, 1)
			go func() {
				r, err := f.rec.Process(ctx, f.req("first", "synthetic"), func(_ context.Context, _ []byte) (evidence.ModelOutcome, error) {
					f.calls.Add(1)
					if stage == "in-model" {
						close(entered)
						<-resume
					}
					return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("must not deliver")}, nil
				}, nil)
				result <- outcome{r, err}
			}()
			select {
			case <-entered:
			case got := <-result:
				t.Fatalf("did not reach %s: %+v", stage, got)
			case <-ctx.Done():
				t.Fatal("timed out reaching turn boundary")
			}
			keys := []string{":charter-instance-fence"}
			if stage == "both-connections-after-ack" {
				keys = append(keys, ":charter-instance-drain")
			}
			for _, key := range keys {
				var killed bool
				err := f.pool.QueryRow(ctx, `WITH key AS (SELECT hashtextextended(current_schema() || $1::text, 0) AS v)
					SELECT pg_terminate_backend(l.pid, 3000) FROM pg_locks l, key
					WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1
					AND l.classid::bigint = ((v >> 32) & 4294967295) AND l.objid::bigint = (v & 4294967295)`, key).Scan(&killed)
				if err != nil || !killed {
					t.Fatalf("could not terminate %s: %v %v", key, killed, err)
				}
			}
			if _, err := f.rec.Process(ctx, f.req("stale", "synthetic"), f.model("stale"), nil); !errors.Is(err, evidence.ErrFenceLost) {
				t.Errorf("stale admission was not refused: %v", err)
			}
			second, err := backend.AcquireFence(ctx)
			if len(keys) == 1 {
				if !errors.Is(err, evidence.ErrFenceHeld) {
					if second != nil {
						second.Release()
					}
					t.Fatalf("successor crossed the drain barrier: %v", err)
				}
				unblock()
			} else if err != nil {
				t.Fatal(err)
			}
			if second != nil {
				defer second.Release()
				rc := &evidence.Recorder{Backend: backend.WithFence(second), Fence: second}
				if n, err := rc.Recover(ctx, time.Time{}); n != 1 || err != nil {
					t.Fatalf("successor recovery while old handler is paused: n=%d, %v", n, err)
				}
				unblock()
			}
			select {
			case got := <-result:
				if got.err == nil || len(got.r.Output) != 0 {
					t.Errorf("stale owner delivered output: %+v", got)
				}
			case <-ctx.Done():
				t.Fatal("old handler did not drain")
			}
			fence.Release()
			wantCalls := int32(0)
			if stage == "in-model" {
				wantCalls = 1
			}
			if n := f.calls.Load(); n != wantCalls {
				t.Errorf("dispatches=%d want %d", n, wantCalls)
			}
			if second == nil {
				second, err = backend.AcquireFence(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer second.Release()
				rc := &evidence.Recorder{Backend: backend.WithFence(second), Fence: second}
				if n, err := rc.Recover(ctx, time.Time{}); n != 1 || err != nil {
					t.Fatalf("recovery after drain: n=%d, %v", n, err)
				}
			}
			rc := &evidence.Recorder{Backend: backend.WithFence(second), Fence: second}
			if n, err := rc.Recover(ctx, time.Time{}); n != 0 || err != nil {
				t.Errorf("recovery was not idempotent: n=%d, %v", n, err)
			}
			var rows int
			if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM evidence_turns`).Scan(&rows); rows != 1 || err != nil {
				t.Fatalf("stale owner wrote an admission: %d turns, %v", rows, err)
			}
			evs := f.verified(f.onlyTurn())
			if strings.Count(types(evs), "turn_interrupted") != 1 {
				t.Errorf("not exactly one interruption: %s", types(evs))
			}
			want := evidence.DisclosureUnknown
			if stage == "before-intent-ack" {
				want = evidence.DisclosureNone
			}
			if got := evidence.DeriveDisclosure(evs); got != want {
				t.Errorf("disclosure=%q want %q", got, want)
			}
		})
	}
}
