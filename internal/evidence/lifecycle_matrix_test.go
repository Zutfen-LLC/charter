package evidence_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/jackc/pgx/v5"
)

type lifeWrite struct {
	name      string
	committed bool
}

type lifeMatrixBackend struct {
	evidence.Backend
	at     int
	mode   string
	trace  []lifeWrite
	cancel func(string)
	fired  bool
}

func (b *lifeMatrixBackend) write(name string, fn func() error) error {
	i := len(b.trace) + 1
	fail := b.at > 0 && (i == b.at || (i > b.at && b.mode == "outage"))
	if i == b.at {
		b.fired = true
	}
	var err error
	committed := false
	if !fail || b.mode == "commit-then-error" {
		err = fn()
		committed = err == nil
	}
	b.trace = append(b.trace, lifeWrite{name, committed})
	if b.cancel != nil {
		b.cancel(name)
	}
	if fail && err == nil {
		return errInjected
	}
	return err
}

func (b *lifeMatrixBackend) Admit(ctx context.Context, a evidence.Admission, e evidence.Event, objs [][]byte) (res evidence.AdmitResult, err error) {
	err = b.write("admission", func() error { var e2 error; res, e2 = b.Backend.Admit(ctx, a, e, objs); return e2 })
	return
}
func (b *lifeMatrixBackend) PutObject(ctx context.Context, tenant string, data []byte) (res evidence.Receipt, err error) {
	err = b.write("put-object", func() error { var e error; res, e = b.Backend.PutObject(ctx, tenant, data); return e })
	return
}
func (b *lifeMatrixBackend) Append(ctx context.Context, e evidence.Event) (res evidence.Receipt, err error) {
	name := e["type"].(string)
	if name == "evidence_ack" {
		if e["seq"] == 5 {
			name = "intent-ack"
		} else {
			name = "output-ack"
		}
	}
	err = b.write(name, func() error { var e2 error; res, e2 = b.Backend.Append(ctx, e); return e2 })
	return
}

func (b *lifeMatrixBackend) committed(name string) bool {
	for _, w := range b.trace {
		if w.name == name && w.committed {
			return true
		}
	}
	return false
}

func TestExpandedC04FailureLifecycleMatrix(t *testing.T) {
	type scenario struct {
		name, disc string
		calls      int
	}
	for _, sc := range []scenario{
		{"deny", evidence.DisclosureNone, 0},
		{"policy-failure", evidence.DisclosureNone, 0},
		{"provider-rejected", evidence.DisclosureUnknown, 1},
		{"provider-unconfirmed", evidence.DisclosureUnknown, 1},
		{"partial-without-acceptance", evidence.DisclosureUnknown, 1},
		{"complete-claimed-without-acceptance", evidence.DisclosureUnknown, 1},
		{"partial-accepted", evidence.DisclosureDisclosed, 1},
		{"authorization-veto", evidence.DisclosureDisclosed, 1},
		{"cancel-before-dispatch", evidence.DisclosureUnknown, 0},
		{"cancel-during-finalization", evidence.DisclosureDisclosed, 1},
	} {
		t.Run(sc.name, func(t *testing.T) {
			f := newFx(t, nil)
			var seed int
			run := func(t *testing.T, mode string, at int) []lifeWrite {
				t.Helper()
				seed++
				req := f.req(fmt.Sprintf("%s-%02d", mode, seed), "synthetic matrix input")
				b := &lifeMatrixBackend{Backend: f.pg, at: at, mode: mode}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				b.cancel = func(name string) {
					if (sc.name == "cancel-before-dispatch" && name == "intent-ack") || (sc.name == "cancel-during-finalization" && name == "usage_settled") {
						cancel()
					}
				}
				rc := &evidence.Recorder{Backend: b, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
					switch sc.name {
					case "deny":
						return evidence.Decision{Reason: "synthetic deny", PolicyVersion: "synthetic-policy"}, nil
					case "policy-failure":
						return evidence.Decision{}, errors.New("synthetic policy unavailable")
					default:
						return f.policy, nil
					}
				}}
				calls := 0
				answer := []byte("synthetic output")
				provider := func(context.Context, []byte) (evidence.ModelOutcome, error) {
					calls++
					switch sc.name {
					case "provider-rejected":
						return evidence.ModelOutcome{}, errors.New("synthetic upstream rejection")
					case "provider-unconfirmed":
						return evidence.ModelOutcome{}, context.DeadlineExceeded
					case "partial-without-acceptance":
						return evidence.ModelOutcome{Output: answer}, errors.New("synthetic uncertain partial")
					case "complete-claimed-without-acceptance":
						return evidence.ModelOutcome{Output: answer, Complete: true}, nil
					case "partial-accepted":
						return evidence.ModelOutcome{Accepted: true, Output: answer}, errors.New("synthetic stream interruption")
					default:
						return evidence.ModelOutcome{Accepted: true, Complete: true, Output: answer}, nil
					}
				}
				gate := func(context.Context) error {
					if sc.name == "authorization-veto" {
						return errors.New("synthetic release veto")
					}
					return nil
				}
				res, err := rc.Process(ctx, req, provider, gate)
				if err == nil || len(res.Output) > 0 {
					t.Fatalf("failure scenario returned output or success: %+v %v", res, err)
				}
				if at > 0 && !b.fired {
					t.Fatalf("target write %d never hit: %+v", at, b.trace)
				}
				if calls > 1 || (at == 0 && calls != sc.calls) {
					t.Fatalf("unexpected dispatch count %d", calls)
				}
				var id string
				readErr := f.pool.QueryRow(context.Background(), `SELECT turn_id::text FROM evidence_turns WHERE tenant_id=$1::uuid AND idempotency_key=$2`, f.tenant, req.IdempotencyKey).Scan(&id)
				if errors.Is(readErr, pgx.ErrNoRows) {
					if at != 1 || mode == "commit-then-error" || calls != 0 {
						t.Fatalf("unexpected missing admission at %d after %d calls", at, calls)
					}
					return b.trace
				}
				if readErr != nil {
					t.Fatal(readErr)
				}
				recovered := &evidence.Recorder{Backend: f.pg, Policy: rc.Policy}
				for i := 0; i < 2; i++ {
					n, err := recovered.Recover(context.Background(), time.Time{})
					if err != nil || n > 1 || (i > 0 && n != 0) {
						t.Fatalf("recovery %d: n=%d %v", i, n, err)
					}
				}
				evs := f.verified(id)
				objs := f.objects(evs)
				if errs := evidence.VerifyCurrentFull(evs, objs); len(errs) > 0 {
					t.Fatalf("full current profile failed: %v", errs)
				}
				want := evidence.DisclosureNone
				if b.committed("intent-ack") {
					want = evidence.DisclosureUnknown
				}
				if b.committed("provider_accepted") {
					want = evidence.DisclosureDisclosed
				}
				if got := evidence.DeriveDisclosure(evs); got != want || (at == 0 && got != sc.disc) || (calls > 0 && got == evidence.DisclosureNone) {
					t.Fatalf("disclosure=%s want=%s baseline=%s calls=%d (%s)", got, want, sc.disc, calls, types(evs))
				}
				last := evs[len(evs)-1]
				wantTerminal := evidence.TypeTurnInterrupted
				wantOutcome := ""
				if (sc.name == "deny" || sc.name == "policy-failure") && b.committed("policy_decision") {
					wantTerminal, wantOutcome = evidence.TypeTurnCompleted, "denied"
				}
				if b.committed("response_released") {
					wantTerminal, wantOutcome = evidence.TypeTurnCompleted, "completed"
				}
				if last["type"] != wantTerminal || (wantOutcome != "" && last["payload"].(map[string]any)["outcome"] != wantOutcome) ||
					strings.Count(types(evs), "turn_completed")+strings.Count(types(evs), "turn_interrupted") != 1 {
					t.Fatalf("bad terminal: %s, %+v", types(evs), last)
				}
				if (strings.HasPrefix(sc.name, "partial-") || sc.name == "complete-claimed-without-acceptance") && b.committed("output_recorded") {
					if got := string(objs[evidence.SHA256(answer)]); got != string(answer) {
						t.Fatalf("durable partial bytes not retained: %q", got)
					}
				}
				previous := calls
				res, err = recovered.Process(context.Background(), req, provider, nil)
				if calls != previous {
					t.Fatal("replay redispatched")
				}
				if wantOutcome == "completed" && (err != nil || !res.Replayed || string(res.Output) != string(answer)) {
					t.Fatalf("delivery-only retry: %+v %v", res, err)
				}
				if wantOutcome != "completed" && (err == nil || len(res.Output) > 0) {
					t.Fatalf("non-success replay: %+v %v", res, err)
				}
				return b.trace
			}
			var baseline []lifeWrite
			if !t.Run("unfaulted", func(t *testing.T) { baseline = run(t, "none", 0) }) {
				return
			}
			if len(baseline) < 3 {
				t.Fatalf("insufficient write boundaries: %v", baseline)
			}
			for _, mode := range []string{"reject", "commit-then-error", "outage"} {
				for i, write := range baseline {
					t.Run(fmt.Sprintf("%s/%02d-%s", mode, i+1, write.name), func(t *testing.T) { run(t, mode, i+1) })
				}
			}
		})
	}
}
