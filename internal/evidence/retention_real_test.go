//go:build retention_drill

package evidence

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/jackc/pgx/v5/pgxpool"
)

// No in-memory object state. Every unfailed call reaches the same pinned S3
// implementation and runtime identity exercised by the authenticated drill.
// Injected faults affect the client observation or the PostgreSQL session;
// they do not masquerade as native protection proof.
type realFaultTransport struct {
	*s3transport.Client
	before    func(context.Context, string, []byte) error
	after     func(context.Context, string, string, []byte) error
	readFault func(string, s3transport.Version) (s3transport.Version, error)
}

func (s *realFaultTransport) Create(ctx context.Context, k string, b []byte, u time.Time) (string, error) {
	if s.before != nil {
		if err := s.before(ctx, k, b); err != nil {
			return "", err
		}
	}
	id, err := s.Client.Create(ctx, k, b, u)
	if err != nil {
		return id, err
	}
	if s.after != nil {
		if err = s.after(ctx, k, id, b); err != nil {
			return "", err
		}
	}
	return id, nil
}
func (s *realFaultTransport) Read(ctx context.Context, k, id string) (s3transport.Version, error) {
	v, err := s.Client.Read(ctx, k, id)
	if err == nil && s.readFault != nil {
		return s.readFault(k, v)
	}
	return v, err
}

func TestRealRetainedBoundaryFailures(t *testing.T) {
	require := func(k string) string {
		t.Helper()
		v := os.Getenv(k)
		if v == "" {
			t.Fatalf("mandatory real-storage input %s is missing", k)
		}
		return v
	}
	if require("CHARTER_S3_SYNTHETIC_OPT_IN") != "I_OWN_THIS_SYNTHETIC_CHARTER_C04_LAB" {
		t.Fatal("synthetic opt-in required")
	}
	endpoint := require("CHARTER_S3_ENDPOINT")
	bucket := require("CHARTER_S3_BUCKET")
	if endpoint != "http://127.0.0.1:7481" || !strings.HasPrefix(bucket, "charter-c04-protected-") {
		t.Fatal("expected owned lab endpoint and bucket")
	}
	root := require("CHARTER_S3_DEPLOYMENT")
	secret, err := os.ReadFile(require("CHARTER_S3_RUNTIME_SECRET_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	s3, err := s3transport.New(s3transport.Config{Endpoint: endpoint, Region: require("CHARTER_S3_REGION"), Bucket: bucket, AccessKeyID: require("CHARTER_S3_RUNTIME_ACCESS_KEY"), SecretAccessKey: strings.TrimSpace(string(secret)), UseBucketDefault: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err = s3.Check(ctx); err != nil {
		t.Fatal(err)
	}
	open := func(key string) *pgxpool.Pool {
		t.Helper()
		c, e := pgxpool.ParseConfig(require(key))
		if e != nil || !net.ParseIP(c.ConnConfig.Host).IsLoopback() || !strings.HasPrefix(c.ConnConfig.Database, "charter_c04_disposable_") {
			t.Fatal("must use disposable PostgreSQL")
		}
		p, e := pgxpool.NewWithConfig(ctx, c)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(p.Close)
		return p
	}
	pg := PG{DB: open("CHARTER_EVIDENCE_DATABASE_URL")}
	owner := open("CHARTER_DRILL_OWNER_DSN")
	req := Request{TenantID: "fault-tenant", ProjectID: "fixture-project", MatterID: "fixture-matter", CustodianID: "fixture-custodian", IdempotencyKey: "synthetic-fault", RequestID: "synthetic-request", Input: []byte("fixture input"), Sources: []Source{{ID: "fixture-source", Version: 1, Bytes: []byte("fixture excerpt")}}}
	out := []byte("fixture output must be withheld on error")
	var injected = errors.New("deterministic boundary failure")
	policy := func(context.Context, Request) (Decision, error) {
		return Decision{Allow: true, PolicyVersion: "test-policy", ReserveUnits: 3, Destination: Destination{Provider: "fixture", EndpointID: "test-local", ModelID: "model"}}, nil
	}
	cases := []struct {
		name    string
		calls   int32
		recover bool
		success bool
	}{
		{"pre_admission", 0, false, false}, {"partial_admission", 0, false, false}, {"lost_blob_response", 1, false, true}, {"lost_admission_response", 0, true, false},
		{"pg_commit_after_admission", 0, true, false}, {"intent_body", 0, true, false}, {"intent_ack", 0, true, false}, {"outage_during_model", 1, true, false},
		{"output_bytes", 1, true, false}, {"finalization", 1, true, false}, {"bad_read_mode", 0, false, false}, {"short_read", 0, false, false}, {"wrong_bytes", 0, false, false},
		{"cancel_during_write", 0, false, false}, {"deadline_during_storage", 0, false, false}, {"revoked_final_gate", 1, false, false},
		{"concurrent_admissions", 1, false, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			acquire := func() *Fence {
				t.Helper()
				f, e := pg.AcquireFence(ctx)
				if e != nil {
					t.Fatal(e)
				}
				t.Cleanup(f.Release)
				return f
			}
			f := acquire()
			if rival, err := pg.AcquireFence(ctx); !errors.Is(err, ErrFenceHeld) {
				if rival != nil {
					rival.Release()
				}
				t.Fatalf("second owner acquired active PostgreSQL fence: %v", err)
			}
			p, k, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				t.Fatal(e)
			}
			var hit atomic.Bool
			var dispatch atomic.Int32
			transport := &realFaultTransport{Client: s3}
			dep := fmt.Sprintf("%s-f%d", root, i)
			options := RetentionOptions{Store: transport, Deployment: dep, Bucket: bucket, TrustedCommitKey: p, Signer: k, Fence: f, RetainFor: time.Minute}
			makeRecorder := func(o RetentionOptions) *Recorder {
				b, x := NewRetentionBackend(o)
				if x != nil {
					t.Fatal(x)
				}
				return &Recorder{Backend: b, Fence: o.Fence, Policy: policy}
			}
			rec := makeRecorder(options)
			runCtx, stop := context.WithCancel(ctx)
			defer stop()
			marker := func(key string) bool { return strings.Contains(key, "/admissions/") }
			suffix := func(b []byte, typ string) bool { return strings.Contains(string(b), `"type":"`+typ+`"`) }
			fail := func() error { hit.Store(true); return injected }
			transport.before = func(c context.Context, key string, data []byte) error {
				switch tc.name {
				case "pre_admission":
					return fail()
				case "partial_admission":
					if strings.Contains(key, "/data/events/") {
						return fail()
					}
				case "intent_body":
					if suffix(data, "disclosure_intent") {
						return fail()
					}
				case "intent_ack":
					if suffix(data, "evidence_ack") && dispatch.Load() == 0 {
						return fail()
					}
				case "outage_during_model":
					if dispatch.Load() > 0 {
						return fail()
					}
				case "output_bytes":
					if string(data) == string(out) {
						return fail()
					}
				case "finalization":
					if suffix(data, "turn_completed") {
						return fail()
					}
				case "cancel_during_write":
					hit.Store(true)
					stop()
					return c.Err()
				case "deadline_during_storage":
					wait, done := context.WithTimeout(c, 2*time.Millisecond)
					defer done()
					<-wait.Done()
					hit.Store(true)
					return wait.Err()
				}
				return nil
			}
			transport.after = func(c context.Context, key, id string, data []byte) error {
				if hit.Load() {
					return nil
				}
				switch tc.name {
				case "lost_blob_response":
					if strings.Contains(key, "/data/objects/") {
						hit.Store(true)
						return &s3transport.AmbiguousError{}
					}
				case "lost_admission_response":
					if marker(key) {
						hit.Store(true)
						return &s3transport.AmbiguousError{}
					}
				case "pg_commit_after_admission":
					if marker(key) {
						got, e := s3.Read(c, key, id)
						if e != nil || string(got.Data) != string(data) {
							t.Fatalf("PG fault not preceded by verified real storage: %v", e)
						}
						var killed bool
						e = owner.QueryRow(c, "SELECT pg_terminate_backend($1)", f.primary.PgConn().PID()).Scan(&killed)
						if e != nil || !killed {
							t.Fatalf("did not terminate actual owner session: %v", e)
						}
						hit.Store(true)
					}
				}
				return nil
			}
			transport.readFault = func(_ string, v s3transport.Version) (s3transport.Version, error) {
				switch tc.name {
				case "bad_read_mode":
					v.Mode = "GOVERNANCE"
					hit.Store(true)
				case "short_read":
					v.Until = time.Now().Add(time.Second)
					hit.Store(true)
				case "wrong_bytes":
					v.Data = []byte("substituted wire bytes")
					hit.Store(true)
				}
				return v, nil
			}
			model := func(context.Context, []byte) (ModelOutcome, error) {
				dispatch.Add(1)
				return ModelOutcome{Accepted: true, Complete: true, Output: out}, nil
			}
			if tc.name == "concurrent_admissions" {
				entered, release := make(chan struct{}), make(chan struct{})
				defer close(release)
				first := make(chan error, 1)
				go func() {
					_, err := rec.Process(ctx, req, func(c context.Context, b []byte) (ModelOutcome, error) {
						close(entered)
						<-release
						return model(c, b)
					}, nil)
					first <- err
				}()
				select {
				case <-entered:
				case err := <-first:
					t.Fatalf("first admission failed: %v", err)
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				conflict := req
				conflict.Input = []byte("different synthetic input")
				if _, err := rec.Process(ctx, conflict, model, nil); !errors.Is(err, ErrIdempotencyMismatch) {
					t.Fatalf("conflicting admission: %v", err)
				}
				if _, err := rec.Process(ctx, req, model, nil); !errors.Is(err, ErrTurnInFlight) {
					t.Fatalf("identical in-flight admission: %v", err)
				}
				// Release only once, and ensure the owning turn finishes before the
				// subtest drops its fence.
				release <- struct{}{}
				if err := <-first; err != nil {
					t.Fatal(err)
				}
				if r, err := rec.Process(ctx, req, model, nil); err != nil || !r.Replayed || dispatch.Load() != 1 || string(r.Output) != string(out) {
					t.Fatalf("delivery-only replay: calls=%d err=%v", dispatch.Load(), err)
				}
				return
			}
			authorize := func(context.Context) error {
				if tc.name == "revoked_final_gate" && dispatch.Load() > 0 {
					return fail()
				}
				return nil
			}
			got, e := rec.Process(runCtx, req, model, authorize)
			if !hit.Load() || dispatch.Load() != tc.calls {
				t.Fatalf("fixture did not reach expected fault/model boundary; injected=%t calls=%d want=%d err=%v", hit.Load(), dispatch.Load(), tc.calls, e)
			}
			if tc.success {
				if e != nil || string(got.Output) != string(out) {
					t.Fatalf("exact version lost-response reconciliation failed: %v", e)
				}
			} else if e == nil || len(got.Output) != 0 {
				t.Fatalf("failure returned a successful or leaking result: %v", e)
			}
			f.Release()
			if _, err := rec.Backend.PutObject(ctx, req.TenantID, []byte("must not persist under stale fence")); !errors.Is(err, ErrFenceLost) {
				t.Fatalf("stale owner wrote or returned the wrong failure: %v", err)
			}
			options.Store = s3
			options.Fence = acquire()
			clean := makeRecorder(options)
			if tc.recover {
				var recoveringTurn string
				if tc.name == "finalization" {
					open, err := clean.Backend.OpenTurns(ctx, time.Time{})
					if err != nil || len(open) != 1 || open[0].TenantID != req.TenantID {
						t.Fatalf("finalization did not leave one open retained turn: %v (%d)", err, len(open))
					}
					recoveringTurn = open[0].TurnID
					before, err := clean.Backend.Load(ctx, req.TenantID, recoveringTurn)
					if err != nil || len(before) == 0 || isTerminal(str(before[len(before)-1], "type")) || last(before, "response_released") < 0 {
						t.Fatalf("expected committed release authorization but no terminal event: %v", err)
					}
				}
				n, e := clean.Recover(ctx, time.Time{})
				if e != nil {
					t.Fatalf("successor recovery: %v", e)
				}
				if tc.name == "lost_admission_response" || tc.name == "pg_commit_after_admission" || tc.name == "outage_during_model" {
					if n != 1 {
						t.Fatalf("expected an open committed turn, recovered %d", n)
					}
				}
				if tc.name == "finalization" {
					// A recovery-completed turn had already committed its release
					// authorization before the terminal append failed. The initial
					// request still received nothing. A later request can only
					// deliver that same output after its own fresh authorization.
					if n != 1 || dispatch.Load() != 1 {
						t.Fatalf("recovery count=%d provider calls=%d; want 1 each", n, dispatch.Load())
					}
					retained := clean.Backend.(*RetentionBackend)
					events, err := retained.Load(ctx, req.TenantID, recoveringTurn)
					if err != nil || len(events) == 0 || str(events[len(events)-1], "type") != TypeTurnCompleted {
						t.Fatalf("recovery did not complete the retained turn: %v", err)
					}
					objects, err := retained.LoadRetainedObjects(ctx, req.TenantID, recoveringTurn, events)
					if err != nil {
						t.Fatalf("recovery exact-version objects: %v", err)
					}
					if errs := VerifyRetentionFull(events, objects); len(errs) != 0 || string(objects[SHA256(out)]) != string(out) {
						t.Fatalf("recovery retained evidence did not verify: %v", errs)
					}
					revoked := errors.New("fixture membership revoked")
					for _, replay := range []struct {
						name string
						want error
						stop bool
					}{
						{"denied", ErrDenied, false},
						{"revoked", revoked, false},
						{"cancelled_at_delivery", context.Canceled, true},
						{"expired_at_delivery", context.DeadlineExceeded, false},
						{"authorized", nil, false},
					} {
						t.Run(replay.name, func(t *testing.T) {
							replayCtx, cancel := context.WithCancel(ctx)
							defer cancel()
							checks := 0
							result, err := clean.Process(replayCtx, req, model, func(context.Context) error {
								checks++
								if replay.stop {
									cancel()
									return nil
								}
								return replay.want
							})
							if checks != 1 || dispatch.Load() != 1 || !errors.Is(err, replay.want) {
								t.Fatalf("delivery-only replay: calls=%d gates=%d err=%v", dispatch.Load(), checks, err)
							}
							if replay.want != nil && (len(result.Output) != 0 || result.Replayed) {
								t.Fatal("unauthorized replay released output")
							}
							if replay.want == nil && (!result.Replayed || result.TurnID != recoveringTurn || string(result.Output) != string(out)) {
								t.Fatal("authorized replay did not return the exact retained output")
							}
						})
					}
					if err := retained.VerifyRetainedTurn(ctx, req.TenantID, recoveringTurn, events); err != nil {
						t.Fatalf("replay changed or invalidated retained evidence: %v", err)
					}
					return
				}
				result, e := clean.Process(ctx, req, model, nil)
				if e == nil || len(result.Output) != 0 || dispatch.Load() != tc.calls {
					t.Fatalf("recovery redispatched or leaked output: calls=%d err=%v", dispatch.Load(), e)
				}
				if tc.name == "outage_during_model" {
					var it *InterruptedError
					if !errors.As(e, &it) || it.Disclosure != "unknown" {
						t.Fatalf("ambiguous work was not kept unknown: %v", e)
					}
				}
			}
		})
	}
}
