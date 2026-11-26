package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/routing"
)

func TestC05GovernedHTTPReceiverAccountingAndReplay(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	var calls atomic.Int32
	actual := make(chan []byte, 4)
	var fail atomic.Bool
	var missing atomic.Bool
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		calls.Add(1)
		actual <- b
		if fail.Load() {
			w.WriteHeader(503)
			return
		}
		if missing.Load() {
			_, _ = io.WriteString(w, `{"output":"ok"}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"output": "ok", "usage": map[string]int{"input_bytes": len(b), "output_bytes": 2}})
	}))
	defer receiver.Close()
	b := evidence.PG{DB: e.st.DB}
	setup := func(p string, cap int64, models ...string) {
		t.Helper()
		if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: e.tenant, ProjectID: p, LocalOnly: true, AllowedModels: models, ProjectCap: cap}); err != nil {
			t.Fatal(err)
		}
	}
	setup(e.p1, 10000000, "det-a", "det-b", "local-http", "hosted-test")
	setup(e.p2, 1, "local-http")
	cfg := routing.DefaultConfig()
	cfg.Endpoint = receiver.URL
	e.auth.Evidence = &evidence.Recorder{Backend: b, Governance: routing.Governance(cfg, b, false, nil), Accounting: b.ReconcileBudget}
	e.auth.Budget = b.Summary
	e.h = New(e.st.DB, PostgresEvidenceBackend(), WithAuth(e.auth))
	post := func(user, p, key, body string, want int) string {
		t.Helper()
		status, out, _ := e.post(user, p, body, "Idempotency-Key", key)
		if status != want {
			t.Fatalf("%s got %d, want %d: %s", key, status, want, out)
		}
		return out
	}
	post("alice", e.p1, "unknown", `{"input":"synthetic","model_id":"missing-model"}`, 403)
	post("alice", e.p1, "hosted", `{"input":"synthetic","model_id":"hosted-test"}`, 403)
	post("alice", e.p1, "endpoint", `{"input":"synthetic","model_id":"local-http","endpoint":"`+receiver.URL+`"}`, 400)
	post("bob", e.p2, "cap", `{"input":"synthetic","model_id":"local-http"}`, 403)
	if calls.Load() != 0 {
		t.Fatal("blocked request reached receiver")
	}
	req := `{"input":"synthetic","model_id":"local-http"}`
	answer := post("alice", e.p1, "http", req, 200)
	var finished struct {
		TurnID string `json:"turn_id"`
	}
	if err := json.Unmarshal([]byte(answer), &finished); err != nil {
		t.Fatal(err)
	}
	sent := <-actual
	for _, ev := range e.verify(finished.TurnID) {
		p := ev["payload"].(map[string]any)
		switch ev["type"] {
		case "disclosure_intent":
			if p["endpoint_id"] != "local-loopback-"+evidence.SHA256([]byte(receiver.URL))[7:] || p["request"].(map[string]any)["sha256"] != evidence.SHA256(sent) {
				t.Fatal("wire request or endpoint was not bound")
			}
		case "usage_settled":
			if p["basis"] != "provider_reported" || p["units"].(json.Number).String() == "0" {
				t.Fatalf("wrong usage: %v", p)
			}
		}
	}
	if replay := post("alice", e.p1, "http", req, 200); !strings.Contains(replay, `"replayed":true`) {
		t.Fatal("not a delivery-only replay")
	}
	post("alice", e.p1, "http", `{"input":"synthetic","model_id":"det-b"}`, 422)
	if calls.Load() != 1 {
		t.Fatal("replay or conflict invoked receiver")
	}
	a := post("alice", e.p1, "a", `{"input":"synthetic","model_id":"det-a"}`, 200)
	d := post("alice", e.p1, "b", `{"input":"synthetic","model_id":"det-b"}`, 200)
	if !strings.Contains(a, "synthetic c04 response") || !strings.Contains(d, "synthetic alternate response") {
		t.Fatal("did not switch adapters")
	}
	fail.Store(true)
	post("alice", e.p1, "fail", req, 503)
	post("alice", e.p1, "fail", req, 409)
	if calls.Load() != 2 {
		t.Fatal("failure triggered fallback or retry")
	}
	fail.Store(false)
	missing.Store(true)
	post("alice", e.p1, "missing-usage", req, 200)
	sum, err := b.Summary(ctx, e.tenant, e.p1)
	if err != nil || sum.Outstanding != 0 || sum.Unknown == 0 || sum.Settled == 0 || len(sum.Models) != 3 {
		t.Fatalf("bad summary %+v %v", sum, err)
	}
	usage := "/v1/projects/" + e.p1 + "/usage"
	e.want("alice", "GET", usage, 404)
	e.want("frank", "GET", usage, 404)
	e.want("zed", "GET", usage, 403)
	if err := e.st.SeedMember(ctx, e.tenant, e.p1, e.users["frank"]); err != nil {
		t.Fatal(err)
	}
	if text := e.want("frank", "GET", usage, 200); strings.Contains(text, "synthetic") || !strings.Contains(text, `"models"`) {
		t.Fatal("incorrect usage projection")
	}
}

func TestC05HTTPMeasuredOverrunWithholdsOutputAndFreezes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	b := evidence.PG{DB: e.st.DB}
	if err := b.SetPolicy(ctx, evidence.BudgetPolicy{TenantID: e.tenant, ProjectID: e.p1, LocalOnly: true, ProjectCap: 10000, AllowedModels: []string{"local-http"}}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sent, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		calls.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]any{"output": "one byte too much", "usage": map[string]int{"input_bytes": len(sent), "output_bytes": len("one byte too much")}})
	}))
	defer receiver.Close()
	cfg := routing.DefaultConfig()
	cfg.Endpoint = receiver.URL
	cfg.MaxOutputBytes = int64(len("one byte too much") - 1)
	e.auth.Evidence = &evidence.Recorder{Backend: b, Governance: routing.Governance(cfg, b, false, nil), Accounting: b.ReconcileBudget}
	const body = `{"input":"synthetic","model_id":"local-http"}`
	if status, out, _ := e.post("alice", e.p1, body, "Idempotency-Key", "overrun"); status != 503 || strings.Contains(out, "one byte") {
		t.Fatalf("overrun delivered: %d %s", status, out)
	}
	s, err := b.Summary(ctx, e.tenant, e.p1)
	if err != nil || !s.Frozen || s.Outstanding != 0 || s.Settled <= 0 || s.Unknown != 0 || s.Remaining != 0 {
		t.Fatalf("overrun not accounted: %+v %v", s, err)
	}
	if status, _, _ := e.post("alice", e.p1, body, "Idempotency-Key", "after-overrun"); status != 403 || calls.Load() != 1 {
		t.Fatal("overrun did not freeze future dispatches")
	}
}
