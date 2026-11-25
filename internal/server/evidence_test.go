package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// post sends a model call with a JSON body and optional headers as `user`.
func (e *env) post(user, pid, body string, hdr ...string) (int, string, string) {
	e.t.Helper()
	tok := e.idp.Token("sub-" + user)
	req := httptest.NewRequest("POST", "/v1/projects/"+pid+"/model-calls", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), tok
}

func (e *env) turns() []string {
	e.t.Helper()
	rows, err := e.st.DB.Query(context.Background(), `SELECT turn_id::text FROM evidence_turns ORDER BY admitted_at`)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	return ids
}

func (e *env) verify(turn string) []evidence.Event {
	e.t.Helper()
	pg := evidence.PG{DB: e.st.DB}
	evs, err := pg.Load(context.Background(), e.tenant, turn)
	if err != nil {
		e.t.Fatal(err)
	}
	objs := map[string][]byte{}
	rows, _ := e.st.DB.Query(context.Background(), `SELECT sha256, bytes FROM evidence_objects WHERE tenant_id=$1`, e.tenant)
	for rows.Next() {
		var h string
		var b []byte
		_ = rows.Scan(&h, &b)
		objs[h] = b
	}
	rows.Close()
	if errs := evidence.Verify(evs, objs); len(errs) != 0 {
		e.t.Fatalf("evidence does not verify: %v", errs)
	}
	return evs
}

func TestModelCallRecordsVerifiableEvidenceWithExactInputs(t *testing.T) {
	e := newEnv(t)
	var sent []byte
	e.auth.Model = func(_ context.Context, b []byte) (evidence.ModelOutcome, error) {
		sent = b
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("synthetic answer")}, nil
	}
	code, body, _ := e.post("alice", e.p1, `{"input":"summarize the memo","artifact_ids":["`+e.a1+`"]}`, "Idempotency-Key", "call-1")
	if code != 200 || !strings.Contains(body, "synthetic answer") {
		t.Fatalf("%d %s", code, body)
	}
	ids := e.turns()
	if len(ids) != 1 {
		t.Fatalf("turns: %v", ids)
	}
	evs := e.verify(ids[0])
	first := evs[0]
	var matter string
	_ = e.st.DB.QueryRow(context.Background(), `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&matter)
	if first["tenant_id"] != e.tenant || first["project_id"] != e.p1 || first["matter_id"] != matter ||
		first["actor"].(map[string]any)["id"] != e.users["alice"] {
		t.Fatalf("tenant/project/matter/custodian not recorded: %v", first)
	}
	pg := evidence.PG{DB: e.st.DB}
	sealed := evs[3]["payload"].(map[string]any)
	stored, err := pg.Object(context.Background(), e.tenant, sealed["request_sha256"].(string))
	if err != nil || string(stored) != string(sent) {
		t.Fatalf("stored request differs from bytes sent: %v", err)
	}
	if !strings.Contains(string(sent), "summarize the memo") || !strings.Contains(string(sent), "needle-one alpha") {
		t.Fatalf("sent request lacks input or retrieved excerpt: %s", sent)
	}
	if d := evs[1]["payload"].(map[string]any)["destination"].(map[string]any); d["model_id"] != "stub-model-0" {
		t.Fatalf("destination: %v", d)
	}
	src := sealed["sources"].([]any)[0].(map[string]any)
	if src["source_id"] != e.a1 || src["sha256"] != evidence.SHA256([]byte("needle-one alpha")) {
		t.Fatalf("source reference: %v", src)
	}

	// Replay: same key, no second model call, stored output returned.
	e.auth.Model = func(context.Context, []byte) (evidence.ModelOutcome, error) {
		t.Error("model re-dispatched on idempotent replay")
		return evidence.ModelOutcome{}, errors.New("must not be called")
	}
	code, body, _ = e.post("alice", e.p1, `{"input":"summarize the memo","artifact_ids":["`+e.a1+`"]}`, "Idempotency-Key", "call-1")
	if code != 200 || !strings.Contains(body, `"replayed":true`) || !strings.Contains(body, "synthetic answer") {
		t.Fatalf("replay: %d %s", code, body)
	}
	if code, _, _ := e.post("alice", e.p1, `{"input":"different"}`, "Idempotency-Key", "call-1"); code != http.StatusUnprocessableEntity {
		t.Fatalf("key reuse with different input: %d", code)
	}
	if len(e.turns()) != 1 {
		t.Fatal("replay created a turn")
	}
}

// Bearer tokens, auth headers and other incidental request metadata must not
// reach evidence rows, objects or logs.
func TestCredentialsNeverReachEvidenceOrLogs(t *testing.T) {
	e := newEnv(t)
	var mu sync.Mutex
	var logs []string
	e.auth.Logf = func(f string, a ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(f, a...))
		mu.Unlock()
	}
	code, _, tok := e.post("alice", e.p1, `{"input":"hello"}`, "Idempotency-Key", "k", "X-Forwarded-For", "203.0.113.9",
		"User-Agent", "telemetry-agent/9.9", "Cookie", "session=abcd1234")
	if code != 200 {
		t.Fatal(code)
	}
	var dump strings.Builder
	rows, _ := e.st.DB.Query(context.Background(), `SELECT body FROM evidence_events UNION ALL SELECT convert_from(bytes,'UTF8') FROM evidence_objects UNION ALL SELECT idempotency_key FROM evidence_turns`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		dump.WriteString(s + "\n")
	}
	rows.Close()
	mu.Lock()
	dump.WriteString(strings.Join(logs, "\n"))
	mu.Unlock()
	for _, secret := range []string{tok, "Bearer", "Authorization", "203.0.113.9", "telemetry-agent", "abcd1234"} {
		if strings.Contains(dump.String(), secret) {
			t.Errorf("%q leaked into evidence or logs", secret)
		}
	}
}

func TestModelCallFailsClosedWithoutEvidence(t *testing.T) {
	t.Run("no recorder configured", func(t *testing.T) {
		e := newEnv(t)
		e.auth.Evidence = nil
		called := false
		e.auth.Work = func(context.Context, store.Principal, string) (string, error) { called = true; return sensitive, nil }
		code, body := e.modelCall("alice", context.Background())
		if code != http.StatusServiceUnavailable || called || strings.Contains(body, sensitive) {
			t.Fatalf("code=%d called=%v body=%s", code, called, body)
		}
	})
	t.Run("evidence store down at admission", func(t *testing.T) {
		e := newEnv(t)
		e.auth.Evidence.Backend = brokenBackend{Backend: evidence.PG{DB: e.st.DB}, failOn: map[string]bool{"admit": true}}
		called := false
		e.auth.Work = func(context.Context, store.Principal, string) (string, error) { called = true; return sensitive, nil }
		code, body := e.modelCall("alice", context.Background())
		if code != http.StatusServiceUnavailable || called || strings.Contains(body, sensitive) {
			t.Fatalf("code=%d called=%v body=%s", code, called, body)
		}
	})
	t.Run("evidence store fails recording the output: not released", func(t *testing.T) {
		e := newEnv(t)
		e.auth.Evidence.Backend = brokenBackend{Backend: evidence.PG{DB: e.st.DB}, failOn: map[string]bool{"output_recorded": true}}
		calls := 0
		e.auth.Work = func(context.Context, store.Principal, string) (string, error) { calls++; return sensitive, nil }
		code, body := e.modelCall("alice", context.Background())
		if code != http.StatusServiceUnavailable || calls != 1 || strings.Contains(body, sensitive) {
			t.Fatalf("code=%d calls=%d body=%s", code, calls, body)
		}
		// The disclosure that did happen is on record after recovery.
		e.auth.Evidence.Backend = evidence.PG{DB: e.st.DB}
		if _, err := e.auth.Evidence.Recover(context.Background(), farFuture()); err != nil {
			t.Fatal(err)
		}
		evs := e.verify(e.turns()[0])
		if evidence.DeriveDisclosure(evs) != "disclosed" || evs[len(evs)-1]["type"] != "turn_interrupted" {
			t.Fatalf("log after recovery: %v", evs[len(evs)-1])
		}
	})
}

// Evidence and the workspace are separate: input text is not searchable
// through the workspace index, and workspace deletion cannot change evidence.
func TestEvidenceIsSeparateFromWorkspaceSearchAndDeletion(t *testing.T) {
	e := newEnv(t)
	if code, _, _ := e.post("alice", e.p1, `{"input":"zxqv-unique-input","artifact_ids":["`+e.a1+`"]}`); code != 200 {
		t.Fatal(code)
	}
	if body := e.want("alice", "GET", "/v1/search?q=zxqv-unique-input", 200); strings.Contains(body, "zxqv") || strings.TrimSpace(body) != "[]" {
		t.Fatalf("evidence leaked into workspace search: %s", body)
	}
	turn := e.turns()[0]
	if _, err := e.st.DB.Exec(context.Background(), `DELETE FROM artifacts`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.DB.Exec(context.Background(), `DELETE FROM project_members`); err != nil {
		t.Fatal(err)
	}
	e.verify(turn) // still complete and verifiable
}

func TestModelCallRefusesOtherProjectsArtifactAndAdmitsNothing(t *testing.T) {
	e := newEnv(t)
	called := false
	e.auth.Model = func(context.Context, []byte) (evidence.ModelOutcome, error) {
		called = true
		return evidence.ModelOutcome{}, nil
	}
	if code, _, _ := e.post("alice", e.p1, `{"input":"x","artifact_ids":["`+e.a2+`"]}`); code != 404 {
		t.Fatalf("foreign artifact: %d", code)
	}
	if code, _, _ := e.post("alice", e.p1, `{"input":"x","bogus":1}`); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
	if code, _, _ := e.post("alice", e.p1, `{"input":"x"}`, "Idempotency-Key", "bad key!"); code != 400 {
		t.Fatalf("bad key: %d", code)
	}
	if called || len(e.turns()) != 0 {
		t.Fatalf("called=%v turns=%v", called, e.turns())
	}
}

// brokenBackend fails the named writes: "admit", or an event type for Append.
type brokenBackend struct {
	evidence.Backend
	failOn map[string]bool
}

var errBroken = errors.New("evidence store unavailable")

func (b brokenBackend) Admit(ctx context.Context, a evidence.Admission, e evidence.Event, o [][]byte) (evidence.AdmitResult, error) {
	if b.failOn["admit"] {
		return evidence.AdmitResult{}, errBroken
	}
	return b.Backend.Admit(ctx, a, e, o)
}

func (b brokenBackend) Append(ctx context.Context, e evidence.Event) (evidence.Receipt, error) {
	if b.failOn[e["type"].(string)] {
		return evidence.Receipt{}, errBroken
	}
	return b.Backend.Append(ctx, e)
}

func farFuture() time.Time { return time.Now().Add(time.Hour) }
