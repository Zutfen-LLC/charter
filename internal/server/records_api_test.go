package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// recordsEnv extends the standard env with the C07 lifecycle service over the
// real PG evidence backend (Storage nil: no retention-enforced S3 in this
// slice, so storage-native protection is honestly unavailable and disposal is
// refused while the lifecycle, authorization and workspace-deletion semantics
// are fully exercised).
type recordsEnv struct {
	*env
	rs  *records.Store
	svc *records.Service
}

func newRecordsEnv(t *testing.T) *recordsEnv {
	e := newEnv(t)
	e.auth.Logf = func(format string, a ...any) { t.Logf(format, a...) }
	// A second records officer for separation-of-duties paths (sweep
	// requester != purge approver).
	gina, err := e.st.CreateUser(context.Background(), e.tenant, "sub-gina", "gina")
	if err != nil {
		t.Fatal(err)
	}
	e.users["gina"] = gina
	if err := e.st.SeedRole(context.Background(), e.tenant, gina, store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	rs := &records.Store{DB: e.st.DB}
	svc := &records.Service{Store: rs, Backend: e.auth.Evidence.Backend, Retained: false, Logf: func(string, ...any) {}}
	e.auth.Records = svc
	rec := e.auth.Evidence
	if rec != nil {
		rec.Lifecycle = svc
	}
	return &recordsEnv{env: e, rs: rs, svc: svc}
}

func (e *recordsEnv) postJSON(user, method, path string, body string, extra ...string) (int, map[string]any) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-"+user))
	req.Header.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(extra); i += 2 {
		req.Header.Set(extra[i], extra[i+1])
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	raw := rec.Body.String()
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			e.t.Fatalf("bad json %s: %v", raw, err)
		}
		return rec.Code, m
	}
	return rec.Code, nil
}

// Authorization matrix for the C07 lifecycle surface: records officers only;
// admins, export reviewers, operators, members and foreign tenants are all
// refused, and hold administration never leaks evidence content to them.
func TestLifecycleRoutesRequireRecordsOfficer(t *testing.T) {
	e := newRecordsEnv(t)
	for _, tc := range [][2]string{
		{"POST", "/v1/holds"}, {"GET", "/v1/holds"}, {"POST", "/v1/retention/sweep"},
		{"GET", "/v1/retention/items"}, {"POST", "/v1/retention/items/00000000-0000-0000-0000-000000000000/purge"},
	} {
		for _, user := range []string{"alice", "carol", "erin", "frank", "zed"} {
			e.want(user, tc[0], tc[1], 403)
		}
	}
	// dave is the records officer: the operations are authorized (and the
	// slice answers with real semantics, not 501).
	code, _ := e.postJSON("dave", "POST", "/v1/retention/sweep", "{}")
	if code != 200 {
		t.Fatalf("records officer sweep: %d", code)
	}
	// Unauthenticated is 401 everywhere.
	if code, _ := e.do("POST", "/v1/retention/sweep", ""); code != 401 {
		t.Fatalf("unauthenticated sweep: %d", code)
	}
}

// The full hold lifecycle over HTTP: place (idempotent), inspect, release,
// with actor, reason, scope and epochs captured in the durable record.
func TestHoldLifecycleOverHTTP(t *testing.T) {
	e := newRecordsEnv(t)
	ctx := context.Background()
	var matter string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	// An admitted turn exists in the matter (via the real recorder).
	turn := e.admitTurn("alice", e.p1, "http-hold-input")
	if turn == "" {
		t.Fatal("setup: no turn admitted")
	}
	body := fmt.Sprintf(`{"matter_id":%q,"reason":"regulatory hold","custodian_ids":[%q]}`, matter, e.users["alice"])
	code, resp := e.postJSON("dave", "POST", "/v1/holds", body, "Idempotency-Key", "http-hold-1")
	if code != 200 {
		t.Fatalf("place: %d %v", code, resp)
	}
	holdID, _ := resp["id"].(string)
	state, _ := resp["state"].(string)
	if holdID == "" || state != "effective" {
		t.Fatalf("place response: %v", resp)
	}
	// Retry with the same idempotency key: exactly the same hold.
	code, resp2 := e.postJSON("dave", "POST", "/v1/holds", body, "Idempotency-Key", "http-hold-1")
	if code != 200 || resp2["id"] != holdID {
		t.Fatalf("idempotent retry: %d %v", code, resp2)
	}
	// Other records officers can inspect; nobody else.
	e.want("gina", "GET", "/v1/holds/"+holdID, 200)
	e.want("alice", "GET", "/v1/holds/"+holdID, 403)
	e.want("carol", "GET", "/v1/holds/"+holdID, 403)
	e.want("zed", "GET", "/v1/holds/"+holdID, 403)
	// The item is held and its evidence events are readable by records
	// officers only.
	if code, _ := e.postJSON("dave", "GET", "/v1/retention/items", ""); code != 200 {
		t.Fatalf("items: %d", code)
	}
	e.want("dave", "GET", "/v1/retention/items/"+turn+"/events", 200)
	e.want("alice", "GET", "/v1/retention/items/"+turn+"/events", 403)
	// Release by a records officer with a reason.
	code, resp3 := e.postJSON("dave", "POST", "/v1/holds/"+holdID+"/release", `{"reason":"matter closed"}`)
	if code != 200 || resp3["state"] != "released" {
		t.Fatalf("release: %d %v", code, resp3)
	}
	// After release the (unheld) PG-backend item content is metadata-only.
	e.want("dave", "GET", "/v1/retention/items/"+turn+"/events", 403)
}

// admitTurn runs one governed-less synthetic turn through the real recorder
// (stub policy allow) and returns the admitted turn id.
func (e *recordsEnv) admitTurn(user, project, input string) string {
	e.t.Helper()
	ctx := context.Background()
	rec := e.auth.Evidence
	principal := e.principal(user)
	matter, err := e.st.ProjectMatter(ctx, principal, project)
	if err != nil {
		e.t.Fatalf("matter: %v", err)
	}
	res, err := rec.Process(ctx, evidence.Request{
		TenantID: principal.TenantID, ProjectID: project, MatterID: matter,
		CustodianID: principal.UserID, IdempotencyKey: "turn-" + input + "-" + time.Now().Format("150405.000000000"),
		Input: []byte(input),
	}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
		return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("synthetic output: " + input)}, nil
	}, nil)
	if err != nil {
		e.t.Fatalf("process: %v", err)
	}
	return res.TurnID
}

func (e *recordsEnv) principal(user string) store.Principal {
	e.t.Helper()
	p, err := e.st.Resolve(context.Background(), e.idp.Issuer, idpTenant, "sub-"+user)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// Deleting the visible chat (artifact) and the project removes ordinary
// workspace access while the held evidence stays intact and recoverable by
// records operations; search, listings and content lookup no longer expose
// the deleted material.
func TestWorkspaceDeletionPreservesHeldEvidence(t *testing.T) {
	e := newRecordsEnv(t)
	ctx := context.Background()
	var matter string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	// alice does work in P1 and it becomes held evidence.
	turn := e.admitTurn("alice", e.p1, "deletion-preservation")
	if turn == "" {
		t.Fatal("no turn")
	}
	body := fmt.Sprintf(`{"matter_id":%q,"reason":"hold for preservation"}`, matter)
	code, resp := e.postJSON("dave", "POST", "/v1/holds", body, "Idempotency-Key", "del-hold-1")
	if code != 200 {
		t.Fatalf("hold: %d %v", code, resp)
	}
	// Before deletion the chat is visible to the member.
	e.want("alice", "GET", "/v1/artifacts/"+e.a1, 200)
	// Delete the chat (member action).
	e.want("alice", "DELETE", "/v1/artifacts/"+e.a1, 204)
	// Ordinary access is gone; search and listings no longer expose it.
	e.want("alice", "GET", "/v1/artifacts/"+e.a1, 404)
	code, raw := e.as("alice", "GET", "/v1/search?q=needle-one")
	if code != 200 || strings.Contains(raw, "needle-one") {
		t.Fatalf("search still exposes deleted material: %d %s", code, raw)
	}
	code, raw = e.as("alice", "GET", "/v1/projects/"+e.p1+"/artifacts")
	if code != 200 || strings.Contains(raw, "P1 memo") {
		t.Fatalf("listing still exposes deleted material: %d %s", code, raw)
	}
	// A foreign member never saw it and still cannot.
	e.want("bob", "GET", "/v1/artifacts/"+e.a1, 404)
	// The evidence is untouched: the full event chain still loads and
	// verifies from the store the workspace cannot write.
	events, err := e.auth.Evidence.Backend.Load(ctx, e.tenant, turn)
	if err != nil || len(events) == 0 {
		t.Fatalf("evidence lost after chat deletion: %v (%d events)", err, len(events))
	}
	// Delete the whole project (admin action) and revoke the custodian.
	e.want("carol", "DELETE", "/v1/projects/"+e.p1, 204)
	// The member's project list no longer contains the deleted project (an
	// empty list is indistinguishable from having no membership).
	if code, raw := e.as("alice", "GET", "/v1/projects"); code != 200 || strings.Contains(raw, "P1") {
		t.Fatalf("deleted project still listed: %d %s", code, raw)
	}
	e.want("carol", "POST", "/v1/users/"+e.users["alice"]+"/disable", 204)
	// The revoked custodian cannot authenticate anymore.
	if code, _ := e.as("alice", "GET", "/v1/me"); code != 403 {
		t.Fatalf("revoked custodian still authenticated: %d", code)
	}
	// The held evidence remains: records officers still read it and the hold
	// is still effective after both deletions and the revocation.
	e.want("dave", "GET", "/v1/retention/items/"+turn+"/events", 200)
	holds, err := e.rs.ListHolds(ctx, e.principal("dave"))
	if err != nil || len(holds) != 1 || holds[0].State != records.HoldEffective {
		t.Fatalf("hold degraded after workspace deletion/revocation: %+v", holds)
	}
	// The full event chain is still independently enumerable.
	if events, err = e.auth.Evidence.Backend.Load(ctx, e.tenant, turn); err != nil || len(events) == 0 {
		t.Fatalf("evidence lost after project deletion: %v", err)
	}
}

// Disposal on the PostgreSQL backend is refused (it does not claim retention
// enforcement); the refusal is explicit rather than a simulated deletion.
func TestDisposalRefusedOnNonRetentionBackend(t *testing.T) {
	e := newRecordsEnv(t)
	ctx := context.Background()
	var matter string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p2).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	turn := e.admitTurn("bob", e.p2, "pg-backend-control")
	if turn == "" {
		t.Fatal("no turn")
	}
	// Short policy so the control is expiry-eligible, then sweep.
	if err := e.rs.SetPolicy(ctx, e.principal("dave"), 1, 0); err != nil {
		t.Fatal(err)
	}
	// The control's retention is one second: let it lapse before sweeping.
	time.Sleep(1100 * time.Millisecond)
	if code, _ := e.postJSON("dave", "POST", "/v1/retention/sweep", "{}"); code != 200 {
		t.Fatal("sweep failed")
	}
	items, err := e.rs.Items(ctx, e.principal("dave"))
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, it := range items {
		if it.TurnID == turn {
			found = it.State == records.ItemDisposalPending
		}
	}
	if !found {
		t.Fatal("control not marked disposal_pending")
	}
	// Purge approval works at the lifecycle level, but the physical delete is
	// refused by the backend that cannot enforce retention.
	e.want("gina", "POST", "/v1/retention/items/"+turn+"/purge", 409)
	// No evidence was harmed.
	if events, err := e.auth.Evidence.Backend.Load(ctx, e.tenant, turn); err != nil || len(events) == 0 {
		t.Fatalf("evidence lost: %v", err)
	}
}

// Hold administration does not grant source-excerpt or derivative-output
// access outside its scope: records content reads require a held item, and
// the workspace member never gains evidence access from a hold.
func TestHoldAdministrationGrantsNoWorkspaceContent(t *testing.T) {
	e := newRecordsEnv(t)
	ctx := context.Background()
	var matter string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	turn := e.admitTurn("alice", e.p1, "isolation-control")
	if turn == "" {
		t.Fatal("no turn")
	}
	body := fmt.Sprintf(`{"matter_id":%q,"reason":"scoped"}`, matter)
	if code, _ := e.postJSON("dave", "POST", "/v1/holds", body, "Idempotency-Key", "iso-hold-1"); code != 200 {
		t.Fatal("hold failed")
	}
	// bob (member of another project) and carol (admin) get no evidence
	// content even though a hold exists.
	e.want("bob", "GET", "/v1/retention/items/"+turn+"/events", 403)
	e.want("carol", "GET", "/v1/retention/items/"+turn+"/events", 403)
	e.want("bob", "GET", "/v1/retention/items/"+turn+"/objects/0000000000000000000000000000000000000000000000000000000000000000", 403)
	// alice cannot use the records surface at all.
	e.want("alice", "GET", "/v1/retention/items/"+turn+"/events", 403)
	// The records officer can read the held evidence (role matrix: content
	// for held matters in scope).
	e.want("dave", "GET", "/v1/retention/items/"+turn+"/events", 200)
}

// Scope changes over HTTP bump the epoch, keep the audit trail, and cannot
// move a hold to another matter.
func TestHoldScopeChangeOverHTTP(t *testing.T) {
	e := newRecordsEnv(t)
	ctx := context.Background()
	var m1, m2 string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&m1); err != nil {
		t.Fatal(err)
	}
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p2).Scan(&m2); err != nil {
		t.Fatal(err)
	}
	if m1 == m2 {
		t.Fatal("fixture: projects share a matter")
	}
	body := fmt.Sprintf(`{"matter_id":%q,"reason":"scope-change-test"}`, m1)
	code, resp := e.postJSON("dave", "POST", "/v1/holds", body, "Idempotency-Key", "scope-1")
	if code != 200 {
		t.Fatalf("place: %d", code)
	}
	holdID, _ := resp["id"].(string)
	// A scope change naming another matter is a substitution and fails closed.
	sub := fmt.Sprintf(`{"matter_id":%q,"reason":"move attempt"}`, m2)
	if code, _ := e.postJSON("dave", "PUT", "/v1/holds/"+holdID, sub); code != 404 {
		t.Fatalf("matter substitution accepted: %d", code)
	}
	// A legitimate narrowing to a custodian subset bumps the epoch.
	narrow := fmt.Sprintf(`{"custodian_ids":[%q],"reason":"narrowed to custodian"}`, e.users["alice"])
	if code, resp2 := e.postJSON("dave", "PUT", "/v1/holds/"+holdID, narrow); code != 200 {
		t.Fatalf("narrow: %d %v", code, resp2)
	}
	var epoch int64
	if err := e.st.DB.QueryRow(ctx, `SELECT e.epoch FROM matter_hold_epochs e JOIN holds h ON h.tenant_id=e.tenant_id AND h.matter_id=e.matter_id WHERE h.id=$1`, holdID).Scan(&epoch); err != nil {
		t.Fatal(err)
	}
	if epoch < 2 {
		t.Fatalf("scope change did not take a new matter epoch: %d", epoch)
	}
	var audits int
	if err := e.st.DB.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='hold.change'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 1 {
		t.Fatalf("hold.change audits = %d, want 1", audits)
	}
}
