package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5"
)

const sensitive = "SENSITIVE-MODEL-OUTPUT"

func (e *env) modelCall(user string, ctx context.Context) (int, string) {
	e.t.Helper()
	req := httptest.NewRequest("POST", "/v1/projects/"+e.p1+"/model-calls", nil).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-"+user))
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func TestModelCallOutputRejectedAfterWorkDeadline(t *testing.T) {
	e := newEnv(t)
	e.auth.WorkTimeout = 30 * time.Millisecond
	e.auth.Work = func(ctx context.Context, _ store.Principal, _ string) (string, error) {
		<-ctx.Done() // adapter ignores the deadline's meaning and returns "success" anyway
		return sensitive, nil
	}
	code, body := e.modelCall("alice", context.Background())
	if code != http.StatusGatewayTimeout || strings.Contains(body, sensitive) {
		t.Fatalf("late output released: %d %s", code, body)
	}
}

func TestModelCallOutputRejectedAfterRequestCancellation(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e.auth.Work = func(c context.Context, _ store.Principal, _ string) (string, error) {
		cancel()
		<-c.Done()
		return sensitive, nil
	}
	code, body := e.modelCall("alice", ctx)
	if code == 200 || strings.Contains(body, sensitive) {
		t.Fatalf("output released after cancellation: %d %s", code, body)
	}
}

func TestModelCallOutputRejectedWhenAccountDisabledDuringWork(t *testing.T) {
	e := newEnv(t)
	e.auth.Work = func(ctx context.Context, p store.Principal, _ string) (string, error) {
		if _, err := e.st.DB.Exec(ctx, `UPDATE users SET disabled_at=now() WHERE id=$1`, p.UserID); err != nil {
			t.Error(err)
		}
		return sensitive, nil
	}
	code, body := e.modelCall("alice", context.Background())
	if code != http.StatusForbidden || strings.Contains(body, sensitive) {
		t.Fatalf("%d %s", code, body)
	}
}

func TestModelCallOutputRejectedWhenMembershipRevokedDuringWork(t *testing.T) {
	e := newEnv(t)
	e.auth.Work = func(ctx context.Context, p store.Principal, pid string) (string, error) {
		if _, err := e.st.DB.Exec(ctx, `DELETE FROM project_members WHERE user_id=$1 AND project_id=$2`, p.UserID, pid); err != nil {
			t.Error(err)
		}
		return sensitive, nil
	}
	code, body := e.modelCall("alice", context.Background())
	if code != http.StatusForbidden || strings.Contains(body, sensitive) {
		t.Fatalf("%d %s", code, body)
	}
}

func TestModelCallFailsClosedWhenAuthorizationDatabaseUnavailableAtRelease(t *testing.T) {
	e := newEnv(t)
	e.auth.Work = func(context.Context, store.Principal, string) (string, error) {
		e.st.DB.Close() // authorization store becomes unreachable before release
		return sensitive, nil
	}
	code, body := e.modelCall("alice", context.Background())
	if code != http.StatusServiceUnavailable || strings.Contains(body, sensitive) {
		t.Fatalf("%d %s", code, body)
	}
}

func TestModelCallWithinDeadlineIsReleased(t *testing.T) {
	e := newEnv(t)
	e.auth.Work = func(context.Context, store.Principal, string) (string, error) { return sensitive, nil }
	code, body := e.modelCall("alice", context.Background())
	if code != 200 || !strings.Contains(body, sensitive) {
		t.Fatalf("authorized in-deadline work not released: %d %s", code, body)
	}
}

// Stale/valid bearer tokens issued before an account is disabled never
// authorize subsequent reads or model calls, on any route.
func TestDisabledAccountTokenRefusedEverywhere(t *testing.T) {
	e := newEnv(t)
	tok := e.idp.Token("sub-alice")
	for _, c := range [][2]string{{"GET", "/v1/projects"}, {"GET", "/v1/search?q=needle"},
		{"GET", "/v1/projects/" + e.p1 + "/artifacts"}, {"GET", "/v1/artifacts/" + e.a1},
		{"GET", "/v1/artifacts/" + e.a1 + "/content"}, {"POST", "/v1/projects/" + e.p1 + "/model-calls"}} {
		if code, _ := e.do(c[0], c[1], tok); code != 200 {
			t.Fatalf("baseline %v: %d", c, code)
		}
	}
	e.want("carol", "POST", "/v1/users/"+e.users["alice"]+"/disable", 204)
	if n := e.countRows(`SELECT count(*) FROM project_members WHERE user_id=$1`, e.users["alice"]); n != 1 {
		t.Fatal("membership should be retained")
	}
	for _, c := range [][2]string{{"GET", "/v1/projects"}, {"GET", "/v1/search?q=needle"},
		{"GET", "/v1/projects/" + e.p1 + "/artifacts"}, {"GET", "/v1/artifacts/" + e.a1},
		{"GET", "/v1/artifacts/" + e.a1 + "/content"}, {"POST", "/v1/projects/" + e.p1 + "/model-calls"}} {
		if code, body := e.do(c[0], c[1], tok); code != 403 || strings.Contains(body, "memo") {
			t.Errorf("%v after disable: %d %s", c, code, body)
		}
	}
}

func (e *env) countRows(q string, a ...any) int {
	e.t.Helper()
	var n int
	if err := e.st.DB.QueryRow(context.Background(), q, a...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// UUID spellings over HTTP: same decisions as the canonical lowercase form.
func TestHTTPUUIDRepresentationsAreEquivalent(t *testing.T) {
	e := newEnv(t)
	up := strings.ToUpper
	e.want("alice", "GET", "/v1/artifacts/"+up(e.a1), 200)
	if b := e.want("alice", "GET", "/v1/projects/"+up(e.p1)+"/artifacts", 200); !strings.Contains(b, e.a1) {
		t.Errorf("upper-case project id lists nothing for a member: %s", b)
	}
	e.want("alice", "POST", "/v1/projects/"+up(e.p1)+"/model-calls", 200)
	e.want("alice", "GET", "/v1/artifacts/"+up(e.a2), 404)
	e.want("alice", "GET", "/v1/projects/"+up(e.p2)+"/artifacts", 404)
	// Self-grant through an upper-case user id is refused over HTTP too.
	e.want("carol", "PUT", "/v1/users/"+up(e.users["carol"])+"/roles/records_officer", 403)
	e.want("carol", "PUT", "/v1/users/"+up(e.users["carol"])+"/roles/export_reviewer", 403)
	if n := e.countRows(`SELECT count(*) FROM tenant_roles WHERE user_id=$1 AND role IN ('records_officer','export_reviewer')`, e.users["carol"]); n != 0 {
		t.Fatalf("carol self-granted %d roles", n)
	}
}

// ---- Authentication coverage independent of the wrapper's own registry -------

// The expected route table is written out by hand here, not derived from the
// code under test. A route added without updating this table, or registered
// outside Auth.route, fails.
var expectedRoutes = []string{
	"GET /v1/me", "GET /v1/projects", "GET /v1/search",
	"GET /v1/projects/{pid}/artifacts", "POST /v1/projects/{pid}/model-calls",
	"GET /v1/artifacts/{id}", "GET /v1/artifacts/{id}/content",
	"PUT /v1/projects/{pid}/members/{uid}", "DELETE /v1/projects/{pid}/members/{uid}",
	"PUT /v1/users/{uid}/roles/{role}", "DELETE /v1/users/{uid}/roles/{role}",
	"POST /v1/users/{uid}/disable",
	"POST /v1/holds", "POST /v1/holds/{id}/release", "POST /v1/exports", "POST /v1/exports/{id}/approve",
}

func TestRouteTableMatchesIndependentExpectation(t *testing.T) {
	e := newEnv(t)
	got := map[string]bool{}
	for _, r := range e.auth.routes {
		got[r] = true
	}
	for _, r := range expectedRoutes {
		if !got[r] {
			t.Errorf("expected route missing from registry: %s", r)
		}
		delete(got, r)
	}
	for r := range got {
		t.Errorf("route registered but not in the reviewed table (add authz tests): %s", r)
	}
}

func TestOnlyHealthRoutesAreRegisteredOutsideTheAuthWrapper(t *testing.T) {
	re := regexp.MustCompile(`(?m)\b(mux|http)\.(Handle|HandleFunc)\(`)
	for file, want := range map[string]int{"server.go": 2, "api.go": 1} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(re.FindAll(b, -1)); n != want {
			t.Errorf("%s: %d direct mux registrations, want %d (only /healthz, /readyz and Auth.route may register)", file, n, want)
		}
	}
}

func TestEveryDeclaredRouteRejectsUnauthenticatedAcrossMethods(t *testing.T) {
	e := newEnv(t)
	repl := strings.NewReplacer("{pid}", e.p1, "{id}", e.a1, "{uid}", e.users["alice"], "{role}", "operator")
	for _, r := range expectedRoutes {
		parts := strings.SplitN(r, " ", 2)
		path := repl.Replace(parts[1])
		for _, hdr := range [][]string{nil, {"Authorization", "Basic YWxpY2U6eA=="}, {"Authorization", "bearer " + e.idp.Token("sub-alice")}} {
			if code, _ := e.do(parts[0], path, "", hdr...); code != 401 {
				t.Errorf("%s with %v: %d, want 401", r, hdr, code)
			}
		}
		if parts[0] == "GET" { // Go's mux also routes HEAD to GET handlers
			if code, _ := e.do("HEAD", path, ""); code != 401 {
				t.Errorf("HEAD %s: %d, want 401", path, code)
			}
		}
		for _, m := range []string{"PATCH", "TRACE", "OPTIONS"} {
			if code, _ := e.do(m, path, e.idp.Token("sub-carol")); code == 200 || code == 204 || code == 501 {
				t.Errorf("%s %s reached a handler: %d", m, path, code)
			}
		}
	}
}

// The role matrix allows one person to hold several explicitly granted roles;
// each capability works independently and none implies workspace access.
func TestOnePersonMayHoldMultipleExplicitRoles(t *testing.T) {
	e := newEnv(t)
	// A second admin is needed to give carol records_officer (no self-grant).
	e.want("carol", "PUT", "/v1/users/"+e.users["alice"]+"/roles/tenant_admin", 204)
	e.want("alice", "PUT", "/v1/users/"+e.users["carol"]+"/roles/records_officer", 204)
	e.want("alice", "PUT", "/v1/users/"+e.users["carol"]+"/roles/export_reviewer", 204)
	e.want("carol", "POST", "/v1/holds", 501)                                  // records_officer
	e.want("carol", "POST", "/v1/exports/x/approve", 501)                      // export_reviewer
	e.want("carol", "PUT", "/v1/users/"+e.users["bob"]+"/roles/operator", 204) // still tenant_admin
	// Holding every role still grants no implicit workspace read.
	e.want("carol", "GET", "/v1/artifacts/"+e.a1, 404)
	e.want("carol", "GET", "/v1/projects/"+e.p1+"/artifacts", 404)
}

// ---- Round 2, finding 2: cancellation during the release-time query ----------

// serverWaitBlocked polls pg_stat_activity until n backends wait on a lock.
func (e *env) waitBlocked(n int) {
	e.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		var got int
		if err := e.st.DB.QueryRow(context.Background(), `SELECT count(*) FROM pg_stat_activity
			WHERE datname=current_database() AND wait_event_type='Lock' AND pid <> pg_backend_pid()`).Scan(&got); err != nil {
			e.t.Fatal(err)
		}
		if got >= n {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("release-time authorization query never blocked (blocked=%d)", got)
		}
		time.Sleep(time.Millisecond)
	}
}

type callResult struct {
	code int
	body string
}

// blockedRelease runs a model call whose Work takes an ACCESS EXCLUSIVE lock on
// project_members before returning sensitive output, so the handler's single
// release-time authorization query blocks on real PostgreSQL. It returns the
// work context seen by Work, a function that lets the query complete, and the
// eventual response. The query is then provably in flight when the test acts.
func (e *env) blockedRelease(reqCtx context.Context) (workCtx <-chan context.Context, unblock func(), res <-chan callResult) {
	e.t.Helper()
	wc := make(chan context.Context, 1)
	txc := make(chan pgx.Tx, 1)
	e.auth.Work = func(ctx context.Context, _ store.Principal, _ string) (string, error) {
		tx, err := e.st.DB.Begin(context.Background())
		if err != nil {
			return "", err
		}
		if _, err := tx.Exec(context.Background(), `LOCK TABLE project_members IN ACCESS EXCLUSIVE MODE`); err != nil {
			return "", err
		}
		wc <- ctx
		txc <- tx
		return sensitive, nil
	}
	out := make(chan callResult, 1)
	go func() {
		code, body := e.modelCall("alice", reqCtx)
		out <- callResult{code, body}
	}()
	tx := <-txc
	e.waitBlocked(1) // the release-time query is now waiting on the lock
	var once sync.Once
	e.t.Cleanup(func() { once.Do(func() { _ = tx.Rollback(context.Background()) }) })
	return wc, func() {
		once.Do(func() {
			if err := tx.Commit(context.Background()); err != nil {
				e.t.Error(err)
			}
		})
	}, out
}

func TestReleaseQueryHarnessReleasesWhenNothingExpires(t *testing.T) {
	e := newEnv(t)
	_, unblock, res := e.blockedRelease(context.Background())
	unblock()
	r := <-res
	if r.code != 200 || !strings.Contains(r.body, sensitive) {
		t.Fatalf("control case failed: %d %s", r.code, r.body)
	}
}

func TestOutputNotReleasedWhenRequestCancelledDuringReleaseQuery(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, unblock, res := e.blockedRelease(ctx)
	cancel()  // cancelled while the authorization query is blocked...
	unblock() // ...then the query completes successfully (user is a member)
	r := <-res
	if r.code == 200 || strings.Contains(r.body, sensitive) {
		t.Fatalf("output released after cancellation during the release query: %d %s", r.code, r.body)
	}
}

func TestOutputNotReleasedWhenDeadlineExpiresDuringReleaseQuery(t *testing.T) {
	e := newEnv(t)
	e.auth.WorkTimeout = time.Second
	wc, unblock, res := e.blockedRelease(context.Background())
	ctx := <-wc
	<-ctx.Done() // the work deadline passes while the query is blocked (event, not a sleep)
	unblock()
	r := <-res
	if r.code != http.StatusGatewayTimeout || strings.Contains(r.body, sensitive) {
		t.Fatalf("output released after deadline expiry during the release query: %d %s", r.code, r.body)
	}
}

// The release-time query is bounded: if the database cannot answer in time the
// call fails closed with no output (and the handler does not hang).
func TestReleaseQueryIsBoundedAndFailsClosed(t *testing.T) {
	e := newEnv(t)
	e.auth.ReleaseCheckTimeout = 150 * time.Millisecond
	_, unblock, res := e.blockedRelease(context.Background())
	r := <-res // returns without the lock ever being released
	unblock()
	if r.code != http.StatusServiceUnavailable || strings.Contains(r.body, sensitive) {
		t.Fatalf("slow authorization query not failed closed: %d %s", r.code, r.body)
	}
}
