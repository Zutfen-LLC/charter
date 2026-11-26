package server

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/Zutfen-LLC/charter/internal/testdb"
)

// runtimeEnv serves the real API on the two restricted login credentials a
// deployment would use; seeding and assertions still use the owner pool.
func runtimeEnv(t *testing.T) (*env, testdb.Creds) {
	t.Helper()
	e := newEnv(t)
	c := testdb.Runtime(t, e.st.DB)
	e.auth.Store = &store.Store{DB: c.Workspace}
	e.auth.Evidence = &evidence.Recorder{Backend: evidence.PG{DB: c.Evidence}, Policy: StubPolicy()}
	e.h = New(c.Workspace, PostgresEvidenceBackend(), WithAuth(e.auth))
	return e, c
}

// Authenticated end-to-end calls under the restricted credentials: reads,
// project isolation, tenant administration (writes), model call with evidence,
// replay and the release gate all work with nothing but the serving logins.
func TestAuthenticatedServerWorksUnderRestrictedCredentials(t *testing.T) {
	e, c := runtimeEnv(t)
	e.want("alice", "GET", "/v1/projects", 200)
	e.want("alice", "GET", "/v1/artifacts/"+e.a1, 200)
	e.want("alice", "GET", "/v1/artifacts/"+e.a2, 404) // isolation still holds
	e.want("alice", "GET", "/v1/search?q=needle", 200)
	// administration writes through the workspace login (members, roles, audit)
	e.want("carol", "PUT", "/v1/projects/"+e.p1+"/members/"+e.users["bob"], 204)
	e.want("carol", "PUT", "/v1/users/"+e.users["frank"]+"/roles/records_officer", 204)
	e.want("carol", "DELETE", "/v1/projects/"+e.p1+"/members/"+e.users["bob"], 204)

	code, body, _ := e.post("alice", e.p1, `{"input":"hello","artifact_ids":["`+e.a1+`"]}`, "Idempotency-Key", "k1")
	if code != 200 || !strings.Contains(body, "stub response") {
		t.Fatalf("model call: %d %s", code, body)
	}
	code, body, _ = e.post("alice", e.p1, `{"input":"hello","artifact_ids":["`+e.a1+`"]}`, "Idempotency-Key", "k1")
	if code != 200 || !strings.Contains(body, `"replayed":true`) {
		t.Fatalf("replay: %d %s", code, body)
	}
	e.verify(e.turns()[0])
	if code, _, _ := e.post("bob", e.p1, `{"input":"x"}`); code != http.StatusNotFound {
		t.Fatalf("non-member model call: %d", code)
	}

	// Neither serving credential can touch evidence beyond its role, whatever
	// the application does.
	ctx := context.Background()
	for _, p := range []struct {
		name string
		do   func() error
	}{
		{"workspace login reads evidence", func() error { _, err := c.Workspace.Exec(ctx, `SELECT 1 FROM evidence_events`); return err }},
		{"workspace login deletes evidence", func() error { _, err := c.Workspace.Exec(ctx, `DELETE FROM evidence_events`); return err }},
		{"evidence login updates evidence", func() error { _, err := c.Evidence.Exec(ctx, `UPDATE evidence_events SET body='x'`); return err }},
		{"evidence login deletes evidence", func() error { _, err := c.Evidence.Exec(ctx, `DELETE FROM evidence_objects`); return err }},
		{"evidence login truncates", func() error { _, err := c.Evidence.Exec(ctx, `TRUNCATE evidence_turns CASCADE`); return err }},
		{"evidence login drops the guard", func() error {
			_, err := c.Evidence.Exec(ctx, `DROP TRIGGER evidence_events_rowguard ON evidence_events`)
			return err
		}},
		{"evidence login assumes the owner", func() error { _, err := c.Evidence.Exec(ctx, `SET ROLE charter`); return err }},
	} {
		if err := p.do(); err == nil {
			t.Errorf("%s succeeded", p.name)
		}
	}
}

// The unsafe-credential rejection also applies to what the server is wired to:
// running the same call on an owner pool is detectably unsafe before serving.
func TestRuntimeEnvPoolsPassStartupChecks(t *testing.T) {
	_, c := runtimeEnv(t)
	if err := evidence.CheckWorkspaceRuntime(context.Background(), c.Workspace); err != nil {
		t.Fatal(err)
	}
	if err := evidence.CheckEvidenceRuntime(context.Background(), c.Evidence); err != nil {
		t.Fatal(err)
	}
}
