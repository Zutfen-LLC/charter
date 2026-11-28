package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/oidc"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

// c08LifecycleProbe keeps HTTP lifecycle transitions in a synthetic backend;
// identities, roles, role grants and the scoped_exports lifecycle row remain
// PostgreSQL-backed through newEnv and records.Store.
type c08LifecycleProbe struct {
	e              *env
	calls          map[string]int
	denials        int
	deny           bool
	requester      string
	requesterGrant time.Time
}

func (p *c08LifecycleProbe) AuditDenial(context.Context, store.Principal, string, string, int) error {
	p.denials++
	return nil
}
func (p *c08LifecycleProbe) Request(_ context.Context, actor store.Principal, req records.NewExportRequest) (records.ExportSummary, error) {
	p.calls["request"]++
	if p.deny || req.Intent.ProjectID != p.e.p1 || req.Intent.MatterID == "foreign-matter" || containsID(req.Intent.CustodianIDs, p.e.users["bob"]) || !req.Intent.WindowStart.Before(time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)) {
		return records.ExportSummary{}, store.ErrNotFound
	}
	p.requester = actor.UserID
	if err := p.e.st.DB.QueryRow(context.Background(), `SELECT granted_at FROM tenant_roles WHERE tenant_id=$1 AND user_id=$2 AND role=$3`, actor.TenantID, actor.UserID, store.RoleRecordsOfficer).Scan(&p.requesterGrant); err != nil {
		return records.ExportSummary{}, err
	}
	return records.ExportSummary{ID: "11111111-1111-4111-8111-111111111111", State: records.ExportRequested, SnapshotDigest: strings.Repeat("a", 64)}, nil
}
func (p *c08LifecycleProbe) Approve(_ context.Context, actor store.Principal, id, digest string) (records.ExportSummary, error) {
	p.calls["approve"]++
	if p.deny || actor.UserID == p.requester {
		return records.ExportSummary{}, records.ErrExportConflict
	}
	var activeGrant time.Time
	if err := p.e.st.DB.QueryRow(context.Background(), `SELECT granted_at FROM tenant_roles WHERE tenant_id=$1 AND user_id=$2 AND role=$3`, actor.TenantID, p.requester, store.RoleRecordsOfficer).Scan(&activeGrant); err != nil || !activeGrant.Equal(p.requesterGrant) {
		return records.ExportSummary{}, store.ErrForbidden
	}
	return records.ExportSummary{ID: id, State: records.ExportApproved, SnapshotDigest: digest}, nil
}
func (p *c08LifecycleProbe) Generate(ctx context.Context, _ store.Principal, id string) (records.ExportSummary, error) {
	p.calls["generate"]++
	if p.deny {
		return records.ExportSummary{}, store.ErrForbidden
	}
	_, err := p.e.st.DB.Exec(ctx, `UPDATE scoped_exports SET state='generating',attempt_token=gen_random_uuid(),lease_until=now()+interval '1 minute' WHERE id=$1 AND state='approved'`, id)
	if err == nil {
		_, err = p.e.st.DB.Exec(ctx, `UPDATE scoped_exports SET state='ready',attempt_token=NULL,lease_until=NULL,package_bytes='synthetic package bytes',manifest_digest=$2,expires_at=now()+interval '1 day' WHERE id=$1 AND state='generating'`, id, strings.Repeat("b", 64))
	}
	if err != nil {
		return records.ExportSummary{}, err
	}
	return records.ExportSummary{ID: id, State: records.ExportReady, SnapshotDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64)}, nil
}
func (p *c08LifecycleProbe) Retrieve(_ context.Context, actor store.Principal, id string) (ExportDelivery, error) {
	p.calls["retrieve"]++
	if p.deny {
		return ExportDelivery{}, store.ErrForbidden
	}
	if actor.TenantID != p.e.tenant {
		return ExportDelivery{}, store.ErrNotFound
	}
	var state string
	var expires *time.Time
	err := p.e.st.DB.QueryRow(context.Background(), `SELECT state,expires_at FROM scoped_exports WHERE id=$1`, id).Scan(&state, &expires)
	if err != nil || state != records.ExportReady || expires == nil || !time.Now().Before(*expires) {
		return ExportDelivery{}, store.ErrNotFound
	}
	return ExportDelivery{DirectoryJSON: []byte(`{"synthetic":"protected package bytes"}`), ManifestDigest: "sha256:" + strings.Repeat("b", 64)}, nil
}
func (p *c08LifecycleProbe) Cancel(ctx context.Context, actor store.Principal, id string) error {
	p.calls["cancel"]++
	_, err := p.e.st.DB.Exec(ctx, `UPDATE scoped_exports SET state='cancelled',package_bytes=NULL,expires_at=NULL WHERE tenant_id=$1 AND id=$2 AND requester_id=$3`, actor.TenantID, id, actor.UserID)
	return err
}

func containsID(ids []string, target string) bool {
	for _, id := range ids {
		if id == target {
			return true
		}
	}
	return false
}

func TestC08HTTPExportLifecycleAuthorizationMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.SeedRole(ctx, e.tenant, e.users["dave"], store.RoleExportReviewer); err != nil {
		t.Fatal(err)
	}
	probe := &c08LifecycleProbe{e: e, calls: map[string]int{}}
	e.auth.Exports = probe
	e.h = New(e.st.DB, TestFixtureBackend(), WithAuth(e.auth))

	var matter string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	intent := `{"project_id":"` + e.p1 + `","matter_id":"` + matter + `","custodian_ids":["` + e.users["alice"] + `"],"window_start":"2026-01-01T00:00:00Z","window_end":"2026-01-03T00:00:00Z","reason":"synthetic lifecycle"}`
	request := func(user, key, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/exports", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-"+user))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	denyNoLeak := func(rec *httptest.ResponseRecorder, want int) {
		t.Helper()
		if rec.Code != want {
			t.Fatalf("status=%d want=%d body=%q", rec.Code, want, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "protected package bytes") || strings.Contains(rec.Body.String(), "synthetic") || rec.Header().Get("Charter-Manifest-Digest") != "" || rec.Header().Get("Content-Disposition") != "" {
			t.Fatalf("denial exposed protected content/metadata: headers=%v body=%q", rec.Header(), rec.Body.String())
		}
	}
	get := func(user, id string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/exports/"+id+"/package", nil)
		req.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-"+user))
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}

	// Combined-role requester is permitted to request, but separation of duties
	// refuses self-approval. The same user may approve another user's request.
	r := request("dave", "lifecycle-self", intent)
	if r.Code != http.StatusOK {
		t.Fatalf("combined requester status=%d %q", r.Code, r.Body.String())
	}
	id := "11111111-1111-4111-8111-111111111111"
	self := httptest.NewRequest(http.MethodPost, "/v1/exports/"+id+"/approve", strings.NewReader(`{"snapshot_digest":"`+strings.Repeat("a", 64)+`"}`))
	self.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-dave"))
	self.Header.Set("Content-Type", "application/json")
	selfRec := httptest.NewRecorder()
	e.h.ServeHTTP(selfRec, self)
	denyNoLeak(selfRec, http.StatusConflict)
	if !strings.Contains(selfRec.Body.String(), `"error":"export conflict"`) {
		t.Fatalf("unexpected self-approval refusal: %q", selfRec.Body.String())
	}
	approval := func() *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/exports/"+id+"/approve", strings.NewReader(`{"snapshot_digest":"`+strings.Repeat("a", 64)+`"}`))
		req.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-erin"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		return rec
	}
	if _, err := e.st.DB.Exec(ctx, `DELETE FROM tenant_roles WHERE tenant_id=$1 AND user_id=$2 AND role=$3`, e.tenant, e.users["dave"], store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	denyNoLeak(approval(), http.StatusForbidden)
	if err := e.st.SeedRole(ctx, e.tenant, e.users["dave"], store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	denyNoLeak(approval(), http.StatusForbidden) // stale request remains stale after regrant
	if err := e.st.SeedRole(ctx, e.tenant, e.users["alice"], store.RoleRecordsOfficer); err != nil {
		t.Fatal(err)
	}
	if rec := request("alice", "combined-approves-other", intent); rec.Code != http.StatusOK {
		t.Fatalf("other request status=%d body=%q", rec.Code, rec.Body.String())
	}
	approveOther := httptest.NewRequest(http.MethodPost, "/v1/exports/"+id+"/approve", strings.NewReader(`{"snapshot_digest":"`+strings.Repeat("a", 64)+`"}`))
	approveOther.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-dave"))
	approveOther.Header.Set("Content-Type", "application/json")
	approveOtherRec := httptest.NewRecorder()
	e.h.ServeHTTP(approveOtherRec, approveOther)
	if approveOtherRec.Code != http.StatusOK {
		t.Fatalf("combined role could not approve another request: %d %q", approveOtherRec.Code, approveOtherRec.Body.String())
	}

	// Other-tenant reviewer reaches the production route but cannot discover an
	// export ID; response is 404 without package or manifest metadata.
	if err := e.st.SeedRole(ctx, e.otherTen, e.users["zed"], store.RoleExportReviewer); err != nil {
		t.Fatal(err)
	}
	otherIDP := e.idp.Mint(syntheticidp.Claims{Subject: "sub-zed", Tenant: "tenant-b"})
	otherVerifier, err := oidc.NewVerifier(oidc.Config{Issuer: e.idp.Issuer, Audience: audience, TenantID: "tenant-b", RequiredScope: e.idp.Scope,
		Keys: &oidc.JWKSFetcher{URL: e.idp.JWKSURL(), AllowLoopbackHTTP: true}})
	if err != nil {
		t.Fatal(err)
	}
	oldVerifier := e.auth.Verifier
	e.auth.Verifier = otherVerifier
	cross := httptest.NewRequest(http.MethodGet, "/v1/exports/"+id+"/package", nil)
	cross.Header.Set("Authorization", "Bearer "+otherIDP)
	crossRec := httptest.NewRecorder()
	e.h.ServeHTTP(crossRec, cross)
	e.auth.Verifier = oldVerifier
	denyNoLeak(crossRec, http.StatusNotFound)

	// Foreign project, matter, custodian, and a half-open start excluding the
	// fixture boundary are refused before a snapshot can be requested.
	before := probe.calls["request"]
	for name, bad := range map[string]string{
		"project":   strings.Replace(intent, e.p1, e.p2, 1),
		"matter":    strings.Replace(intent, matter, "foreign-matter", 1),
		"custodian": strings.Replace(intent, e.users["alice"], e.users["bob"], 1),
		"half-open": strings.Replace(intent, `"2026-01-01T00:00:00Z"`, `"2026-01-02T00:00:00Z"`, 1),
	} {
		rec := request("dave", "bad-"+name, bad)
		denyNoLeak(rec, http.StatusNotFound)
	}
	if probe.calls["request"] != before+4 {
		t.Fatalf("selection probe calls=%d want=%d", probe.calls["request"], before+4)
	}

	// Expiry and cancellation are persisted PostgreSQL state transitions; HTTP
	// retrieval rejects both before returning package bytes or manifest headers.
	for index, mode := range []string{"expired", "cancelled"} {
		id := []string{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333"}[index]
		_, err := e.st.DB.Exec(ctx, `INSERT INTO scoped_exports(id,tenant_id,request_key,project_id,matter_id,requester_id,request_bytes,request_digest,custodian_ids,window_start,window_end,reason,snapshot_bytes,snapshot_digest,requester_role,requester_grant_at,state,approver_id,approver_role,approved_at,approver_grant_at,package_bytes,manifest_digest,expires_at) VALUES($1,$2,$3,$4,$5,$6,'{}','`+strings.Repeat("c", 64)+`',ARRAY[$7]::uuid[],now()-interval '1 day',now()+interval '1 day','synthetic','{}','`+strings.Repeat("a", 64)+`','records_officer',(SELECT granted_at FROM tenant_roles WHERE tenant_id=$2 AND user_id=$6 AND role='records_officer'),'approved',$8,'export_reviewer',now(),(SELECT granted_at FROM tenant_roles WHERE tenant_id=$2 AND user_id=$8 AND role='export_reviewer'),NULL,NULL,now()+interval '1 day')`, id, e.tenant, mode, e.p1, matter, e.users["dave"], e.users["alice"], e.users["erin"])
		if err != nil {
			t.Fatal(err)
		}
		generate := httptest.NewRequest(http.MethodPost, "/v1/exports/"+id+"/generate", nil)
		generate.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-dave"))
		generated := httptest.NewRecorder()
		e.h.ServeHTTP(generated, generate)
		if generated.Code != http.StatusOK {
			t.Fatalf("generate %s status=%d body=%q", mode, generated.Code, generated.Body.String())
		}
		if mode == "expired" {
			_, err = e.st.DB.Exec(ctx, `UPDATE scoped_exports SET expires_at=now()-interval '1 second' WHERE id=$1`, id)
		} else {
			cancel := httptest.NewRequest(http.MethodPost, "/v1/exports/"+id+"/cancel", nil)
			cancel.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-dave"))
			cancelled := httptest.NewRecorder()
			e.h.ServeHTTP(cancelled, cancel)
			if cancelled.Code != http.StatusNoContent {
				t.Fatalf("cancel status=%d body=%q", cancelled.Code, cancelled.Body.String())
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		rec := get("erin", id)
		denyNoLeak(rec, http.StatusNotFound)
	}

	// A closed PostgreSQL pool makes principal resolution fail in production
	// authenticate() (Resolve errors map to 503). Closing it is the exact outage
	// mechanism; authentication precedes export middleware, so no export audit
	// callback is required or expected and no backend method may run.
	calls := probe.calls["retrieve"]
	e.st.DB.Close()
	outage := get("erin", id)
	denyNoLeak(outage, http.StatusServiceUnavailable)
	if probe.calls["retrieve"] != calls {
		t.Fatal("authorization outage reached export package backend")
	}

	if probe.denials < 1 {
		t.Fatal("route-level denials were not audited")
	}
}
