package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/store"
)

type c08AuthProbeExports struct {
	calls   map[string]int
	denials int
}

func (p *c08AuthProbeExports) Request(_ context.Context, _ store.Principal, _ records.NewExportRequest) (records.ExportSummary, error) {
	p.calls["request"]++
	return records.ExportSummary{ID: "11111111-1111-4111-8111-111111111111", State: records.ExportRequested, SnapshotDigest: strings.Repeat("a", 64)}, nil
}
func (p *c08AuthProbeExports) Approve(_ context.Context, _ store.Principal, id, digest string) (records.ExportSummary, error) {
	p.calls["approve"]++
	return records.ExportSummary{ID: id, State: records.ExportApproved, SnapshotDigest: digest}, nil
}
func (p *c08AuthProbeExports) Generate(_ context.Context, _ store.Principal, id string) (records.ExportSummary, error) {
	p.calls["generate"]++
	return records.ExportSummary{ID: id, State: records.ExportReady, SnapshotDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64)}, nil
}
func (p *c08AuthProbeExports) Retrieve(_ context.Context, _ store.Principal, _ string) (ExportDelivery, error) {
	p.calls["retrieve"]++
	return ExportDelivery{DirectoryJSON: []byte(`{"synthetic":"package"}`), ManifestDigest: "sha256:" + strings.Repeat("b", 64)}, nil
}
func (p *c08AuthProbeExports) Cancel(context.Context, store.Principal, string) error {
	p.calls["cancel"]++
	return nil
}
func (p *c08AuthProbeExports) AuditDenial(context.Context, store.Principal, string, string, int) error {
	p.denials++
	return nil
}

// TestC08HTTPExportAuthRoleMatrix qualifies production route middleware against
// PostgreSQL-backed principals. State-machine and package-byte authorization
// are exercised separately by the records integration and native HTTP drills.
func TestC08HTTPExportAuthRoleMatrix(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.st.SeedRole(ctx, e.tenant, e.users["dave"], store.RoleExportReviewer); err != nil {
		t.Fatal(err)
	}
	probe := &c08AuthProbeExports{calls: map[string]int{}}
	e.auth.Exports = probe
	e.h = New(e.st.DB, TestFixtureBackend(), WithAuth(e.auth))

	type routeCase struct {
		method, path, operation, role string
		body                          string
		allowedStatus                 int
	}
	id := "11111111-1111-4111-8111-111111111111"
	var matter string
	if err := e.st.DB.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, e.p1).Scan(&matter); err != nil {
		t.Fatal(err)
	}
	cases := []routeCase{
		{"POST", "/v1/exports", "request", store.RoleRecordsOfficer, `{"project_id":"` + e.p1 + `","matter_id":"` + matter + `","custodian_ids":["` + e.users["alice"] + `"],"window_start":"2026-01-01T00:00:00Z","window_end":"2026-01-02T00:00:00Z","reason":"synthetic"}`, http.StatusOK},
		{"POST", "/v1/exports/" + id + "/approve", "approve", store.RoleExportReviewer, `{"snapshot_digest":"` + strings.Repeat("a", 64) + `"}`, http.StatusOK},
		{"POST", "/v1/exports/" + id + "/generate", "generate", store.RoleRecordsOfficer, "", http.StatusOK},
		{"GET", "/v1/exports/" + id + "/package", "retrieve", store.RoleExportReviewer, "", http.StatusOK},
		{"POST", "/v1/exports/" + id + "/cancel", "cancel", store.RoleRecordsOfficer, "", http.StatusNoContent},
	}
	users := []string{"alice", "bob", "carol", "dave", "erin", "frank"}
	for _, tc := range cases {
		for _, user := range users {
			t.Run(tc.operation+"/"+user, func(t *testing.T) {
				before := probe.calls[tc.operation]
				body := strings.NewReader(tc.body)
				req := httptest.NewRequest(tc.method, tc.path, body)
				req.Header.Set("Authorization", "Bearer "+e.idp.Token("sub-"+user))
				if tc.operation == "request" {
					req.Header.Set("Idempotency-Key", "c08-role-matrix")
				}
				if tc.body != "" {
					req.Header.Set("Content-Type", "application/json")
				}
				rec := httptest.NewRecorder()
				e.h.ServeHTTP(rec, req)
				principalRole, _ := e.st.HasRole(ctx, store.Principal{TenantID: e.tenant, UserID: e.users[user]}, tc.role)
				want := tc.allowedStatus
				if !principalRole {
					want = http.StatusForbidden
				}
				if rec.Code != want {
					t.Fatalf("status=%d want=%d response=%q", rec.Code, want, rec.Body.String())
				}
				if !principalRole && (probe.calls[tc.operation] != before || strings.Contains(rec.Body.String(), "synthetic package") || rec.Header().Get("Charter-Manifest-Digest") != "") {
					t.Fatal("denied route called export backend or exposed package data")
				}
			})
		}
	}
	if probe.calls["request"] != 1 || probe.calls["approve"] != 2 || probe.calls["generate"] != 1 || probe.calls["retrieve"] != 2 || probe.calls["cancel"] != 1 {
		t.Fatalf("unexpected authorized call totals: %#v", probe.calls)
	}
	if probe.denials != 23 {
		t.Fatalf("denial audit calls=%d want=23", probe.denials)
	}
}
