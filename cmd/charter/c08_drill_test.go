//go:build retention_drill

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/exportbundle"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestC08NativeExportDrill uses the production retained capture, hold,
// authorization and export handlers with real SeaweedFS and PostgreSQL. Its
// SharePoint fixture and IdP are synthetic and loopback-only.
func TestC08NativeExportDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	c := config.Load()
	if c.EvidenceBackend != config.EvidenceBackendRetentionS3 || c.RetentionS3.RecordsAccessKey == "" || c.RetentionS3.RecordsSecretFile == "" {
		t.Fatal("C08 drill requires the native retained profile and records-scoped storage credential")
	}
	if err := validateLabConfig(c.Addr, c.RetentionS3); err != nil {
		t.Fatal(err)
	}
	if err := validateSyntheticDatabases(c); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("CHARTER_DRILL_OWNER_DSN")
	if dsn == "" {
		t.Fatal("CHARTER_DRILL_OWNER_DSN not set")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	var blank bool
	if err := pool.QueryRow(ctx, "SELECT NOT EXISTS (SELECT 1 FROM tenants)").Scan(&blank); err != nil {
		t.Fatal(err)
	}
	if !blank {
		t.Fatal("C08 drill requires a fresh migrated synthetic database")
	}
	root := os.Getenv("CHARTER_DRILL_OUTPUT")
	if root == "" {
		t.Fatal("CHARTER_DRILL_OUTPUT not set")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	sc := c.RetentionS3
	secret, err := sizedRead(sc.RecordsSecretFile, 1024, true)
	must(err)
	client, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(secret))})
	must(err)
	backend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: client, Deployment: sc.Deployment, Bucket: sc.Bucket, TrustedCommitKey: mustHex(t, sc.CommitKey)})
	must(err)
	// Exercise the retained reader against actual storage. Empty inventory is
	// the expected fresh synthetic database state; errors are preserved rather
	// than converted into a successful proof.
	ids, err := backend.InventoryTurns(ctx, "00000000-0000-4000-8000-000000000008")
	must(err)
	if len(ids) != 0 {
		t.Fatalf("fresh C08 native deployment unexpectedly contains %d turns", len(ids))
	}
	probe := map[string]any{"profile": evidence.RetentionProfile, "native_inventory_turns": len(ids), "route_integration": "separate c08-native-export.json receipt", "verified_at": time.Now().UTC().Format(time.RFC3339Nano)}
	b, err := json.MarshalIndent(probe, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(root, "c08-native-preflight.json"), append(b, '\n'), 0600))
	runC08NativeRoutes(t, ctx, c, pool, backend, root)
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func runC08NativeRoutes(t *testing.T, ctx context.Context, c config.Config, owner *pgxpool.Pool, source *evidence.RetentionBackend, root string) {
	t.Helper()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	idp := syntheticidp.New("charter-export-drill", "synthetic-c08")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-c08", "synthetic export demonstration")
	must(err)
	users := map[string]string{}
	for _, name := range []string{"custodian", "records", "reviewer", "reviewer-other", "admin", "operator"} {
		id, err := st.CreateUser(ctx, tenant, name, "synthetic "+name)
		must(err)
		users[name] = id
	}
	for name, roles := range map[string][]string{"records": {store.RoleRecordsOfficer, store.RoleExportReviewer}, "reviewer": {store.RoleExportReviewer}, "reviewer-other": {store.RoleExportReviewer}, "admin": {store.RoleTenantAdmin}, "operator": {store.RoleOperator}} {
		for _, role := range roles {
			must(st.SeedRole(ctx, tenant, users[name], role))
		}
	}
	project, err := st.CreateProject(ctx, tenant, "held synthetic project")
	must(err)
	control, err := st.CreateProject(ctx, tenant, "excluded synthetic project")
	must(err)
	var matter string
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, project).Scan(&matter))
	for _, p := range []string{project, control} {
		must(st.SeedMember(ctx, tenant, p, users["custodian"]))
		must((evidence.PG{DB: owner}).SetPolicy(ctx, evidence.BudgetPolicy{TenantID: tenant, ProjectID: p, LocalOnly: true, AllowedModels: []string{"det-a", "det-b"}, ProjectCap: 10000000}))
	}
	connector, fixture, err := c06RetainedSource(tenant, project, users["custodian"])
	must(err)
	c.OIDC = config.OIDC{Issuer: idp.Issuer, JWKSURL: idp.JWKSURL(), Audience: "charter-export-drill", TenantID: "synthetic-c08", RequiredScope: "charter.access", AllowInsecureLoopback: true}
	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: nil}}
	addr := "http://" + c.Addr
	stop, err := startC06Retained(ctx, c, connector, client, addr)
	must(err)
	defer func() { must(stop()) }()
	tokens := map[string]string{}
	for name := range users {
		tokens[name] = idp.Token(name)
	}
	type response struct {
		body   []byte
		digest string
		status int
	}
	do := func(method, path, actor, key string, payload any, want int) response {
		t.Helper()
		var raw []byte
		if payload != nil {
			var err error
			raw, err = json.Marshal(payload)
			must(err)
		}
		req, err := http.NewRequestWithContext(ctx, method, addr+path, bytes.NewReader(raw))
		must(err)
		req.Header.Set("Authorization", "Bearer "+tokens[actor])
		req.Header.Set("Content-Type", "application/json")
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		resp, err := client.Do(req)
		must(err)
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, (32<<20)+1))
		must(err)
		digest := resp.Header.Get("Charter-Manifest-Digest")
		if resp.StatusCode != want {
			t.Fatalf("%s %s actor=%s status=%d want=%d; response size=%d", method, path, actor, resp.StatusCode, want, len(body))
		}
		if want >= 400 && (digest != "" || len(body) > 512 || bytes.Contains(body, []byte("manifest.json"))) {
			t.Fatal("denial exposed package content")
		}
		return response{body, digest, resp.StatusCode}
	}
	parse := func(r response) map[string]any { var m map[string]any; must(json.Unmarshal(r.body, &m)); return m }
	start := time.Now().UTC().Add(-time.Second)
	const input = "exact synthetic C08 input"
	turn := parse(do("POST", "/v1/projects/"+project+"/model-calls", "custodian", "c08-model-1", map[string]any{"input": input, "sharepoint_sources": []any{map[string]any{"document_id": "sp-original-doc", "version": "1.0", "offset": 8, "length": 21}}}, 200))["turn_id"].(string)
	excluded := parse(do("POST", "/v1/projects/"+control+"/model-calls", "custodian", "c08-model-control", map[string]any{"input": "unrelated control must never export"}, 200))["turn_id"].(string)
	end := time.Now().UTC().Add(time.Second)
	holdBody := map[string]any{"matter_id": matter, "custodian_ids": []string{users["custodian"]}, "reason": "synthetic C08 preservation"}
	hold1 := parse(do("POST", "/v1/holds", "records", "c08-hold-1", holdBody, 200))
	hold2 := parse(do("POST", "/v1/holds", "records", "c08-hold-2", holdBody, 200))
	if hold1["state"] != "effective" || hold2["state"] != "effective" || hold1["id"] == hold2["id"] {
		t.Fatal("two independent effective holds not established")
	}
	modifyRetainedSource(fixture)
	chat, err := st.CreateArtifact(ctx, tenant, project, "mutable chat", "unrelated workspace-only material")
	must(err)
	do("DELETE", "/v1/artifacts/"+chat, "custodian", "", nil, 204)
	do("DELETE", "/v1/projects/"+project, "admin", "", nil, 204)
	do("POST", "/v1/users/"+users["custodian"]+"/disable", "admin", "", nil, 204)
	req := map[string]any{"project_id": project, "matter_id": matter, "custodian_ids": []string{users["custodian"]}, "window_start": start.Format(time.RFC3339Nano), "window_end": end.Format(time.RFC3339Nano), "reason": "synthetic C08 independent review"}
	for _, actor := range []string{"admin", "operator", "reviewer"} {
		do("POST", "/v1/exports", actor, "denied", req, 403)
	}
	result := parse(do("POST", "/v1/exports", "records", "c08-export", req, 200))
	export, ok := result["export_id"].(string)
	if !ok || result["state"] != "requested" {
		t.Fatal("missing durable export request")
	}
	path := "/v1/exports/" + export
	approval := map[string]any{"snapshot_digest": result["snapshot_digest"]}
	do("GET", path+"/package", "reviewer", "", nil, 404)
	do("POST", path+"/approve", "records", "", approval, 409)
	approv := parse(do("POST", path+"/approve", "reviewer", "", approval, 200))
	if approv["state"] != "approved" {
		t.Fatal("approval state absent")
	}
	ready := parse(do("POST", path+"/generate", "records", "", nil, 200))
	expected, ok := ready["manifest_digest"].(string)
	if !ok || ready["state"] != "ready" {
		t.Fatal("manifest anchor not available independently to requester")
	}
	for _, actor := range []string{"admin", "operator"} {
		do("GET", path+"/package", actor, "", nil, 403)
	}
	do("GET", path+"/package", "reviewer-other", "", nil, 404)
	got := do("GET", path+"/package", "reviewer", "", nil, 200)
	if got.digest != expected {
		t.Fatal("package response digest differs from requester control record")
	}
	var files map[string][]byte
	must(json.Unmarshal(got.body, &files))
	verified, err := exportbundle.VerifyMembers(files, evidence.RetentionProfile, expected)
	must(err)
	if verified.Status != exportbundle.Complete || verified.Turns != 1 || files["events/"+excluded+".jsonl"] != nil {
		t.Fatal("export census or exclusion mismatch")
	}
	refs, err := source.TurnVersionRefs(ctx, tenant, turn)
	must(err)
	exact, err := source.LoadExportReadback(ctx, tenant, project, turn, refs)
	must(err)
	raw := append(bytes.Join(exact.CanonicalEvents, []byte{'\n'}), '\n')
	if !bytes.Equal(files["events/"+turn+".jsonl"], raw) {
		t.Fatal("event log differs from independently read retained bytes")
	}
	for digest, obj := range exact.Objects {
		if !bytes.Equal(files["objects/"+strings.TrimPrefix(digest, "sha256:")], obj) {
			t.Fatal("exported object differs from independently read retained version")
		}
	}
	if !bytes.Equal(exact.Objects[evidence.SHA256([]byte(input))], []byte(input)) || !bytes.Equal(exact.Objects[evidence.SHA256([]byte("exact retained source"))], []byte("exact retained source")) {
		t.Fatal("original input or captured SharePoint bytes not retained")
	}
	duplicate := do("GET", path+"/package", "reviewer", "", nil, 200)
	if !bytes.Equal(got.body, duplicate.body) {
		t.Fatal("duplicate retrieval changed verified output")
	}
	do("POST", "/v1/holds/"+hold1["id"].(string)+"/release", "records", "", map[string]any{"reason": "synthetic change invalidates export"}, 200)
	do("GET", path+"/package", "reviewer", "", nil, 409)
	for _, action := range []string{"export.request", "export.approve", "export.ready", "export.retrieve"} {
		var n int
		must(owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action=$2 AND detail->>'export_id'=$3`, tenant, action, export).Scan(&n))
		if n == 0 {
			t.Fatalf("custody event %s not persisted", action)
		}
	}
	var denials int
	must(owner.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='export.reject' AND detail->>'supplied_export_id'=$2`, tenant, export).Scan(&denials))
	if denials < 5 {
		t.Fatalf("authenticated export denials were not audited: %d", denials)
	}
	must(os.WriteFile(filepath.Join(root, "c08-transport.json"), got.body, 0600))
	summary, err := json.MarshalIndent(map[string]any{"export_id": export, "snapshot_digest": result["snapshot_digest"], "trusted_manifest_digest": expected, "profile": evidence.RetentionProfile, "exact_versions": len(refs), "event_count": len(exact.Events), "verified_objects": len(exact.Objects), "probes": []string{"project_deleted", "chat_deleted", "custodian_disabled", "other_project_excluded", "exact_retained_bytes", "overlapping_holds", "self_approval_refused", "duplicate_delivery_identical", "release_invalidates", "custody_audit"}}, "", "  ")
	must(err)
	must(os.WriteFile(filepath.Join(root, "c08-native-export.json"), append(summary, '\n'), 0600))
}
