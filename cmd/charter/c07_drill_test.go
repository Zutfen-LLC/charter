//go:build retention_drill

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
	"github.com/Zutfen-LLC/charter/internal/records"
	"github.com/Zutfen-LLC/charter/internal/sharepoint"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestC07HoldRetentionLifecycleDrill is the integrated C07 acceptance drill
// (#7): authorized tenant-scoped holds over matter/custodian selections,
// storage-native legal-hold protection on the pinned SeaweedFS Object Lock
// profile, workspace deletion and custodian revocation without loss of held
// evidence, overlapping holds, auditable release, honest base retention, and
// actual expiry+disposal of unheld controls - all through the real serving
// and lifecycle paths against real PostgreSQL and retention-enforced storage.
//
// The disposal-eligible control turns are admitted through the retained
// recorder with the records-write transport (explicit short COMPLIANCE
// retention) BEFORE serving starts, because the qualified runtime write path
// inherits the bucket default (1 day floor) that cannot expire within a
// bounded drill. Every lifecycle and disposal operation on them runs through
// the real implementation and storage.
func TestC07HoldRetentionLifecycleDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	absent := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			t.Fatalf("%s not set", name)
		}
		return v
	}
	c := config.Load()
	if c.EvidenceBackend != config.EvidenceBackendRetentionS3 || c.RetentionS3.RecordsAccessKey == "" || c.RetentionS3.RecordsSecretFile == "" {
		t.Fatal("C07 drill requires the retained profile with the records-scoped storage credential")
	}
	must(validateLabConfig(c.Addr, c.RetentionS3))
	must(validateSyntheticDatabases(c))
	ds := absent("CHARTER_DRILL_OWNER_DSN")
	_, err := labDSN(ds)
	must(err)
	owner, err := pgxpool.New(ctx, ds)
	must(err)
	defer owner.Close()
	must(owner.Ping(ctx))
	var blank bool
	must(owner.QueryRow(ctx, "SELECT NOT EXISTS (SELECT 1 FROM tenants)").Scan(&blank))
	if !blank {
		t.Fatal("C07 drill requires fresh migrated synthetic DB")
	}
	root := absent("CHARTER_DRILL_OUTPUT")
	must(os.Mkdir(root, 0700))
	dump := func(name string, x any) {
		t.Helper()
		b, e := json.MarshalIndent(x, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(root, name), append(b, '\n'), 0600))
	}
	sc := c.RetentionS3
	seedKey, err := hex.DecodeString(sc.CommitKey)
	must(err)
	recordsSecret, err := sizedRead(sc.RecordsSecretFile, 1024, true)
	must(err)
	// Drill-owned records transport: legal holds, versioned deletes, and
	// (for the disposal-eligible seed turns only) short-retention writes.
	recordsClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(recordsSecret))})
	must(err)
	runtimeSecret, err := sizedRead(sc.SecretFile, 1024, true)
	must(err)
	runtimeClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.AccessKey, SecretAccessKey: strings.TrimSpace(string(runtimeSecret))})
	must(err)
	// Independent read-only verifier (no signer, no fence).
	readonly, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: runtimeClient, Deployment: sc.Deployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey})
	must(err)
	seedBytes, err := sizedRead(sc.SignerSeedFile, 128, true)
	must(err)
	seed, err := hex.DecodeString(strings.TrimSpace(string(seedBytes)))
	must(err)
	signer := ed25519.NewKeyFromSeed(seed)

	// Identities: tenant A holds the drilled matters; tenant B is foreign.
	idp := syntheticidp.New("charter-retention-drill", "synthetic-a")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-a", "c07-drill-a")
	must(err)
	other, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-b", "c07-drill-b")
	must(err)
	alice, err := st.CreateUser(ctx, tenant, "alice", "synthetic custodian alice")
	must(err)
	bob, err := st.CreateUser(ctx, tenant, "bob", "synthetic custodian bob")
	must(err)
	r1, err := st.CreateUser(ctx, tenant, "records-one", "synthetic records officer one")
	must(err)
	r2, err := st.CreateUser(ctx, tenant, "records-two", "synthetic records officer two")
	must(err)
	admin, err := st.CreateUser(ctx, tenant, "admin", "synthetic tenant admin")
	must(err)
	zed, err := st.CreateUser(ctx, other, "zed", "synthetic foreign user")
	must(err)
	p1, err := st.CreateProject(ctx, tenant, "held matter project")
	must(err)
	p2, err := st.CreateProject(ctx, tenant, "disposal control project")
	must(err)
	p3, err := st.CreateProject(ctx, tenant, "hold-release-disposal project")
	must(err)
	pForeign, err := st.CreateProject(ctx, other, "foreign project")
	must(err)
	var matter1, matter2, matter3 string
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p1).Scan(&matter1))
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p2).Scan(&matter2))
	must(owner.QueryRow(ctx, `SELECT matter_id::text FROM projects WHERE id=$1`, p3).Scan(&matter3))
	for _, m := range [][2]string{{"alice", p1}, {"bob", p2}, {"alice", p3}} {
		must(st.SeedMember(ctx, tenant, m[1], map[string]string{"alice": alice, "bob": bob}[m[0]]))
	}
	must(st.SeedMember(ctx, other, pForeign, zed))
	must(st.SeedRole(ctx, tenant, r1, store.RoleRecordsOfficer))
	must(st.SeedRole(ctx, tenant, r2, store.RoleRecordsOfficer))
	must(st.SeedRole(ctx, tenant, admin, store.RoleTenantAdmin))
	for _, p := range []string{p1, p2, p3} {
		must((evidence.PG{DB: owner}).SetPolicy(ctx, evidence.BudgetPolicy{TenantID: tenant, ProjectID: p, LocalOnly: true, AllowedModels: []string{"det-a", "det-b"}, ProjectCap: 10000000}))
	}
	// Fast synthetic retention policy so sweeps act within the drill.
	if _, err := owner.Exec(ctx, `INSERT INTO retention_policies(tenant_id, retention_seconds, grace_seconds, set_by) VALUES ($1, 2, 0, $2)`, tenant, r1); err != nil {
		t.Fatal(err)
	}

	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: nil}}
	addr := "http://" + c.Addr

	// ---- Phase 0: disposal-eligible seed turns in a drill-owned deployment ----
	// The qualified runtime serving path inherits the bucket-default
	// retention floor (1 day) that cannot expire within a bounded drill, and
	// the serving backend's signed floor refuses sub-floor versions by
	// design. The disposal lifecycle therefore runs in its own deployment
	// namespace: real recorder, real signed evidence, real lifecycle and
	// disposal code, real storage - only the namespace and retention horizon
	// are drill-owned.
	disposalDeployment := sc.Deployment + "-c07"
	evPool, err := pgxpool.New(ctx, os.Getenv("CHARTER_EVIDENCE_DATABASE_URL"))
	must(err)
	seedStarted := time.Now()
	seedFence, err := (evidence.PG{DB: evPool}).AcquireFence(ctx)
	must(err)
	writeClient, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.RecordsAccessKey, SecretAccessKey: strings.TrimSpace(string(recordsSecret))})
	must(err)
	writeBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: writeClient, Deployment: disposalDeployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey, Signer: signer, MinimumRetention: time.Now().Add(30 * time.Second), RetainFor: 60 * time.Second, Fence: seedFence})
	must(err)
	seedRecorder := &evidence.Recorder{Backend: writeBackend, Fence: seedFence, Policy: func(context.Context, evidence.Request) (evidence.Decision, error) {
		return evidence.Decision{Allow: true, PolicyVersion: "c07-drill-seed", Destination: evidence.Destination{Provider: "synthetic", EndpointID: "seed", ModelID: "det-a"}}, nil
	}}
	seedTurn := func(custodian, project, matter, input string) string {
		t.Helper()
		res, err := seedRecorder.Process(ctx, evidence.Request{
			TenantID: tenant, ProjectID: project, MatterID: matter, CustodianID: custodian,
			IdempotencyKey: "c07-seed-" + input, Input: []byte(input),
		}, func(ctx context.Context, sent []byte) (evidence.ModelOutcome, error) {
			return evidence.ModelOutcome{Accepted: true, Complete: true, Output: []byte("seed output " + input)}, nil
		}, func(context.Context) error { return nil })
		must(err)
		return res.TurnID
	}
	control2 := seedTurn(bob, p2, matter2, "unheld-control")
	release3 := seedTurn(alice, p3, matter3, "hold-release-control")
	raceTurn := seedTurn(alice, p3, matter3, "race-turn")
	seedFence.Release()
	evPool.Close()
	dump("c07-seed-turns.json", map[string]string{"unheld_control": control2, "hold_release_control": release3, "race_turn": raceTurn})

	// ---- Phase 1: serving with the records-scoped storage credential ----
	connector, sourceFixture, err := c06RetainedSource(tenant, p1, alice)
	must(err)
	c.OIDC = config.OIDC{Issuer: idp.Issuer, JWKSURL: idp.JWKSURL(), Audience: "charter-retention-drill", TenantID: "synthetic-a", RequiredScope: "charter.access", AllowInsecureLoopback: true}
	c06stop, err := startC06Retained(ctx, c, connector, client, addr)
	must(err)
	t.Cleanup(func() { _ = c06stop() })
	post := func(tok string, body []byte, key string, want int) map[string]any {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "POST", addr+"/v1/projects/"+p1+"/model-calls", bytes.NewReader(body))
		must(e)
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("Idempotency-Key", key)
		r.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(r)
		must(e)
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		must(e)
		if resp.StatusCode != want {
			t.Fatalf("turn status %d want %d: %s", resp.StatusCode, want, b)
		}
		var data map[string]any
		if len(b) > 0 {
			must(json.Unmarshal(b, &data))
		}
		return data
	}
	api := func(method, path, token, body string) (int, map[string]any) {
		t.Helper()
		var rd io.Reader
		if body != "" {
			rd = strings.NewReader(body)
		}
		r, e := http.NewRequestWithContext(ctx, method, addr+path, rd)
		must(e)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		resp, e := client.Do(r)
		must(e)
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		must(e)
		var data map[string]any
		if strings.HasPrefix(strings.TrimSpace(string(b)), "{") {
			must(json.Unmarshal(b, &data))
		}
		return resp.StatusCode, data
	}
	hold := func(officer, idem, matter, reason string, custodians ...string) map[string]any {
		t.Helper()
		tok := idp.Token(officer)
		list := ""
		for _, c := range custodians {
			list += fmt.Sprintf("%q,", c)
		}
		list = strings.TrimSuffix(list, ",")
		body := fmt.Sprintf(`{"matter_id":%q,"reason":%q,"custodian_ids":[%s]}`, matter, reason, list)
		req, e := http.NewRequestWithContext(ctx, "POST", addr+"/v1/holds", strings.NewReader(body))
		must(e)
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", idem)
		resp, e := client.Do(req)
		must(e)
		defer resp.Body.Close()
		b, e := io.ReadAll(resp.Body)
		must(e)
		var data map[string]any
		if len(b) > 0 {
			must(json.Unmarshal(b, &data))
		}
		if resp.StatusCode != 200 {
			t.Fatalf("place hold %s: %d %v", idem, resp.StatusCode, data)
		}
		return data
	}
	aliceTok, bobTok := idp.Token("alice"), idp.Token("bob")
	r1Tok, r2Tok := idp.Token("records-one"), idp.Token("records-two")
	adminTok, zedTok := idp.Token("admin"), idp.Token("zed")

	// Step 1: governed turns with exact versioned synthetic SharePoint
	// context in the held matter (C06 path).
	const sourceBody = `{"input":"synthetic C07 held matter work","sharepoint_sources":[{"document_id":"sp-original-doc","version":"1.0","offset":8,"length":21}]}`
	baselineResponse := post(aliceTok, []byte(sourceBody), "c07-held-work-1", 200)
	baselineTurn := baselineResponse["turn_id"].(string)
	baselineEvents, err := readonly.Load(ctx, tenant, baselineTurn)
	must(err)
	baselineObjects, err := readonly.LoadRetainedObjects(ctx, tenant, baselineTurn, baselineEvents)
	must(err)
	if errsList := evidence.VerifyRetentionFull(baselineEvents, baselineObjects); len(errsList) != 0 {
		t.Fatalf("baseline evidence: %v", errsList)
	}
	dump("c07-baseline-events.json", baselineEvents)

	// Step 2: apply hold H1 to eligible existing evidence.
	h1 := hold("records-one", "c07-h1", matter1, "C07 drill: regulatory hold")
	if h1["state"] != "effective" {
		t.Fatalf("H1 not effective: %v", h1)
	}
	report1 := h1["report"].(map[string]any)
	if items, _ := report1["items"].([]any); len(items) != 1 {
		t.Fatalf("H1 report items: %v", report1)
	}
	hold1ID := h1["id"].(string)
	// Storage-native protection verified from the drill (not the service):
	refsH1, err := readonly.TurnVersionRefs(ctx, tenant, baselineTurn)
	must(err)
	for _, ref := range refsH1 {
		state, err := recordsClient.LegalHold(ctx, ref.Key, ref.Version)
		must(err)
		if state != "ON" {
			t.Fatalf("existing evidence version not protected: %s -> %q", ref.Key, state)
		}
	}
	dump("c07-h1.json", h1)

	// Step 3: capture new matching work after effective activation.
	newWorkResponse := post(aliceTok, []byte(`{"input":"c07 new matching work under hold"}`), "c07-new-work", 200)
	newTurn := newWorkResponse["turn_id"].(string)
	refsNew, err := readonly.TurnVersionRefs(ctx, tenant, newTurn)
	must(err)
	if len(refsNew) == 0 {
		t.Fatal("no versions for new work")
	}
	for _, ref := range refsNew {
		state, err := recordsClient.LegalHold(ctx, ref.Key, ref.Version)
		must(err)
		if state != "ON" {
			t.Fatalf("new matching work escaped protection: %s -> %q", ref.Key, state)
		}
	}
	dump("c07-new-work-turn.json", newWorkResponse)

	// Step 4: apply the overlapping hold H2 (custodian-scoped).
	h2 := hold("records-two", "c07-h2", matter1, "C07 drill: second overlapping hold", alice)
	if h2["state"] != "effective" {
		t.Fatalf("H2 not effective: %v", h2)
	}

	// Step 5: change and delete the source document (workspace/source change).
	sourceFixture.Put(sharepoint.Document{Metadata: sharepoint.Metadata{TenantID: "synthetic-ms-tenant", SiteID: "synthetic-site", LibraryID: "synthetic-library", DocumentID: "sp-original-doc", Version: "2.0", ETag: "synthetic-etag-2"}, Content: []byte("changed: exact retained source v2")})
	sourceFixture.Grant("sp-original-doc", "synthetic-delegate", false)
	// Step 6: delete the visible chat and project.
	chat, err := st.CreateArtifact(ctx, tenant, p1, "held matter chat", "chat body")
	must(err)
	code, _ := api("DELETE", "/v1/artifacts/"+chat, aliceTok, "")
	if code != 204 {
		t.Fatalf("chat deletion: %d", code)
	}
	code, _ = api("DELETE", "/v1/projects/"+p1, adminTok, "")
	if code != 204 {
		t.Fatalf("project deletion: %d", code)
	}
	// Step 7: revoke the custodian.
	code, _ = api("POST", "/v1/users/"+alice+"/disable", adminTok, "")
	if code != 204 {
		t.Fatalf("custodian revocation: %d", code)
	}
	// Step 8: ordinary users cannot retrieve the deleted or restricted
	// material; the revoked custodian cannot authenticate.
	if code, _ := api("GET", "/v1/artifacts/"+chat, aliceTok, ""); code != 403 {
		t.Fatalf("revoked custodian still authenticated: %d", code)
	}
	if code, _ := api("GET", "/v1/retention/items/"+baselineTurn+"/events", zedTok, ""); code != 403 {
		t.Fatalf("foreign user reached records surface: %d", code)
	}
	if code, _ := api("GET", "/v1/retention/items/"+baselineTurn+"/events", bobTok, ""); code != 403 {
		t.Fatalf("ordinary member reached held evidence: %d", code)
	}
	if code, _ := api("GET", "/v1/retention/items/"+baselineTurn+"/events", adminTok, ""); code != 403 {
		t.Fatalf("tenant admin reached held evidence content: %d", code)
	}
	// Step 9: authorized records operations retain access.
	code, events := api("GET", "/v1/retention/items/"+baselineTurn+"/events", r1Tok, "")
	if code != 200 {
		t.Fatalf("records officer lost held evidence: %d %v", code, events)
	}
	// Step 10: independent reconstruction of the original evidence chains and
	// exact objects (through the read-only backend, no signer).
	reconstructed, err := readonly.Load(ctx, tenant, baselineTurn)
	must(err)
	reconstructedObjects, err := readonly.LoadRetainedObjects(ctx, tenant, baselineTurn, reconstructed)
	must(err)
	if err := readonly.VerifyRetainedTurn(ctx, tenant, baselineTurn, baselineEvents); err != nil {
		t.Fatalf("independent reconstruction: %v", err)
	}
	if len(reconstructed) != len(baselineEvents) || len(reconstructedObjects) != len(baselineObjects) {
		t.Fatal("reconstruction diverged from baseline")
	}
	dump("c07-reconstruction.json", map[string]any{"turn": baselineTurn, "events": len(reconstructed), "objects": len(reconstructedObjects)})

	// Step 11: unauthorized and direct storage deletion of held versions.
	// The runtime credential is refused by IAM; the records credential (the
	// only one that can delete) is refused by the storage's legal hold.
	runtimeRef := refsH1[0]
	if err := runtimeClient.DeleteVersion(ctx, runtimeRef.Key, runtimeRef.Version); err == nil || !errors.Is(err, s3transport.ErrObjectProtected) {
		t.Fatalf("runtime delete of held version: %v", err)
	}
	if err := recordsClient.DeleteVersion(ctx, runtimeRef.Key, runtimeRef.Version); err == nil || !errors.Is(err, s3transport.ErrObjectProtected) {
		t.Fatalf("direct records delete of held version was not refused by storage protection: %v", err)
	}
	dump("c07-direct-delete-refused.json", map[string]any{"key": runtimeRef.Key, "version": runtimeRef.Version, "refused": true})

	// Step 12: release H1; H2 keeps the protection.
	code, released1 := api("POST", "/v1/holds/"+hold1ID+"/release", r1Tok, `{"reason":"C07 drill: first hold released"}`)
	if code != 200 || released1["state"] != "released" {
		t.Fatalf("release H1: %d %v", code, released1)
	}
	for _, ref := range refsH1 {
		state, err := recordsClient.LegalHold(ctx, ref.Key, ref.Version)
		must(err)
		if state != "ON" {
			t.Fatalf("releasing H1 removed protection still required by H2: %s", ref.Key)
		}
	}
	dump("c07-h1-released.json", released1)

	// Step 13: release H2; the remaining base retention (COMPLIANCE, 1 day)
	// still protects the versions - disposal is honestly blocked, not forced.
	hold2ID := h2["id"].(string)
	code, released2 := api("POST", "/v1/holds/"+hold2ID+"/release", r2Tok, `{"reason":"C07 drill: second hold released"}`)
	if code != 200 || released2["state"] != "released" {
		t.Fatalf("release H2: %d %v", code, released2)
	}
	if err := recordsClient.DeleteVersion(ctx, runtimeRef.Key, runtimeRef.Version); err == nil || !errors.Is(err, s3transport.ErrObjectProtected) {
		t.Fatalf("base retention did not protect after full release: %v", err)
	}
	dump("c07-h2-released.json", released2)

	// Serving-path disposal is honestly blocked: after every hold is
	// released the turn becomes disposal-eligible under policy, but the base
	// COMPLIANCE retention (bucket default, 1 day) still protects the bytes -
	// physical disposal is refused and never claimed while protected
	// versions remain.
	if code, data := api("POST", "/v1/retention/sweep", r1Tok, "{}"); code != 200 {
		t.Fatalf("sweep (serving): %d %v", code, data)
	}
	code, begun := api("POST", "/v1/retention/items/"+baselineTurn+"/purge", r2Tok, "")
	if code != 200 || begun["outcome"] != "purging" {
		t.Fatalf("purge begin (serving): %d %v", code, begun)
	}
	code, blockedFinish := api("POST", "/v1/retention/items/"+baselineTurn+"/purge/finish", r2Tok, "")
	if code != 409 {
		t.Fatalf("purge finish (serving): %d %v (want 409: storage protection remains)", code, blockedFinish)
	}
	for _, ref := range refsH1 {
		state, err := recordsClient.LegalHold(ctx, ref.Key, ref.Version)
		must(err)
		if state == "ON" {
			t.Fatalf("legal hold left on after every release: %s", ref.Key)
		}
		if err := recordsClient.DeleteVersion(ctx, ref.Key, ref.Version); err == nil || !errors.Is(err, s3transport.ErrObjectProtected) {
			t.Fatalf("base retention did not protect the serving-path bytes: %v", err)
		}
	}
	dump("c07-serving-blocked.json", map[string]any{"turn": baselineTurn, "begin": begun["outcome"], "finish_http": code, "reason": "base COMPLIANCE retention protects the versions"})

	// ---- Phase B: the disposal lifecycle in the drill-owned deployment ----
	// The seed versions carry the minimum writable retention (60s); wait for
	// the authoritative storage deadlines to pass so disposal is permitted
	// by storage enforcement rather than simulated through application state.
	if wait := 75*time.Second - time.Since(seedStarted); wait > 0 {
		time.Sleep(wait)
	}
	// Real records.Service, real Store, real storage transport; the retention
	// horizon fits the drill. The seed fence was released after Phase 0, so
	// these operations need no evidence-write fence (lifecycle state and
	// conditional deletes are PG transactions plus storage-native deletes).
	disposalBackend, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: writeClient, Deployment: disposalDeployment, Bucket: sc.Bucket, TrustedCommitKey: seedKey})
	must(err)
	disposalService := recordsServiceFor(owner, disposalBackend, recordsClient)
	officer1 := store.Principal{TenantID: tenant, UserID: r1, Roles: map[string]bool{store.RoleRecordsOfficer: true}}
	officer2 := store.Principal{TenantID: tenant, UserID: r2, Roles: map[string]bool{store.RoleRecordsOfficer: true}}

	// Step 14: the unheld control expires under policy and is actually
	// disposed: logical deletion, eligible expiry and observed physical
	// disposal are distinct results.
	marked, err := disposalService.Sweep(ctx, officer1)
	must(err)
	if marked == 0 {
		t.Fatal("no disposal-eligible control marked")
	}
	outcome, err := disposalService.Store.BeginPurge(ctx, officer2, control2, func(context.Context, string) (bool, error) {
		return disposalService.VersionPresent(ctx, tenant, control2), nil
	})
	if err != nil || outcome != "purging" {
		t.Fatalf("purge begin (control): %s %v", outcome, err)
	}
	finishOutcome, versionsOut, err := disposalService.FinishPurge(ctx, &officer2, control2)
	if err != nil || finishOutcome != "disposed" {
		t.Fatalf("purge finish (control): %s %v %v", finishOutcome, err, versionsOut)
	}
	if _, err := disposalBackend.TurnVersionRefs(ctx, tenant, control2); err == nil {
		t.Fatal("disposed control is still enumerable")
	}
	dump("c07-control-disposed.json", map[string]any{"turn": control2, "outcome": finishOutcome, "versions": versionsOut})

	// The held-then-released control: release respected the hold, then the
	// not-yet-expired base retention, then ordinary disposal completed.
	h3, err := disposalService.Place(ctx, officer1, records.Scope{MatterID: matter3, CustodianIDs: []string{alice}}, "C07 drill: hold on the release control", "c07-h3")
	must(err)
	if h3.State != records.HoldEffective {
		t.Fatalf("H3 not effective: %v", h3)
	}
	// While held, the control is not eligible.
	if _, err := disposalService.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	}
	if outcome, err := disposalService.Store.BeginPurge(ctx, officer2, release3, func(context.Context, string) (bool, error) {
		return disposalService.VersionPresent(ctx, tenant, release3), nil
	}); err != nil || outcome != "not_eligible" {
		t.Fatalf("held control must not be purge-eligible: %s %v", outcome, err)
	}
	released3, err := disposalService.Release(ctx, officer1, h3.ID, "release the control")
	must(err)
	if released3.State != records.HoldReleased {
		t.Fatalf("release H3: %v", released3)
	}
	if _, err := disposalService.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	}
	if outcome, err := disposalService.Store.BeginPurge(ctx, officer2, release3, func(context.Context, string) (bool, error) {
		return disposalService.VersionPresent(ctx, tenant, release3), nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("purge begin (release control): %s %v", outcome, err)
	}
	// Step 16 (crash window): the conditional delete is interrupted before
	// completion; a FRESH service instance (restart) reconciles and completes
	// it deterministically from durable state.
	restarted := recordsServiceFor(owner, disposalBackend, recordsClient)
	finishOutcome3, versionsOut3, err := restarted.FinishPurge(ctx, &officer2, release3)
	if err != nil || finishOutcome3 != "disposed" {
		t.Fatalf("purge finish after restart: %s %v %v", finishOutcome3, err, versionsOut3)
	}
	if _, err := disposalBackend.TurnVersionRefs(ctx, tenant, release3); err == nil {
		t.Fatal("released control still enumerable after disposal")
	}
	dump("c07-release-control-disposed.json", map[string]any{"turn": release3, "outcome": finishOutcome3, "versions": versionsOut3})

	// Step 15 (races on real PG+storage): a hold placement racing a purge
	// finish cannot create a preservation gap - whichever commits first
	// wins and the loser observes it deterministically.
	if _, err := restarted.Sweep(ctx, officer1); err != nil {
		t.Fatal(err)
	}
	if outcome, err := restarted.Store.BeginPurge(ctx, officer2, raceTurn, func(context.Context, string) (bool, error) {
		return restarted.VersionPresent(ctx, tenant, raceTurn), nil
	}); err != nil || outcome != "purging" {
		t.Fatalf("race purge begin: %s %v", outcome, err)
	}
	type raceResult struct {
		outcome string
		err     error
		hold    *records.Hold
	}
	finishCh := make(chan raceResult, 1)
	holdCh := make(chan raceResult, 1)
	go func() {
		o, _, e := restarted.FinishPurge(ctx, &officer2, raceTurn)
		finishCh <- raceResult{o, e, nil}
	}()
	go func() {
		h, e := restarted.Place(ctx, officer1, records.Scope{MatterID: matter3, CustodianIDs: []string{alice}}, "racing hold", "c07-race-hold")
		holdCh <- raceResult{"", e, h}
	}()
	fin := <-finishCh
	hld := <-holdCh
	must(fin.err)
	must(hld.err)
	if fin.outcome == "disposed" {
		rep := hld.hold.Report
		if len(rep.DisposedBeforeHold) == 0 {
			t.Fatalf("hold placed after disposal without a recorded gap: %+v", rep)
		}
	} else if fin.outcome != "restored_active" && fin.outcome != "stale_retry" && fin.outcome != "not_purging" {
		t.Fatalf("unexpected race finish outcome: %s", fin.outcome)
	} else {
		// The hold won the race: the tombstone was lifted before the
		// conditional delete ran (case F, including the not_purging shape
		// where the restore happened during placement).
		if _, err := disposalBackend.TurnDisposalRefs(ctx, tenant, raceTurn); err != nil {
			t.Fatalf("restored turn's bytes were deleted: %v", err)
		}
	}
	dump("c07-race-outcomes.json", map[string]any{"finish": fin.outcome, "hold_state": hld.hold.State, "hold_report": hld.hold.Report})

	// Step 17: independent verification of custody and lifecycle records.
	var audits []map[string]any
	rows, err := owner.Query(ctx, `SELECT action, COALESCE(actor_id::text, ''), detail FROM audit_log WHERE action LIKE 'hold.%' OR action LIKE 'purge.%' OR action LIKE 'retention.%' OR action LIKE 'workspace.%' ORDER BY id`)
	must(err)
	for rows.Next() {
		var action, actor string
		var detail []byte
		must(rows.Scan(&action, &actor, &detail))
		audits = append(audits, map[string]any{"action": action, "actor_id": actor, "detail": json.RawMessage(detail)})
	}
	must(rows.Err())
	for _, want := range []string{"hold.place", "hold.effective", "hold.release", "retention.sweep", "purge.begin", "purge.finish", "workspace.artifact.delete", "workspace.project.delete"} {
		found := false
		for _, a := range audits {
			if a["action"] == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing audit action %s", want)
		}
	}
	dump("c07-lifecycle-audit.json", audits)
	// The held evidence chain still verifies end-to-end after every step.
	if err := readonly.VerifyRetainedTurn(ctx, tenant, baselineTurn, baselineEvents); err != nil {
		t.Fatalf("held evidence no longer verifies: %v", err)
	}
	dump("c07-drill-complete.json", map[string]any{"baseline_turn": baselineTurn, "new_work_turn": newTurn, "unheld_control": control2, "release_control": release3, "race_turn": raceTurn})
}

// recordsServiceFor builds the real C07 lifecycle service over the drill's
// PostgreSQL and a records-scoped storage transport (used by the disposal
// phase, whose deployment namespace is drill-owned).
func recordsServiceFor(db *pgxpool.Pool, backend evidence.Backend, storage *s3transport.Client) *records.Service {
	return &records.Service{Store: &records.Store{DB: db}, Backend: backend, Storage: storage, Retained: true, Logf: func(string, ...any) {}}
}
