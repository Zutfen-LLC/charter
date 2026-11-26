//go:build retention_drill

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
	"github.com/Zutfen-LLC/charter/internal/evidence/s3transport"
	"github.com/Zutfen-LLC/charter/internal/oidc/syntheticidp"
	"github.com/Zutfen-LLC/charter/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Run only in the owned, no-NIC lab. This is a mandatory test in its build
// target: missing prerequisites fail, rather than becoming a successful skip.
func TestRetentionReconstructionDrill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	absent := func(name string) string {
		t.Helper()
		s := os.Getenv(name)
		if s == "" {
			t.Fatalf("missing %s in real-storage test", name)
		}
		return s
	}
	c := config.Load()
	if os.Geteuid() != 0 {
		t.Fatal("owned lab runner must isolate Charter in an unprivileged uid")
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
		t.Fatal("reconstruction drill requires fresh migrated synthetic DB")
	}
	idp := syntheticidp.New("charter-retention-drill", "synthetic-a")
	defer idp.Server.Close()
	st := store.Store{DB: owner}
	tenant, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-a", "retention-drill-a")
	must(err)
	other, err := st.CreateTenant(ctx, idp.Issuer, "synthetic-b", "retention-drill-b")
	must(err)
	actor, err := st.CreateUser(ctx, tenant, "alice", "synthetic alice")
	must(err)
	_, err = st.CreateUser(ctx, other, "bob", "synthetic bob")
	must(err)
	project, err := st.CreateProject(ctx, tenant, "retention drill")
	must(err)
	const original = "Original synthetic excerpt: alpha beta gamma."
	const input = "Summarize the synthetic exhibit exactly."
	artifact, err := st.CreateArtifact(ctx, tenant, project, "synthetic exhibit", original)
	must(err)
	must(st.SeedMember(ctx, tenant, project, actor))
	must((evidence.PG{DB: owner}).SetPolicy(ctx, evidence.BudgetPolicy{TenantID: tenant, ProjectID: project, LocalOnly: true, AllowedModels: []string{"det-a", "det-b"}, ProjectCap: 10000000}))
	root := absent("CHARTER_DRILL_OUTPUT")
	must(os.Mkdir(root, 0700))
	dump := func(name string, x any) {
		t.Helper()
		b, e := json.MarshalIndent(x, "", "  ")
		must(e)
		must(os.WriteFile(filepath.Join(root, name), append(b, '\n'), 0600))
	}
	secret, err := sizedRead(c.RetentionS3.SecretFile, 1024, true)
	must(err)
	sc := c.RetentionS3
	storage, err := s3transport.New(s3transport.Config{Endpoint: sc.Endpoint, Region: sc.Region, Bucket: sc.Bucket, AccessKeyID: sc.AccessKey, SecretAccessKey: strings.TrimSpace(string(secret))})
	must(err)
	key, err := hex.DecodeString(sc.CommitKey)
	must(err)
	readonly, err := evidence.NewRetentionBackend(evidence.RetentionOptions{Store: storage, Deployment: sc.Deployment, Bucket: sc.Bucket, TrustedCommitKey: key})
	must(err)
	client := &http.Client{Timeout: time.Minute, Transport: &http.Transport{Proxy: nil}}
	addr := "http://" + c.Addr
	env := []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	for _, row := range os.Environ() {
		n, _, _ := strings.Cut(row, "=")
		if strings.HasPrefix(n, "CHARTER_S3_") || n == "CHARTER_ADDR" || n == "CHARTER_DATABASE_URL" || n == "CHARTER_EVIDENCE_DATABASE_URL" || n == "CHARTER_BUDGET_DATABASE_URL" || n == "CHARTER_EVIDENCE_BACKEND" {
			env = append(env, row)
		}
	}
	env = append(env, "CHARTER_OIDC_ISSUER="+idp.Issuer, "CHARTER_OIDC_JWKS_URL="+idp.JWKSURL(), "CHARTER_OIDC_AUDIENCE=charter-retention-drill", "CHARTER_OIDC_TENANT_ID=synthetic-a", "CHARTER_OIDC_REQUIRED_SCOPE=charter.access", "CHARTER_OIDC_INSECURE_LOOPBACK_FIXTURE=1")
	sorted := func(items []string) []string { return slices.Sorted(slices.Values(items)) }
	newServer := func(settings []string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, absent("CHARTER_DRILL_BINARY"), "serve")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
		cmd.Env = settings
		return cmd
	}
	for _, tc := range []struct{ key, value, expected string }{
		{"CHARTER_EVIDENCE_BACKEND", "", "evidence backend conflicts with the database binding"},
		{"CHARTER_S3_SYNTHETIC_OPT_IN", "", "incomplete or unsafe synthetic S3 storage configuration"},
		{"CHARTER_S3_ENDPOINT", "http://storage.invalid:7481", "requires a literal loopback storage endpoint"},
		{"CHARTER_S3_RUNTIME_ACCESS_KEY", "wrong-synthetic-identity", "qualification is missing, expired, invalid"},
		{"CHARTER_S3_ADMIN_ACCESS_KEY", "synthetic-not-a-secret", "administrative or ambient credential present"},
	} {
		settings := append(append([]string(nil), env...), tc.key+"="+tc.value)
		out, err := newServer(settings).CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte(tc.expected)) {
			t.Fatalf("startup refusal for %s did not reach the expected guard: %v\n%s", tc.key, err, out)
		}
	}
	starter := func(label string) func() {
		t.Helper()
		f, e := os.OpenFile(filepath.Join(root, label+".log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		must(e)
		cmd := newServer(env)
		cmd.Stdout = f
		cmd.Stderr = f
		must(cmd.Start())
		must(f.Close())
		stopped := false
		stop := func() {
			if !stopped {
				stopped = true
				_ = cmd.Process.Signal(os.Interrupt)
				_ = cmd.Wait()
			}
		}
		t.Cleanup(stop)
		for i := 0; i < 70; i++ {
			r, e := client.Get(addr + "/readyz")
			if e == nil {
				_ = r.Body.Close()
				if r.StatusCode == 200 {
					proc := fmt.Sprintf("/proc/%d/", cmd.Process.Pid)
					actual, e := os.ReadFile(proc + "environ")
					must(e)
					if !slices.Equal(sorted(strings.Split(strings.TrimSuffix(string(actual), "\x00"), "\x00")), sorted(env)) {
						t.Fatal("serving process environment differs from the qualified runtime configuration")
					}
					statement, e := loadQualification(ctx, sc, time.Now())
					must(e)
					var envKeys []string
					for _, row := range env {
						name, _, _ := strings.Cut(row, "=")
						envKeys = append(envKeys, name)
					}
					dump(label+"-identity.json", map[string]any{"uid": cmd.SysProcAttr.Credential.Uid, "environment_keys": sorted(envKeys), "deployment": statement.Deployment, "bucket": statement.Bucket, "endpoint": statement.Endpoint, "runtime_access_key_sha256": statement.Credential, "qualification_report_sha256": statement.EvidenceReport})
					return stop
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("retention-mode Charter did not become ready; see %s/%s.log", root, label)
		return stop
	}
	request, err := json.Marshal(map[string]any{"input": input, "artifact_ids": []string{artifact}})
	must(err)
	post := func(tok string, want int) map[string]any {
		t.Helper()
		r, e := http.NewRequestWithContext(ctx, "POST", addr+"/v1/projects/"+project+"/model-calls", bytes.NewReader(request))
		must(e)
		r.Header.Set("Authorization", "Bearer "+tok)
		r.Header.Set("Idempotency-Key", "c04-reconstruction-drill")
		r.Header.Set("Content-Type", "application/json")
		resp, e := client.Do(r)
		must(e)
		defer resp.Body.Close()
		var data map[string]any
		b, e := io.ReadAll(resp.Body)
		must(e)
		if resp.StatusCode != want {
			t.Fatalf("turn status %d want %d: %s", resp.StatusCode, want, b)
		}
		must(json.Unmarshal(b, &data))
		if _, hasOutput := data["output"]; want != 200 && hasOutput {
			t.Fatal("rejected request returned an output field")
		}
		return data
	}
	checkReadiness := func(want int) map[string]any {
		t.Helper()
		r, err := client.Get(addr + "/readyz")
		must(err)
		defer r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("readiness status %d, want %d", r.StatusCode, want)
		}
		var body map[string]any
		must(json.NewDecoder(r.Body).Decode(&body))
		return body
	}
	lab := func(action string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, "python3", "/mnt/rgw-payload/lab-qualification.py", action)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("native control %s: %v: %s", action, err, out)
		}
	}
	stop := starter("first-server")
	alice := idp.Token("alice")
	ready := checkReadiness(200)
	profile, _ := ready["evidence_backend"].(map[string]any)
	if profile["retention_enforced"] != true || profile["kind"] != evidence.RetentionProfile || profile["retention_status"] != "storage-native-qualified-synthetic" {
		t.Fatal("readiness did not report the qualified synthetic backend")
	}
	lab("unsafe-default")
	dump("unsafe-storage-readiness.json", checkReadiness(503))
	dump("unsafe-storage-response.json", post(alice, 503))
	lab("restore-default")
	dump("restored-storage-readiness.json", checkReadiness(200))
	pid, err := strconv.Atoi(absent("CHARTER_DRILL_STORAGE_PID"))
	must(err)
	exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	must(err)
	if pid <= 1 || exe != "/mnt/rgw-payload/weed" {
		t.Fatal("outage target is not the staged storage binary")
	}
	must(syscall.Kill(pid, syscall.SIGSTOP))
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGCONT) })
	dump("unavailable-readiness.json", checkReadiness(503))
	live, err := client.Get(addr + "/healthz")
	must(err)
	var health map[string]any
	must(json.NewDecoder(live.Body).Decode(&health))
	must(live.Body.Close())
	if live.StatusCode != 200 || health["status"] != "ok" || !reflect.DeepEqual(health["evidence_backend"], ready["evidence_backend"]) {
		t.Fatal("liveness confused startup qualification with current readiness")
	}
	dump("live-during-outage.json", health)
	dump("unavailable-response.json", post(alice, 503))
	must(syscall.Kill(pid, syscall.SIGCONT))
	first := post(alice, 200)
	dump("first-response.json", first)
	_ = post(idp.Mint(syntheticidp.Claims{Subject: "bob", Tenant: "synthetic-b"}), 401)
	turn, ok := first["turn_id"].(string)
	if !ok || turn == "" || first["replayed"] != false {
		t.Fatal("invalid first delivery")
	}
	baseline, err := readonly.Load(ctx, tenant, turn)
	must(err)
	payloads, err := readonly.LoadRetainedObjects(ctx, tenant, turn, baseline)
	must(err)
	if es := evidence.VerifyRetentionFull(baseline, payloads); len(es) > 0 {
		t.Fatalf("retained verification: %v", es)
	}
	if !bytes.Equal(payloads[evidence.SHA256([]byte(original))], []byte(original)) || !bytes.Equal(payloads[evidence.SHA256([]byte(input))], []byte(input)) {
		t.Fatal("exact original input or excerpt absent")
	}
	output, _ := first["output"].(string)
	if output == "" || !bytes.Equal(payloads[evidence.SHA256([]byte(output))], []byte(output)) {
		t.Fatal("exact output absent")
	}
	var requestDigest string
	for _, e := range baseline {
		if e["type"] == "context_sealed" {
			requestDigest, _ = e["payload"].(map[string]any)["request_sha256"].(string)
		}
	}
	if sealed := payloads[requestDigest]; len(sealed) == 0 || evidence.SHA256(sealed) != requestDigest || output != "synthetic c04 response for "+requestDigest {
		t.Fatal("exact provider request was not bound to the consumed bytes and output")
	}
	dump("events.json", baseline)
	dump("objects.json", payloads)
	refs, err := storage.Versions(ctx, "charter/v1/"+sc.Deployment+"/"+tenant+"/")
	must(err)
	var inventory []map[string]any
	for _, ref := range refs {
		if ref.DeleteMarker {
			t.Fatal("unexpected marker in clean drill")
		}
		v, e := storage.Read(ctx, ref.Key, ref.VersionID)
		must(e)
		inventory = append(inventory, map[string]any{"key": ref.Key, "version_id": v.ID, "sha256": evidence.SHA256(v.Data), "byte_length": len(v.Data), "mode": v.Mode, "retain_until": v.Until, "bytes": v.Data})
	}
	dump("exact-version-inventory.json", inventory)
	stop()
	substitution := exec.CommandContext(ctx, "python3", "/mnt/rgw-payload/lab-qualification.py", "substitute")
	if out, err := substitution.CombinedOutput(); err != nil {
		t.Fatalf("native canonical/latest substitution control: %v: %s", err, out)
	}
	// Remove the workspace source and retire the PostgreSQL evidence-index tables
	// inside the freshly allocated synthetic database. No S3 index is consulted.
	_, err = owner.Exec(ctx, `DELETE FROM artifacts WHERE id=$1`, artifact)
	must(err)
	_, err = owner.Exec(ctx, `ALTER TABLE evidence_events RENAME TO unavailable_evidence_events; ALTER TABLE evidence_objects RENAME TO unavailable_evidence_objects; ALTER TABLE evidence_turns RENAME TO unavailable_evidence_turns`)
	must(err)
	recovered, err := readonly.Load(ctx, tenant, turn)
	must(err)
	after, err := readonly.LoadRetainedObjects(ctx, tenant, turn, recovered)
	must(err)
	if !reflect.DeepEqual(baseline, recovered) || !reflect.DeepEqual(payloads, after) {
		t.Fatal("independent recovery changed chain or bytes")
	}
	dump("reconstructed-events.json", recovered)
	dump("reconstructed-objects.json", after)
	if _, err = readonly.Load(ctx, other, turn); err == nil {
		t.Fatal("cross-tenant retained lookup succeeded")
	}
	_, err = owner.Exec(ctx, `ALTER TABLE unavailable_evidence_events RENAME TO evidence_events; ALTER TABLE unavailable_evidence_objects RENAME TO evidence_objects; ALTER TABLE unavailable_evidence_turns RENAME TO evidence_turns`)
	must(err)
	_, err = owner.Exec(ctx, `INSERT INTO artifacts(id,tenant_id,project_id,title,body) VALUES($1,$2,$3,$4,$5)`, artifact, tenant, project, "synthetic exhibit", original)
	must(err)
	stop = starter("restarted-server")
	dump("anonymous-replay-response.json", post("", 401))
	expired := idp.Mint(syntheticidp.Claims{Subject: "alice", IssuedAt: time.Now().Add(-time.Hour), Lifetime: time.Minute})
	dump("expired-replay-response.json", post(expired, 401))
	_, err = owner.Exec(ctx, `DELETE FROM project_members WHERE project_id=$1 AND user_id=$2`, project, actor)
	must(err)
	dump("revoked-replay-response.json", post(alice, 404))
	must(st.SeedMember(ctx, tenant, project, actor))
	must((evidence.PG{DB: owner}).SetPolicy(ctx, evidence.BudgetPolicy{TenantID: tenant, ProjectID: project, LocalOnly: true, AllowedModels: []string{"det-a", "det-b"}, ProjectCap: 10000000}))
	replay := post(idp.Token("alice"), 200)
	dump("replay-response.json", replay)
	if replay["turn_id"] != turn || replay["output"] != output || replay["replayed"] != true {
		t.Fatal("restart did not preserve delivery-only replay")
	}
	last, err := readonly.Load(ctx, tenant, turn)
	must(err)
	if !reflect.DeepEqual(baseline, last) {
		t.Fatal("restart/replay altered the retained event chain")
	}
	stop()
	for name, count := range map[string]int{"first-server.log": 1, "restarted-server.log": 0} {
		logs, e := os.ReadFile(filepath.Join(root, name))
		must(e)
		if bytes.Count(logs, []byte("synthetic retention provider invoked")) != count {
			t.Fatalf("unexpected number of provider invocations in %s", name)
		}
	}
	t.Logf("recovered %d canonical events, %d referenced objects and %d exact versions after workspace and index loss", len(recovered), len(after), len(inventory))
}
