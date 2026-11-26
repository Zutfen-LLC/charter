package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zutfen-LLC/charter/internal/config"
	"github.com/Zutfen-LLC/charter/internal/evidence"
)

func TestRetentionQualificationCannotRedirectOrDowngrade(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c := config.RetentionS3{Endpoint: "http://127.0.0.1:7481", Bucket: "charter-c04-protected-fixture", Deployment: "lab-run", Region: "us-east-1", AccessKey: "synthetic-runtime-id", MinSeconds: "600"}
	c.CommitKey = hex.EncodeToString(make([]byte, ed25519.PublicKeySize))
	q := qualificationStatement{Version: retentionQualificationVersion, Profile: evidence.RetentionProfile, Endpoint: c.Endpoint, Bucket: c.Bucket, Deployment: c.Deployment, Region: c.Region, Credential: evidence.SHA256([]byte(c.AccessKey)), Implementation: "SeaweedFS 4.55", ImageDigest: evidence.SHA256([]byte("empty-package-test")), EvidenceReport: evidence.SHA256([]byte("wire-fixture-report")), IssuedAt: now.Add(-time.Minute).Format(time.RFC3339), ValidUntil: now.Add(2 * time.Hour).Format(time.RFC3339), Controls: requiredStorageControls, Canary: qualificationCanary{Key: "charter/v1/lab-run/authority", Version: "v-test-physical", SHA: evidence.SHA256([]byte("test-canary")), Length: 11, Mode: "COMPLIANCE", Until: now.Add(4 * time.Hour).Format(time.RFC3339)}}
	q.CommitKey, q.MinSeconds = c.CommitKey, c.MinSeconds
	q.Coordination = "1234567:16390:sha256:" + strings.Repeat("a", 64)
	body := authorityBody(c.Deployment, q.Coordination)
	q.Canary.SHA, q.Canary.Length = evidence.SHA256(body), len(body)
	path := filepath.Join(t.TempDir(), "qualification.json")
	c.QualificationFile, c.QualificationKey = path, hex.EncodeToString(pub)
	put := func(q qualificationStatement) {
		t.Helper()
		p, e := json.Marshal(q)
		if e != nil {
			t.Fatal(e)
		}
		sig := ed25519.Sign(priv, append([]byte(qualificationDomain), p...))
		b, e := json.Marshal(qualificationEnvelope{Payload: string(p), Signature: hex.EncodeToString(sig)})
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	put(q)
	if _, err = loadQualification(ctx, c, now); err != nil {
		t.Fatalf("valid fixture: %v", err)
	}
	other := c
	other.Bucket = "charter-c04-protected-other"
	if _, err = loadQualification(ctx, other, now); err == nil {
		t.Fatal("approved key could redirect to another bucket")
	}
	other = c
	other.AccessKey = "different-runtime"
	if _, err = loadQualification(ctx, other, now); err == nil {
		t.Fatal("unqualified runtime accepted")
	}
	other = c
	other.MinSeconds = "60"
	if _, err = loadQualification(ctx, other, now); err == nil {
		t.Fatal("operator-selected duration downgraded the signed minimum")
	}
	other = c
	other.CommitKey = c.QualificationKey
	if _, err = loadQualification(ctx, other, now); err == nil {
		t.Fatal("qualification was not bound to the trusted evidence key")
	}
	if _, err = loadQualification(ctx, c, now.Add(3*time.Hour)); err == nil {
		t.Fatal("expired scope accepted")
	}
	foreign := q
	foreign.Coordination = "1234567:16391:sha256:" + strings.Repeat("a", 64)
	put(foreign)
	if _, err = loadQualification(ctx, c, now); err == nil {
		t.Fatal("a new signed database identity reused the old retained authority receipt")
	}
	foreign.Coordination = ""
	put(foreign)
	if _, err = loadQualification(ctx, c, now); err == nil {
		t.Fatal("signed qualification without database identity was accepted")
	}
	q.Profile = evidence.CurrentProfile
	put(q)
	if _, err = loadQualification(ctx, c, now); err == nil {
		t.Fatal("downgraded profile accepted even with authentic signature")
	}
	q.Profile = evidence.RetentionProfile
	q.Controls = nil
	put(q)
	if _, err = loadQualification(ctx, c, now); err == nil {
		t.Fatal("missing actual runtime control coverage accepted")
	}
}

func TestSyntheticDatabasesRefuseSplitOrRemoteAuthority(t *testing.T) {
	const base = "postgres://fixture:fixture@127.0.0.1:55433/charter_c04_disposable_test?sslmode=disable"
	const differentUser = "postgres://evidence:fixture@127.0.0.1:55433/charter_c04_disposable_test?sslmode=disable"
	cfg := config.Config{DatabaseURL: base, EvidenceDatabaseURL: differentUser}
	if err := validateSyntheticDatabases(cfg); err != nil {
		t.Fatal(err)
	}
	for _, dsn := range []string{
		"postgres://fixture:fixture@example.test:55433/charter_c04_disposable_test?sslmode=disable",
		"postgres://fixture:fixture@127.0.0.1:55433/production?sslmode=disable",
		"postgres://fixture:fixture@127.0.0.1:55434/charter_c04_disposable_test?sslmode=disable",
		base + "&search_path=unrelated",
		"host=127.0.0.1,203.0.113.1 port=55433,55433 dbname=charter_c04_disposable_test sslmode=disable",
	} {
		cfg.EvidenceDatabaseURL = dsn
		if err := validateSyntheticDatabases(cfg); err == nil {
			t.Fatal("accepted an unsafe runtime database scope")
		}
	}
}
